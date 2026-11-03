from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.cve_replay import (
    CveReplayAudit,
    CveReplayCandidate,
    CveReplayCandidates,
    CveReplayState,
    CveReplayTrends,
    CveReplayVerdict,
)
from traust_core.v1.models.dependencies import AdvisoryRecord


def classify(
    audit: CveReplayAudit,
    report: ReportArtifact,
    advisory: AdvisoryRecord,
    checked_at: datetime,
    *,
    present_at_audit: bool | None,
) -> CveReplayCandidate:
    text = "\n".join(report.text_fragments(sections=("findings", "negative_results")))
    identifiers = {str(advisory.identifier), *map(str, advisory.aliases)}
    named = tuple(sorted(i for i in identifiers if _names(text, i)))
    areas = tuple(a for a in _areas(advisory) if a.casefold() in text.casefold())
    if present_at_audit is False or advisory.withdrawn:
        verdict = CveReplayVerdict.NOT_APPLICABLE
        reason = (
            "adjudicated absent at audit" if present_at_audit is False else "advisory withdrawn"
        )
    elif named:
        verdict = CveReplayVerdict.DETECTED
        reason = "advisory identifier named in findings or negative results"
    elif areas:
        verdict = CveReplayVerdict.UNCLEAR
        reason = f"affected area named without advisory identifier: {', '.join(areas)}"
    else:
        verdict = CveReplayVerdict.MISSED
        reason = (
            "neither advisory identifier nor affected area named in findings or negative results"
        )
    return CveReplayCandidate(
        **audit.model_dump(),
        advisory_id=str(advisory.display_id),
        aliases=tuple(sorted(identifiers - {str(advisory.display_id)})),
        published_at=advisory.published_at,
        checked_at=checked_at,
        severity=advisory.severity,
        summary=advisory.summary or advisory.details[:200],
        present_at_audit=present_at_audit,
        audit_verdict=verdict,
        matched_advisory_ids=named,
        reason=reason,
        source=advisory.source,
    )


def candidates(state: CveReplayState) -> CveReplayCandidates:
    return CveReplayCandidates(candidates=tuple(r for r in state.checks if r.queue_eligible))


def trends(state: CveReplayState) -> CveReplayTrends:
    return CveReplayTrends(rows=tuple(r for r in state.checks if r.trend_eligible))


def merge(state: CveReplayState, checks: Iterable[CveReplayCandidate]) -> CveReplayState:
    rows = list(state.checks)
    for check in checks:
        aliases = {check.advisory_id.upper(), *(a.upper() for a in check.aliases)}
        if any(
            r.repository_id == check.repository_id
            and r.audited_commit == check.audited_commit
            and r.audit_id == check.audit_id
            and aliases & {r.advisory_id.upper(), *(a.upper() for a in r.aliases)}
            for r in rows
        ):
            continue
        rows.append(check)
    return state.model_copy(update={"checks": tuple(rows)})


def _names(text: str, identifier: str) -> bool:
    return bool(re.search(rf"(?<![\w-]){re.escape(identifier)}(?![\w-])", text, re.IGNORECASE))


def _areas(advisory: AdvisoryRecord) -> tuple[str, ...]:
    areas: list[str] = []
    for package in advisory.affected:
        for path in package.imports:
            subpath = path.removeprefix(package.name).strip("/")
            if path != package.name and len(subpath) >= 4:
                areas.append(subpath)
        for symbol in package.symbols:
            for path in package.imports:
                symbol = symbol.removeprefix(f"{path}.")
            if len(symbol) >= 4:
                areas.append(symbol)
    return tuple(dict.fromkeys(areas))
