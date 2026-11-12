from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from traust_core.v1.models.base import Model
from traust_core.v1.models.dependencies import AdvisoryRecord
from traust_core.v1.models.identity import IdentitySource
from traust_core.v1.models.vocabulary import ScannerSeverity


class CveReplayVerdict(StrEnum):
    DETECTED = "detected"
    UNCLEAR = "unclear"
    MISSED = "missed"
    NOT_APPLICABLE = "not_applicable"


class CveReplayAudit(Model):
    repository_id: UUID
    repository_ref_id: UUID
    repository: str
    audited_commit: str
    audit_id: UUID
    report_artifact_id: UUID
    audited_at: AwareDatetime


class CveReplayCandidate(CveReplayAudit):
    advisory_id: str
    aliases: tuple[str, ...] = ()
    published_at: AwareDatetime | None = None
    withdrawn: bool = Field(default=False, strict=True)
    checked_at: AwareDatetime
    severity: ScannerSeverity
    summary: str
    present_at_audit: bool | None
    reviewer: str | None = None
    presence_evidence: str | None = None
    presence_identity_source: IdentitySource | None = None
    matched_advisory_ids: tuple[str, ...] = ()
    audit_verdict: CveReplayVerdict
    reason: str
    source: str
    requires_human_review: Literal[True] = True

    @model_validator(mode="after")
    def human_presence(self) -> Self:
        if self.present_at_audit is not None:
            if self.reviewer is None or not self.reviewer.startswith("human:"):
                raise ValueError("CVE replay presence requires a verified human reviewer")
            if self.presence_identity_source is None:
                raise ValueError("CVE replay presence requires verified identity provenance")
            if self.presence_evidence is None or not self.presence_evidence.strip():
                raise ValueError("CVE replay presence evidence must not be blank")
        elif (
            self.reviewer is not None
            or self.presence_evidence is not None
            or self.presence_identity_source is not None
        ):
            raise ValueError("CVE replay presence evidence requires an explicit presence verdict")
        if self.audit_verdict == CveReplayVerdict.MISSED and self.present_at_audit is not True:
            raise ValueError("CVE replay miss requires human-confirmed presence at the audit")
        if self.audit_verdict == CveReplayVerdict.DETECTED and self.present_at_audit is False:
            raise ValueError(
                "CVE replay detection contradicts human-confirmed absence at the audit"
            )
        if (
            self.audit_verdict == CveReplayVerdict.NOT_APPLICABLE
            and self.present_at_audit is not False
            and not self.withdrawn
        ):
            raise ValueError("CVE replay exclusion requires human-confirmed absence or withdrawal")
        return self

    @property
    def queue_eligible(self) -> bool:
        return self.present_at_audit is not False and self.audit_verdict in (
            CveReplayVerdict.MISSED,
            CveReplayVerdict.UNCLEAR,
        )

    @property
    def trend_eligible(self) -> bool:
        return self.present_at_audit is True and self.audit_verdict == CveReplayVerdict.MISSED

    def same_advisory(self, other: CveReplayCandidate) -> bool:
        return (
            self.audit_id == other.audit_id
            and self.repository_ref_id == other.repository_ref_id
            and bool(self.identifiers & other.identifiers)
        )

    @property
    def identifiers(self) -> frozenset[str]:
        return frozenset(i.upper() for i in (self.advisory_id, *self.aliases))

    @classmethod
    def classify(
        cls,
        audit: CveReplayAudit,
        report_text: str,
        advisory: AdvisoryRecord,
        checked_at: AwareDatetime,
        *,
        present_at_audit: bool | None = None,
        reviewer: str | None = None,
        presence_identity_source: IdentitySource | None = None,
        presence_evidence: str | None = None,
    ) -> Self:
        identifiers = {str(advisory.identifier), *map(str, advisory.aliases)}
        named = tuple(sorted(i for i in identifiers if _names(report_text, i)))
        areas = tuple(a for a in _areas(advisory) if a.casefold() in report_text.casefold())
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
        elif present_at_audit is True:
            verdict = CveReplayVerdict.MISSED
            reason = "human-confirmed presence; no advisory identifier or affected area in report"
        else:
            verdict = CveReplayVerdict.UNCLEAR
            reason = "no report match; presence at the audited commit requires human adjudication"
        return cls(
            **audit.model_dump(),
            advisory_id=str(advisory.display_id),
            aliases=tuple(sorted(identifiers - {str(advisory.display_id)})),
            published_at=advisory.published_at,
            withdrawn=advisory.withdrawn,
            checked_at=checked_at,
            severity=advisory.severity,
            summary=advisory.summary or advisory.details[:200],
            present_at_audit=present_at_audit,
            reviewer=reviewer,
            presence_identity_source=presence_identity_source,
            presence_evidence=presence_evidence,
            audit_verdict=verdict,
            matched_advisory_ids=named,
            reason=reason,
            source=advisory.source,
        )


class CveReplayCandidates(Model):
    role: Literal["human-gated benchmark candidates; not admitted ground truth"] = (
        "human-gated benchmark candidates; not admitted ground truth"
    )
    candidates: tuple[CveReplayCandidate, ...] = ()


class CveReplayTrends(Model):
    series: Literal["fn_cve_replay_missed"] = "fn_cve_replay_missed"
    rows: tuple[CveReplayCandidate, ...] = ()


class CveReplayWatermark(Model):
    repository_id: UUID
    repository_ref_id: UUID
    audit_id: UUID
    checked_at: AwareDatetime


class CveReplayState(Model):
    watermarks: tuple[CveReplayWatermark, ...] = ()
    checks: tuple[CveReplayCandidate, ...] = ()

    def merged(self, checks: tuple[CveReplayCandidate, ...]) -> Self:
        rows = list(self.checks)
        for check in checks:
            index = next((i for i, old in enumerate(rows) if old.same_advisory(check)), None)
            if index is None:
                rows.append(check)
            elif check.present_at_audit is not None or rows[index].present_at_audit is None:
                rows[index] = check
        return self.model_copy(update={"checks": tuple(rows)})

    def candidates(self) -> CveReplayCandidates:
        return CveReplayCandidates(candidates=tuple(r for r in self.checks if r.queue_eligible))

    def trends(self) -> CveReplayTrends:
        return CveReplayTrends(rows=tuple(r for r in self.checks if r.trend_eligible))


class CveReplayRun(Model):
    checked_at: AwareDatetime
    audited_reports: int
    queried_commits: int
    checks: tuple[CveReplayCandidate, ...]
    watermarks: tuple[CveReplayWatermark, ...]
    candidates: CveReplayCandidates
    trends: CveReplayTrends


class CveReplaySnapshot(Model):
    audit: CveReplayAudit
    revision: int = Field(ge=1)
    watermark: AwareDatetime | None
    checks: tuple[CveReplayCandidate, ...] = ()

    @model_validator(mode="after")
    def bound_checks(self) -> Self:
        binding = self.audit.model_dump()
        if any(check.model_dump(include=set(binding)) != binding for check in self.checks):
            raise ValueError("CVE replay snapshot checks must bind the exact recorded audit")
        return self


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
