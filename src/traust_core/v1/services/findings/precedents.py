from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from uuid import UUID

from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Location,
    Precedent,
    PrecedentReason,
    PrecedentStrength,
    report_sources,
)
from traust_core.v1.models.vocabulary import ActorKind, SourceType
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.identity import canon_path

VERDICTS = ("false_positive", "hardening")
_VENDOR_ROOT = re.compile(
    r"(?:^|/)(?:vendor|_vendor|vendored|third_party|thirdparty|third-party|external|externals|"
    r"node_modules|bundled|Godeps/_workspace/src)/"
)
# Assessor refutations from these kinds count; validation refutations wait on the validation
# domain's soundness gate (unverifiable means excluded, as before).
_REFUTING_KINDS = frozenset({"triage", "verification"})


def vendor_path(path: str | None) -> str:
    """The path after its last vendor root, so two repos vendoring one file name it alike."""
    s = canon_path(path)
    ends = [m.end() for m in _VENDOR_ROOT.finditer(s)]
    return s[ends[-1] :] if ends else s


class FindingPrecedents:
    """Prior verdicts on the same function in the same file, in any repository; never a verdict.

    Keyed on `location` (vendor-normalized path + enclosing symbol) and a shared CWE, not a
    path-and-CWE hash: two issues in one file under one CWE stay apart.
    """

    def __init__(self, uow: TraustUnitOfWork) -> None:
        self._uow = uow
        self._log = AssessmentLog(uow)

    def for_locations(
        self, finding_id: UUID, locations: Sequence[Location], limit: int
    ) -> list[Precedent]:
        return self.for_findings({finding_id: locations}, limit).get(finding_id, [])

    def for_findings(
        self, locations: Mapping[UUID, Sequence[Location]], limit: int
    ) -> dict[UUID, list[Precedent]]:
        """Up to `limit` per finding, strongest then newest; no symbol, no match."""
        wanted = {
            fid: {(vendor_path(loc.path), loc.symbol) for loc in locs if loc.symbol}
            for fid, locs in locations.items()
        }
        symbols = {symbol for keys in wanted.values() for _, symbol in keys}
        if not symbols:
            return {}
        with self._uow as uow:
            same_place = uow.locations.list_with_symbols(symbols)
            occurrences = {
                o.id: o
                for o in uow.occurrences.list_by_ids({loc.occurrence_id for loc in same_place})
            }
            places: dict[UUID, set[tuple[str, str]]] = defaultdict(set)
            for loc in same_place:
                places[occurrences[loc.occurrence_id].finding_id].add(
                    (vendor_path(loc.path), loc.symbol)
                )
            related = set(places) | set(locations)
            cwes: dict[UUID, set[UUID]] = defaultdict(set)
            for link in uow.finding_cwes.list_for_findings(related):
                cwes[link.finding_id].add(link.cwe_id)
            history: dict[UUID, list[Decision]] = defaultdict(list)
            for d in uow.decisions.list_for_findings(list(set(places) - set(locations))):
                history[d.finding_id].append(d)
            ids = {d.assessment_id for ds in history.values() for d in ds if d.assessment_id}
            assessments = self._log.list_by_ids(ids)
        sources = report_sources(assessments)
        refuting = {a.id for a in assessments if a.kind in _REFUTING_KINDS}
        picks = {other: select(other, ds, sources, refuting) for other, ds in history.items()}

        found: dict[UUID, list[Precedent]] = {}
        for fid, keys in wanted.items():
            out = []
            for other, picked in picks.items():
                shared = keys & places[other]
                if other == fid or not shared or not cwes[other] & cwes[fid] or picked is None:
                    continue
                path, symbol = min(shared)
                reason = PrecedentReason(strength=picked[1], path=path, symbol=symbol)
                out.append(Precedent(decision=picked[0], similarity=1.0, reason=reason))
            out.sort(key=_rank)
            if out:
                found[fid] = out[:limit]
        return found


def select(
    finding_id: UUID,
    decisions: Sequence[Decision],
    sources: Mapping[UUID, SourceType],
    refuting: Collection[UUID],
) -> tuple[Decision, PrecedentStrength] | None:
    """A finding's precedent and its strength, or None.

    A person's latest FP / hardening verdict, while the finding's disposition still agrees. Else an
    assessor's (an assessment, no actor) from a triage or verification, unless anyone confirmed
    the finding, it is confirmed or corrected now, or a person overrode an FP.
    """
    now = Disposition.fold(finding_id, decisions, sources)
    people = [d for d in decisions if d.validity in VERDICTS and _is_person(d)]
    if people:
        latest = people[-1]
        return (latest, PrecedentStrength.HUMAN) if now.validity == latest.validity else None
    if any(d.validity == "confirmed" for d in decisions) or now.fp_overridden:
        return None
    if now.validity in ("confirmed", "corrected"):
        return None
    machines = [d for d in decisions if d.validity in VERDICTS and d.assessment_id in refuting]
    return (machines[-1], PrecedentStrength.MACHINE) if machines else None


def _rank(p: Precedent) -> tuple[bool, float]:
    return (p.reason.strength != PrecedentStrength.HUMAN, -p.decision.occurred_at.timestamp())


def _is_person(decision: Decision) -> bool:
    return (decision.actor or "").startswith(f"{ActorKind.HUMAN}:")
