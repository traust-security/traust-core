from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Location,
    Precedent,
    PrecedentReason,
    PrecedentStrength,
    effective_decisions,
)
from traust_core.v1.models.vocabulary import ActorKind, FindingKind
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.identity import canon_path
from traust_core.v1.services.validation import ValidationRecords

log = logging.getLogger(__name__)

_VENDOR_ROOT = re.compile(
    r"(?:^|/)(?:vendor|_vendor|vendored|third_party|thirdparty|third-party|external|externals|"
    r"node_modules|bundled|Godeps/_workspace/src)/"
)
_REFUTING_KINDS = frozenset({"triage", "verification"})


def vendor_path(path: str | None) -> str:
    """The path after its last vendor root, so two repos vendoring one file name it alike."""
    s = canon_path(path)
    ends = [m.end() for m in _VENDOR_ROOT.finditer(s)]
    return s[ends[-1] :] if ends else s


class FindingPrecedents:
    """Prior verdict context matched by vendor-normalized path, enclosing symbol and shared CWE."""

    def __init__(
        self, uow: TraustUnitOfWork, *, validation: ValidationRecords | None = None
    ) -> None:
        self._uow = uow
        self._log = AssessmentLog(uow)
        self._validation = validation

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
            candidates = {
                other
                for other, keys in places.items()
                if other not in locations
                and any(keys & wanted[fid] and cwes[other] & cwes[fid] for fid in locations)
            }
            history: dict[UUID, list[Decision]] = defaultdict(list)
            for d in uow.decisions.list_for_findings(list(set(places) - set(locations))):
                history[d.finding_id].append(d)
            ids = {d.assessment_id for ds in history.values() for d in ds if d.assessment_id}
            assessments = self._log.list_by_ids(ids)
            kinds = {f.id: f.kind for f in uow.findings.list_by_ids(history)}
        refuting = {a.id for a in assessments if a.kind in _REFUTING_KINDS}
        validation_ids = {a.id for a in assessments if a.kind == "validation"}
        weaknesses = {
            other: (
                any(
                    pair.enum == "finding_kind" and pair.value == FindingKind.WEAKNESS
                    for pair in contracts.normalize_enum("finding_kind", kinds[other]).pairs
                )
                if kinds[other] is not None
                else any(d.validity == "hardening" for d in ds)
            )
            for other, ds in history.items()
        }
        possible = {
            other: select(other, ds, refuting | validation_ids, weakness=weaknesses[other])
            for other, ds in history.items()
        }
        validation = [
            d
            for other, ds in history.items()
            if other in candidates
            and possible[other] is not None
            and possible[other][1] == PrecedentStrength.MACHINE
            for d in effective_decisions(ds)
            if d.assessment_id in validation_ids and d.validity == "false_positive"
        ]
        verified: set[UUID] = set()
        if validation:
            if self._validation is None:
                log.warning("validation precedents excluded: evidence reader is not configured")
            else:
                verified = {
                    check.decision_id
                    for check in self._validation.check_refutations(validation)
                    if check.reason is None
                }
                with self._uow as uow:
                    fresh: dict[UUID, list[Decision]] = defaultdict(list)
                    for d in uow.decisions.list_for_findings(list(history)):
                        fresh[d.finding_id].append(d)
                history = fresh
        picks = {
            other: select(
                other,
                ds,
                refuting,
                weakness=weaknesses[other],
                verified=verified,
            )
            for other, ds in history.items()
        }

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
    refuting: Collection[UUID],
    *,
    weakness: bool,
    verified: Collection[UUID] = (),
) -> tuple[Decision, PrecedentStrength] | None:
    """The strongest standing human verdict, else an uncontested eligible machine refutation."""
    decisions = effective_decisions(decisions)
    now = Disposition.fold(finding_id, decisions)
    verdicts = {"false_positive", "confirmed"} if weakness else {"false_positive"}
    people = [d for d in decisions if d.validity in verdicts and _is_person(d)]
    if people:
        latest = people[-1]
        return (latest, PrecedentStrength.HUMAN) if now.validity == latest.validity else None
    if (not weakness and any(d.validity == "confirmed" for d in decisions)) or now.fp_overridden:
        return None
    if now.validity == "confirmed" and not weakness:
        return None
    if now.validity is not None and now.validity not in verdicts:
        return None
    machines = [
        d
        for d in decisions
        if d.validity in verdicts and (d.assessment_id in refuting or d.id in verified)
    ]
    return (machines[-1], PrecedentStrength.MACHINE) if machines else None


def _rank(p: Precedent) -> tuple[bool, float]:
    return (p.reason.strength != PrecedentStrength.HUMAN, -p.decision.occurred_at.timestamp())


def _is_person(decision: Decision) -> bool:
    return (decision.actor or "").startswith(f"{ActorKind.HUMAN}:")
