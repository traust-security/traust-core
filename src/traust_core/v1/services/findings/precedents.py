from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Collection, Iterator, Mapping, Sequence
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import FILE_BYTES_SHA256, CodeHash
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    HashUnavailable,
    Location,
    Precedent,
    PrecedentBasis,
    PrecedentReason,
    PrecedentStrength,
    effective_decisions,
)
from traust_core.v1.models.vocabulary import ActorKind, FindingKind
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.identity import canon_path
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.validation import ValidationRecords

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
        keys = set().union(*wanted.values())
        same_place = []
        occurrences = {}
        hashes: dict[UUID, list[CodeHash]] = defaultdict(list)
        cwes: dict[UUID, set[UUID]] = defaultdict(set)
        read_cwes: set[UUID] = set()
        after = None
        target_ids = {loc.id for locs in locations.values() for loc in locs if loc.id is not None}
        while True:
            with self._uow as uow:
                page = uow.locations.list_with_symbols_page(symbols, 250, after)
                relevant = [loc for loc in page if (vendor_path(loc.path), loc.symbol) in keys]
                ids = {loc.id for loc in relevant}
                if after is None:
                    ids |= target_ids
                for claim in uow.location_hashes.list_for_locations(ids):
                    hashes[claim.location_id].append(
                        CodeHash(algorithm=claim.algorithm, digest=claim.digest)
                    )
                occurrences.update(
                    {
                        o.id: o
                        for o in uow.occurrences.list_by_ids(
                            {loc.occurrence_id for loc in relevant}
                        )
                    }
                )
                related = {occurrences[loc.occurrence_id].finding_id for loc in relevant} | set(
                    locations
                )
                for batch in _batches(related - read_cwes):
                    for link in uow.finding_cwes.list_for_findings(batch):
                        cwes[link.finding_id].add(link.cwe_id)
                read_cwes |= related
                same_place.extend(relevant)
            if len(page) < 250:
                break
            after = (page[-1].symbol, page[-1].id)
        places: dict[UUID, set[tuple[str, str]]] = defaultdict(set)
        by_finding: dict[UUID, list[Location]] = defaultdict(list)
        for loc in same_place:
            fid = occurrences[loc.occurrence_id].finding_id
            places[fid].add((vendor_path(loc.path), loc.symbol))
            by_finding[fid].append(loc)
        with self._uow as uow:
            candidates = {
                other
                for other, keys in places.items()
                if other not in locations
                and any(keys & wanted[fid] and cwes[other] & cwes[fid] for fid in locations)
            }
            history: dict[UUID, list[Decision]] = defaultdict(list)
            for batch in _batches(candidates):
                for d in uow.decisions.list_for_findings(batch):
                    history[d.finding_id].append(d)
            ids = {d.assessment_id for ds in history.values() for d in ds if d.assessment_id}
            assessments = [a for batch in _batches(ids) for a in self._log.list_by_ids(batch)]
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
                raise ConfigError(
                    "validation precedents need an evidence reader: wire one "
                    "(FindingPrecedents(validation=ValidationRecords)); Context always does"
                )
            verified = {
                check.decision_id
                for check in self._validation.check_refutations(validation)
                if check.reason is None
            }
            with self._uow as uow:
                fresh: dict[UUID, list[Decision]] = defaultdict(list)
                for batch in _batches(history):
                    for d in uow.decisions.list_for_findings(batch):
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

        selected = [picked[0] for picked in picks.values() if picked is not None]
        selected_ids = {d.finding_id for d in selected}
        assessed = {
            a.id: a
            for batch in _batches(
                {o.assessment_id for o in occurrences.values() if o.finding_id in selected_ids}
                | {d.assessment_id for d in selected if d.assessment_id is not None}
            )
            for a in self._log.list_by_ids(batch)
        }
        refs = {
            r.id: r
            for r in Inventory(self._uow).list_refs_by_ids(
                {a.repository_ref_id for a in assessed.values()}
                | {d.repository_ref_id for d in selected if d.repository_ref_id is not None}
            )
        }
        commits = {r.id: (r.repository_id, r.sha) for r in refs.values()}
        place_commits = {
            loc.id: commits[
                assessed[occurrences[loc.occurrence_id].assessment_id].repository_ref_id
            ]
            for loc in same_place
            if occurrences[loc.occurrence_id].finding_id in selected_ids
        }

        found: dict[UUID, list[Precedent]] = {}
        for fid, keys in wanted.items():
            out = []
            for other, picked in picks.items():
                shared = keys & places[other]
                if other == fid or not shared or not cwes[other] & cwes[fid] or picked is None:
                    continue
                decision = picked[0]
                ref_id = (
                    assessed[decision.assessment_id].repository_ref_id
                    if decision.assessment_id is not None
                    else decision.repository_ref_id
                )
                judged = commits[ref_id] if ref_id is not None else None
                reasons = []
                for path, symbol in sorted(shared):
                    target = [
                        loc
                        for loc in locations[fid]
                        if (vendor_path(loc.path), loc.symbol) == (path, symbol)
                    ]
                    prior = [
                        loc
                        for loc in by_finding[other]
                        if (vendor_path(loc.path), loc.symbol) == (path, symbol)
                        and judged is not None
                        and place_commits[loc.id] == judged
                    ]
                    reason = match_reason(
                        picked[1],
                        path,
                        symbol,
                        [h for loc in target for h in hashes.get(loc.id, ())],
                        [h for loc in prior for h in hashes.get(loc.id, ())],
                        bound=bool(prior),
                    )
                    if reason is not None:
                        reasons.append(reason)
                if not reasons:
                    continue
                reason = min(
                    reasons, key=lambda r: (r.basis != PrecedentBasis.HASH_BACKED, r.path, r.symbol)
                )
                out.append(Precedent(decision=picked[0], similarity=1.0, reason=reason))
            out.sort(key=_rank)
            if out:
                found[fid] = out[:limit]
        return found


def _batches(ids: Collection[UUID]) -> Iterator[list[UUID]]:
    values = list(dict.fromkeys(ids))
    for start in range(0, len(values), 250):
        yield values[start : start + 250]


def match_reason(
    strength: PrecedentStrength,
    path: str,
    symbol: str,
    target: Sequence[CodeHash],
    prior: Sequence[CodeHash],
    *,
    bound: bool,
) -> PrecedentReason | None:
    if not bound:
        return PrecedentReason(
            strength=strength, path=path, symbol=symbol, unavailable_reason=HashUnavailable.BINDING
        )
    if not target or not prior:
        unavailable = (
            HashUnavailable.BOTH
            if not target and not prior
            else HashUnavailable.TARGET
            if not target
            else HashUnavailable.PRIOR
        )
        return PrecedentReason(
            strength=strength, path=path, symbol=symbol, unavailable_reason=unavailable
        )
    left: dict[str, set[str]] = defaultdict(set)
    right: dict[str, set[str]] = defaultdict(set)
    for claim in target:
        left[claim.algorithm].add(claim.digest)
    for claim in prior:
        right[claim.algorithm].add(claim.digest)
    common = left.keys() & right.keys() & {FILE_BYTES_SHA256}
    if not common or any(left[a] != right[a] or len(left[a]) != 1 for a in common):
        return None
    return PrecedentReason(
        strength=strength,
        path=path,
        symbol=symbol,
        basis=PrecedentBasis.HASH_BACKED,
        unavailable_reason=None,
        hashes=tuple(CodeHash(algorithm=a, digest=next(iter(left[a]))) for a in sorted(common)),
    )


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
