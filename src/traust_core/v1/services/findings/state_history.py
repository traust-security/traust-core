"""The finding state projection: the folded state stamped on each decision row.

`Disposition.fold` over the finding's decision history - the census's own
derivation - stamped at insert (`stamp`), read as the latest decision's
columns (`DecisionRepository.current_states`), backfilled (`backfill`) and
drift-checked (`check`) through the same fold. Never updated except the
backfill's fill of NULLs; reconcilable by replay (the parity test).
"""

from __future__ import annotations

import logging
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from uuid import UUID

from traust_core.v1.models.findings import Decision, Disposition, Occurrence, finding_state, kind_of
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.facts import decision_lines
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.portfolio import Inventory

# Bumped when the fold policy changes; the rebuild re-stamps.
POLICY_VERSION = "2026-11-16.1"

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Folded:
    state: str
    severity: Severity | None
    decided: bool
    proven: bool
    unverified: bool

    def onto_finding(self, uow: TraustUnitOfWork, finding_id: UUID) -> None:
        """The finding's current answer: what dashboards read, stamped from this fold."""
        severity = self.severity.value if self.severity is not None else None
        uow.findings.stamp_current(finding_id, self.state, severity, self.decided)

    def onto(self, draft: Decision) -> Decision:
        return draft.model_copy(
            update={
                "folded_state": self.state,
                "folded_severity": self.severity.value if self.severity is not None else None,
                "folded_decided": self.decided,
                "folded_proven": self.proven,
                "folded_unverified": self.unverified,
                "folded_policy_version": POLICY_VERSION,
            }
        )


def fold(
    uow: TraustUnitOfWork,
    rating: RatingPolicy,
    finding_id: UUID,
    kind: str | None,
    decisions: Sequence[Decision],
) -> Folded:
    """The census's derivation, unchanged."""
    judged = [
        d
        for d in decisions
        if d.validity is not None or d.severity is not None or d.resolution is not None
    ]
    disposition: Disposition | None = None
    if judged:
        lines: dict[UUID, bool] = {}
        if any(d.assessment_id is not None or d.repository_ref_id is not None for d in judged):
            refs = Inventory(uow).census_refs_of([finding_id])
            log = AssessmentLog(uow)
            assessments = {d.assessment_id for d in judged if d.assessment_id is not None}
            rows = {row.id: row for row in log.census_by_ids(assessments)} if assessments else {}
            baselines = {
                row.id: row
                for row in log.census_by_ids(
                    {
                        a.baseline_assessment_id
                        for a in rows.values()
                        if a.baseline_assessment_id is not None
                    }
                )
            }
            lines = decision_lines(judged, rows, baselines, refs)
        disposition = Disposition.fold(finding_id, judged, lines)
    occurrence = _latest_report(uow, uow.occurrences.list_for_finding(finding_id))
    return Folded(
        state=finding_state(kind_of(kind, tuple(d.validity for d in decisions)), disposition),
        severity=rating.effective_severity(occurrence, disposition),
        decided=disposition is not None,
        proven=disposition is not None
        and disposition.assurance == DispositionAssurance.EXECUTION_PROVEN,
        unverified=disposition is None or disposition.assurance == DispositionAssurance.CLAIMED,
    )


def _latest_report(uow: TraustUnitOfWork, occurrences: Sequence[Occurrence]) -> Occurrence | None:
    # the views' report order: the reporting assessment's time, then the occurrence's own
    if not occurrences:
        return None
    when = {
        a.id: a.occurred_at
        for a in AssessmentLog(uow).list_by_ids({o.assessment_id for o in occurrences})
    }
    return max(occurrences, key=lambda o: (when[o.assessment_id], o.created_at, str(o.id)))


def stamp(
    draft: Decision,
    uow: TraustUnitOfWork,
    rating: RatingPolicy,
    *,
    history: Sequence[Decision] | None = None,
) -> Decision:
    """The single owner of the stored state: the draft and its finding stamped from one fold,
    in one transaction."""
    history = uow.decisions.list_for_finding(draft.finding_id) if history is None else history
    finding = uow.findings.get(draft.finding_id)
    folded = fold(uow, rating, draft.finding_id, finding.kind, [*history, draft])
    folded.onto_finding(uow, draft.finding_id)
    return folded.onto(draft)


def restamp(uow: TraustUnitOfWork, rating: RatingPolicy, finding_id: UUID) -> None:
    """Refold one finding and stamp its current answer: after an occurrence, so the
    effective severity follows the most recent report (Q8) under the standing judgment."""
    finding = uow.findings.get(finding_id)
    decisions = uow.decisions.list_for_finding(finding_id)
    fold(uow, rating, finding_id, finding.kind, decisions).onto_finding(uow, finding_id)


def restamp_all(
    uow: TraustUnitOfWork, rating: RatingPolicy, repository_ids: Collection[UUID]
) -> int:
    """Stamp every finding's current answer from the fold: data channel 0002's one-time
    upgrade path - remove with that entry once every store has applied it."""
    stamped = 0
    for finding_id, _repository_id, kind, _title, _created in uow.findings.census_for_repositories(
        repository_ids
    ):
        decisions = uow.decisions.list_for_finding(finding_id)
        fold(uow, rating, finding_id, kind, decisions).onto_finding(uow, finding_id)
        stamped += 1
    return stamped


@dataclass(frozen=True, slots=True)
class Backfill:
    stamped: int = 0
    absent: int = 0


def _latest(decisions: Sequence[Decision]) -> Decision:
    """The row `current_states` reads: latest by insertion, not occurred_at."""
    return max(decisions, key=lambda d: (d.created_at, d.id or UUID(int=0)))


def backfill(
    uow: TraustUnitOfWork,
    rating: RatingPolicy,
    repository_ids: Collection[UUID],
) -> Backfill:
    """Fold once per finding, stamp its latest decision row (filling NULLs).

    One-time upgrade path: exists only for decisions written before the
    projection. Once every environment is stamped, remove this (and
    DecisionRepository.stamp_latest, and the trigger carve-out it rides -
    a later migration restores the absolute append-only guard). check()
    stays: it is the drift detector, not the upgrade.
    """
    stamped = absent = 0
    rows = uow.findings.census_for_repositories(repository_ids)
    for finding_id, _repository_id, kind, _title, _created in rows:
        decisions = uow.decisions.list_for_finding(finding_id)
        if not decisions:
            absent += 1
            continue
        folded = fold(uow, rating, finding_id, kind, decisions)
        uow.decisions.stamp_latest(
            _latest(decisions).id,
            {
                "folded_state": folded.state,
                "folded_severity": (folded.severity.value if folded.severity is not None else None),
                "folded_decided": folded.decided,
                "folded_proven": folded.proven,
                "folded_unverified": folded.unverified,
                "folded_policy_version": POLICY_VERSION,
            },
        )
        stamped += 1
    log.info(
        "state projection backfill stamped=%d absent=%d",
        stamped,
        absent,
        extra={"operation": "state.backfill", "outcome": "stamped", "count": stamped},
    )
    return Backfill(stamped, absent)


@dataclass(frozen=True, slots=True)
class Drift:
    matched: int = 0
    drifted: int = 0
    unstamped: int = 0
    drifted_findings: tuple[UUID, ...] = ()

    def healthy(self) -> bool:
        return self.drifted == 0


def check(
    uow: TraustUnitOfWork,
    rating: RatingPolicy,
    repository_ids: Collection[UUID],
    *,
    report_limit: int = 20,
) -> Drift:
    """Re-derive without writing: the drift detector."""
    matched = drifted = unstamped = 0
    drifted_ids: list[UUID] = []
    rows = uow.findings.census_for_repositories(repository_ids)
    for finding_id, _r, kind, _t, _c in rows:
        decisions = uow.decisions.list_for_finding(finding_id)
        if not decisions:
            continue
        folded = fold(uow, rating, finding_id, kind, decisions)
        latest = _latest(decisions)
        if latest.folded_state is None:
            unstamped += 1
        elif (
            latest.folded_state == folded.state
            and latest.folded_severity
            == (folded.severity.value if folded.severity is not None else None)
            and latest.folded_decided == folded.decided
            and latest.folded_proven == folded.proven
            and latest.folded_unverified == folded.unverified
        ):
            matched += 1
        else:
            drifted += 1
            if len(drifted_ids) < report_limit:
                drifted_ids.append(finding_id)
    result = Drift(matched, drifted, unstamped, tuple(drifted_ids))
    log.info(
        "state projection check matched=%d drifted=%d unstamped=%d",
        matched,
        drifted,
        unstamped,
        extra={
            "operation": "state.check",
            "outcome": "healthy" if result.healthy() else "drifted",
            "count": drifted,
        },
    )
    return result
