"""The findings census: the counted facts of a whole scope, folded from narrow SQL rows.

What the rollup's tallies read — states, severities, category labels, the top cut —
never needs a `FindingView`: a view carries locations, cwes and normalized histories a
count never looks at, and materializing one per finding (230k rows as models on the
estate the audit measured) is what starved core under dashboard load. The census reads
one narrow column set per table, folds the same policy the views fold (the disposition,
the kind crosswalk, the rating) over tuples, and hands each bounded batch of rows to
the counter — the views' outputs unchanged, their cost not.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from functools import cache
from typing import NamedTuple
from uuid import UUID

from traust_core.v1.models.assessment import CensusAssessment
from traust_core.v1.models.findings import (
    CensusDecision,
    Disposition,
    Finding,
    FindingState,
    finding_state,
    kind_of,
    newest_first_key,
    normalize_classifiers,
)
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.claims import ApprovedClaim, approved_claims_for, claim_fold
from traust_core.v1.services.findings.facts import decision_lines
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.portfolio import Inventory

# The census walks whole repositories at a time, a batch closed once it holds this many
# findings: memory stays bounded by findings, never by repository count alone — a
# monorepo estate cannot load a whole table in one batch, and a single repository larger
# than the bound is its own batch, whole. Narrow rows weigh a fraction of the models the
# fold's own `_FACTS_BATCH` bounded at a thousand, so a batch here holds ten thousand
# findings' tuples — tens of megabytes — while keeping the statement count near the
# batch count.
_FINDINGS_PER_BATCH = 10_000


@dataclass(frozen=True, slots=True)
class FindingCensusRow:
    """One finding's counted facts: what every tally of the rollup reads, nothing a
    listing serves."""

    finding_id: UUID
    repository_id: UUID
    state: FindingState
    severity: Severity | None
    category: str | None
    decided: bool
    proven: bool
    unverified: bool
    # the top cut's own fields, read only for an open critical or high finding
    title: str
    cvss_score: Decimal | None
    sla_due: datetime | None


class CensusOccurrence(NamedTuple):
    """The latest report's census columns — what the rating and the top cut read — with
    the first report's time (the clock an SLA reads)."""

    severity: str | None
    cvss_score: Decimal | None
    first: datetime


@cache
def _crosswalk(
    validity: str | None,
    resolution: str | None,
    evidence_grade: str | None,
    reason: str | None,
    severity: str | None,
    source_channel: str | None,
) -> tuple[str | None, str | None, str | None, str | None, str | None, str | None]:
    """`normalize_classifiers` on the values alone: an estate repeats a handful of
    classifier combinations, so the crosswalk runs once per distinct one."""
    return normalize_classifiers(
        validity, resolution, evidence_grade, reason, severity, source_channel
    )


def _normalized(row: CensusDecision) -> CensusDecision:
    """The fold's narrow normalizer: the same crosswalk `normalize_decision` applies,
    on the census row's own columns."""
    validity, resolution, evidence_grade, _, severity, _ = _crosswalk(
        row.validity,
        row.resolution,
        row.evidence_grade,
        row.reason,
        row.severity,
        row.source_channel,
    )
    if (row.validity, row.resolution, row.evidence_grade, row.severity) == (
        validity,
        resolution,
        evidence_grade,
        severity,
    ):
        return row
    return row._replace(
        validity=validity, resolution=resolution, evidence_grade=evidence_grade, severity=severity
    )


class FindingCensus:
    """The scope's findings as census rows, within the caller's transaction: one narrow
    column set per table, the disposition folded over tuples (the policy's own owner),
    each bounded batch of whole repositories handed to the counter and released."""

    def __init__(self, rating: RatingPolicy, objects: ObjectStore | None = None) -> None:
        self._rating = rating
        self._objects = objects

    def rows(
        self,
        uow: TraustUnitOfWork,
        repository_ids: Collection[UUID],
        as_of: datetime | None = None,
    ) -> Iterator[list[FindingCensusRow]]:
        wanted = list(dict.fromkeys(repository_ids))
        if not wanted:
            return
        sizes = dict(uow.findings.census_counts_for_repositories(wanted))
        if not any(sizes.values()):
            return  # a scope with no findings reads no claims and counts no rows
        # the claim candidates are one distinct query for the whole scope, not per batch
        with_claims = set(uow.decisions.list_finding_ids_with_claims())
        batch: list[UUID] = []
        counted = 0
        for repository_id in wanted:
            size = sizes.get(repository_id, 0)
            if batch and counted + size > _FINDINGS_PER_BATCH:
                yield self._rows_of(uow, batch, as_of, with_claims)
                batch, counted = [], 0
            batch.append(repository_id)
            counted += size
        if batch:
            yield self._rows_of(uow, batch, as_of, with_claims)

    def _rows_of(
        self,
        uow: TraustUnitOfWork,
        batch: Sequence[UUID],
        as_of: datetime | None,
        with_claims: set[UUID],
    ) -> list[FindingCensusRow]:
        findings = uow.findings.census_for_repositories(batch)
        if not findings:
            return []
        # the fold's own within-repository order, newest first: the top cut's stable-sort
        # ties break exactly as the views' fold broke them (the SQL's (id) tie-break is not
        # the fold's (str(id)) one, so the exact key is applied here)
        findings.sort(key=lambda row: newest_first_key(row[4], row[0]))
        latest = {
            finding_id: CensusOccurrence(severity, cvss, first)
            for finding_id, severity, cvss, first in uow.census_reads.occurrences_for_repositories(
                batch, as_of
            )
        }
        decisions: defaultdict[UUID, list[CensusDecision]] = defaultdict(list)
        for decision in uow.census_reads.decisions_for_repositories(batch, until=as_of):
            decisions[decision.finding_id].append(decision)
        categories: dict[UUID, str | None] = {}
        for finding_id, label in uow.census_reads.labels_for_repositories(batch):
            if finding_id not in categories:
                categories[finding_id] = label
        claims = self._claims_of(uow, findings, with_claims)
        lines = self._lines_of(uow, decisions, batch)
        return [
            row
            for finding in findings
            if (row := self._row(finding, as_of, latest, decisions, categories, claims, lines))
            is not None
        ]

    def _claims_of(
        self,
        uow: TraustUnitOfWork,
        findings: Sequence[tuple[UUID, UUID, str | None, str, datetime]],
        with_claims: set[UUID],
    ) -> Mapping[UUID, Sequence[ApprovedClaim]]:
        if self._objects is None:
            return {}
        corrected = [
            Finding(
                id=finding_id,
                repository_id=repository_id,
                fingerprint_algo="",
                fingerprint="",
                title=title,
            )
            for finding_id, repository_id, _, title, _ in findings
            if finding_id in with_claims
        ]
        if not corrected:
            return {}
        return approved_claims_for(uow, self._objects, corrected)

    @staticmethod
    def _lines_of(
        uow: TraustUnitOfWork,
        decisions: Mapping[UUID, Sequence[CensusDecision]],
        batch: Sequence[UUID],
    ) -> dict[UUID, bool]:
        """The decisions' default-line mapping, over the census's own narrow rows. A scope
        whose decisions are all line-free (no assessment, no named ref) folds no lines, so
        its refs stay unread."""
        said = [decision for rows in decisions.values() for decision in rows]
        if not any(d.assessment_id is not None or d.repository_ref_id is not None for d in said):
            return {}
        refs = Inventory(uow).census_refs_of(batch)
        log = AssessmentLog(uow)
        judged = {decision.assessment_id for decision in said if decision.assessment_id is not None}
        assessments: dict[UUID, CensusAssessment] = {
            row.id: row for row in (log.census_by_ids(judged) if judged else ())
        }
        baselines = {
            row.id: row
            for row in log.census_by_ids(
                {
                    a.baseline_assessment_id
                    for a in assessments.values()
                    if a.baseline_assessment_id is not None
                }
            )
        }
        return decision_lines(said, assessments, baselines, refs)

    def _row(
        self,
        finding: tuple[UUID, UUID, str | None, str, datetime],
        as_of: datetime | None,
        latest: Mapping[UUID, CensusOccurrence],
        decisions: Mapping[UUID, Sequence[CensusDecision]],
        categories: Mapping[UUID, str | None],
        claims: Mapping[UUID, Sequence[ApprovedClaim]],
        lines: Mapping[UUID, bool],
    ) -> FindingCensusRow | None:
        finding_id, repository_id, kind, title, _ = finding
        occurrence = latest.get(finding_id)
        if as_of is not None and occurrence is None:
            return None  # never reported by then: the view a tally would count is absent
        raw = decisions.get(finding_id, ())
        # the fold's own None rule (facts.disposition): no judgement-bearing decision,
        # no disposition — an unjudged finding counts as open, never as an empty fold
        judged = [
            d
            for d in raw
            if d.validity is not None or d.severity is not None or d.resolution is not None
        ]
        disposition = (
            Disposition.fold(finding_id, judged, lines, normalize=_normalized) if judged else None
        )
        state = finding_state(kind_of(kind, tuple(d.validity for d in raw)), disposition)
        severity = self._rating.effective_severity(occurrence, disposition)
        folded = claim_fold(claims.get(finding_id, ()), as_of)
        category = categories.get(finding_id)
        if folded is not None and folded.claim is not None:
            category = folded.category
        due = None
        if occurrence is not None and (disposition is None or disposition.is_open()):
            due = self._rating.sla_due(severity, occurrence.first, occurrence.cvss_score)
        return FindingCensusRow(
            finding_id=finding_id,
            repository_id=repository_id,
            state=state,
            severity=severity,
            category=category,
            decided=disposition is not None,
            proven=disposition is not None
            and disposition.assurance == DispositionAssurance.EXECUTION_PROVEN,
            unverified=disposition is None or disposition.assurance == DispositionAssurance.CLAIMED,
            title=folded.title if folded is not None else title,
            cvss_score=occurrence.cvss_score if occurrence is not None else None,
            sla_due=due,
        )
