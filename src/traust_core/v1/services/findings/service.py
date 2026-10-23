from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.common import Page, PageRequest, TimeBucket
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
    Occurrence,
)
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.review import FindingReview


class FindingService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        decisions: FindingDecisions,
        review: FindingReview,
        precedents: FindingPrecedents,
        rating: RatingPolicy,
    ) -> None:
        self._uow = uow
        self._rating = rating
        self.intake = intake
        self.decisions = decisions
        self.review = review
        self.precedents = precedents

    def get(self, finding_id: UUID) -> FindingView:
        with self._uow as uow:
            (view,) = self._views(uow, [uow.findings.get(finding_id)], as_of=None)
        return view

    def list(self, filter: FindingFilter, page: PageRequest) -> Page[FindingView]:
        raise NotImplementedError("stub: replaces corpus/findings_db.py, open_findings")

    def history(self, finding_id: UUID) -> list[Decision]:
        return self.decisions.list_for_finding(finding_id)

    def baseline(self, repository_id: UUID, as_of: datetime) -> list[FindingView]:
        """The repository's findings as they stood at `as_of`: reported by then, judged by then."""
        with self._uow as uow:
            return self._views(uow, uow.findings.list_for_repository(repository_id), as_of)

    def open_count(self, repository_id: UUID, severities: Sequence[Severity]) -> int:
        with self._uow as uow:
            return uow.open_counts.open_count(repository_id, severities)

    def summary(self, filter: FindingFilter, group_by: FindingDimension) -> list[FindingRollup]:
        raise NotImplementedError("stub: replaces findings_summary, pattern_exposure, dashboards")

    def timeline(self, filter: FindingFilter, bucket: TimeBucket) -> list[FindingSeriesPoint]:
        raise NotImplementedError("stub: replaces build_cumulative.py, build_trends buckets")

    def _views(
        self, uow: TraustUnitOfWork, findings: Sequence[Finding], as_of: datetime | None
    ) -> list[FindingView]:
        """One query per table for the set; a finding not yet reported at `as_of` is left out."""
        ids = [f.id for f in findings if f.id is not None]
        decisions: defaultdict[UUID, list[Decision]] = defaultdict(list)
        for d in uow.decisions.list_for_findings(ids, until=as_of):
            decisions[d.finding_id].append(d)
        occurrences = uow.occurrences.list_for_findings(ids)
        assessments = uow.assessments.list_by_ids(
            {o.assessment_id for o in occurrences}
            | {d.assessment_id for ds in decisions.values() for d in ds if d.assessment_id}
        )
        at = {a.id: a.occurred_at for a in assessments}
        seen: defaultdict[UUID, list[Occurrence]] = defaultdict(list)
        for o in sorted(occurrences, key=lambda o: at[o.assessment_id]):
            if as_of is None or at[o.assessment_id] <= as_of:
                seen[o.finding_id].append(o)
        views = []
        for finding in findings:
            assert finding.id is not None
            reported, said = seen[finding.id], decisions[finding.id]
            if as_of is not None and not reported:
                continue
            latest = reported[-1] if reported else None
            disposition = Disposition.fold(finding.id, said) if said else None
            severity = self._rating.effective_severity(latest, disposition)
            due = None
            if latest is not None and (disposition is None or disposition.is_open()):
                opened = at[reported[0].assessment_id]
                due = self._rating.sla_due(severity, opened, latest.cvss_score)
            views.append(
                FindingView(
                    finding=finding,
                    occurrence=latest,
                    disposition=disposition,
                    effective_severity=severity,
                    sla_due=due,
                )
            )
        return views
