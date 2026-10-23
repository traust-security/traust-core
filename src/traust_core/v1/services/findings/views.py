from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingLabel,
    FindingView,
    Location,
    Occurrence,
    ReviewCase,
    ReviewItem,
    normalize_decision,
)
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.rating import RatingPolicy


class FindingViewQuery:
    """Batched finding context and normalized history, within the caller's transaction."""

    def __init__(self, rating: RatingPolicy) -> None:
        self._rating = rating

    def views(
        self,
        uow: TraustUnitOfWork,
        findings: Sequence[Finding],
        as_of: datetime | None = None,
    ) -> list[FindingView]:
        views, _ = self._read(uow, findings, as_of)
        return views

    def review_cases(self, uow: TraustUnitOfWork, items: Sequence[ReviewItem]) -> list[ReviewCase]:
        if not items:
            return []
        findings = uow.findings.list_by_ids({item.finding_id for item in items})
        views, history = self._read(uow, findings, None)
        by_id = {view.finding.id: view for view in views}
        histories = {
            finding_id: tuple(normalize_decision(row) for row in rows)
            for finding_id, rows in history.items()
        }
        return [
            ReviewCase(
                review_item=item,
                finding=by_id[item.finding_id],
                history=histories.get(item.finding_id, ()),
            )
            for item in items
        ]

    def _read(
        self, uow: TraustUnitOfWork, findings: Sequence[Finding], as_of: datetime | None
    ) -> tuple[list[FindingView], dict[UUID, list[Decision]]]:
        if not findings:
            return [], {}
        ids = [f.id for f in findings if f.id is not None]
        decisions: defaultdict[UUID, list[Decision]] = defaultdict(list)
        for decision in uow.decisions.list_for_findings(ids, until=as_of):
            decisions[decision.finding_id].append(decision)
        occurrences = uow.occurrences.list_for_findings(ids)
        assessments = uow.assessments.list_by_ids(
            {o.assessment_id for o in occurrences}
            | {d.assessment_id for ds in decisions.values() for d in ds if d.assessment_id}
        )
        at = {a.id: a.occurred_at for a in assessments}
        seen: defaultdict[UUID, list[Occurrence]] = defaultdict(list)
        for occurrence in sorted(occurrences, key=lambda o: at[o.assessment_id]):
            if as_of is None or at[occurrence.assessment_id] <= as_of:
                seen[occurrence.finding_id].append(occurrence)
        latest_ids = [ocs[-1].id for ocs in seen.values() if ocs[-1].id]
        places: defaultdict[UUID, list[Location]] = defaultdict(list)
        for location in uow.locations.list_for_occurrences(latest_ids) if latest_ids else ():
            places[location.occurrence_id].append(location)
        links = uow.finding_cwes.list_for_findings(ids)
        names = {c.id: c.identifier for c in uow.cwes.list_by_ids({fc.cwe_id for fc in links})}
        cwes: defaultdict[UUID, list[str]] = defaultdict(list)
        for link in links:
            cwes[link.finding_id].append(names[link.cwe_id])
        tags: defaultdict[UUID, list[FindingLabel]] = defaultdict(list)
        for label in uow.finding_labels.list_for_findings(ids):
            tags[label.finding_id].append(label)
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
                    locations=tuple(places[latest.id]) if latest and latest.id else (),
                    cwes=tuple(sorted(cwes[finding.id])),
                    labels=tuple(tags[finding.id]),
                )
            )
        return views, decisions
