from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingLabel,
    Occurrence,
)
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """What a set of findings' views fold from, loaded with one query per table."""

    decisions: Mapping[UUID, Sequence[Decision]]
    reported: Mapping[UUID, Sequence[Occurrence]]
    at: Mapping[UUID, datetime]
    assessors: Mapping[UUID, str]
    cwes: Mapping[UUID, Sequence[str]]
    labels: Mapping[UUID, Sequence[FindingLabel]]
    assessments: Mapping[UUID, Assessment]

    @classmethod
    def load(
        cls, uow: TraustUnitOfWork, findings: Sequence[Finding], until: datetime | None
    ) -> FindingFacts:
        """Decisions made after `until` are left out; every occurrence is kept."""
        ids = [f.id for f in findings if f.id is not None]
        decisions: defaultdict[UUID, list[Decision]] = defaultdict(list)
        for d in uow.decisions.list_for_findings(ids, until=until):
            decisions[d.finding_id].append(d)
        occurrences = uow.occurrences.list_for_findings(ids)
        assessments = AssessmentLog(uow).list_by_ids(
            {o.assessment_id for o in occurrences}
            | {d.assessment_id for ds in decisions.values() for d in ds if d.assessment_id}
        )
        at = {a.id: a.occurred_at for a in assessments if a.id}
        reported: defaultdict[UUID, list[Occurrence]] = defaultdict(list)
        for o in sorted(occurrences, key=lambda o: at[o.assessment_id]):
            reported[o.finding_id].append(o)
        links = uow.finding_cwes.list_for_findings(ids) if ids else []
        names = {c.id: c.identifier for c in uow.cwes.list_by_ids({fc.cwe_id for fc in links})}
        cwes: defaultdict[UUID, list[str]] = defaultdict(list)
        for fc in links:
            cwes[fc.finding_id].append(names[fc.cwe_id])
        labels: defaultdict[UUID, list[FindingLabel]] = defaultdict(list)
        for fl in uow.finding_labels.list_for_findings(ids) if ids else ():
            labels[fl.finding_id].append(fl)
        return cls(
            decisions=decisions,
            reported=reported,
            at=at,
            assessors={a.id: a.assessor for a in assessments if a.id},
            cwes=cwes,
            labels=labels,
            assessments={a.id: a for a in assessments if a.id is not None},
        )

    def reported_by(self, finding_id: UUID, as_of: datetime | None) -> list[Occurrence]:
        """The finding's occurrences in assessment order, those assessed after `as_of` left out."""
        return [
            o
            for o in self.reported.get(finding_id, ())
            if as_of is None or self.at[o.assessment_id] <= as_of
        ]

    def off_line(self, finding_id: UUID, line: Collection[UUID]) -> bool:
        """Reported, but never on `line`'s refs: a branch re-audit's finding only."""
        seen = self.reported.get(finding_id, ())
        return bool(seen) and all(
            self.assessments[o.assessment_id].repository_ref_id not in line for o in seen
        )

    def decided_by(self, finding_id: UUID, as_of: datetime | None) -> list[Decision]:
        return [
            d for d in self.decisions.get(finding_id, ()) if as_of is None or d.occurred_at <= as_of
        ]

    def disposition(self, finding_id: UUID, as_of: datetime | None) -> Disposition | None:
        said = self.decided_by(finding_id, as_of)
        return Disposition.fold(finding_id, said) if said else None
