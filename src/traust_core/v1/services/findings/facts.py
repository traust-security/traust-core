from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    Finding,
    FindingLabel,
    Occurrence,
    report_sources,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import TraustUnitOfWork


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """What a set of findings' views fold from, loaded with one query per table."""

    decisions: Mapping[UUID, Sequence[Decision]]
    reported: Mapping[UUID, Sequence[Occurrence]]
    at: Mapping[UUID, datetime]
    assessors: Mapping[UUID, str]
    sources: Mapping[UUID, SourceType]
    cwes: Mapping[UUID, Sequence[str]]
    labels: Mapping[UUID, Sequence[FindingLabel]]

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
        assessments = uow.assessments.list_by_ids(
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
            sources=report_sources(assessments),
            cwes=cwes,
            labels=labels,
        )

    def reported_by(self, finding_id: UUID, as_of: datetime | None) -> list[Occurrence]:
        """The finding's occurrences in assessment order, those assessed after `as_of` left out."""
        return [
            o
            for o in self.reported.get(finding_id, ())
            if as_of is None or self.at[o.assessment_id] <= as_of
        ]

    def decided_by(self, finding_id: UUID, as_of: datetime | None) -> list[Decision]:
        return [
            d for d in self.decisions.get(finding_id, ()) if as_of is None or d.occurred_at <= as_of
        ]

    def disposition(self, finding_id: UUID, as_of: datetime | None) -> Disposition | None:
        said = self.decided_by(finding_id, as_of)
        return Disposition.fold(finding_id, said, self.sources) if said else None

    def changed(self, finding_id: UUID, after: datetime, until: datetime) -> list[Decision] | None:
        """The decisions made in (after, until], or None when nothing about the finding moved."""
        said = [d for d in self.decisions.get(finding_id, ()) if after < d.occurred_at <= until]
        seen = any(
            after < self.at[o.assessment_id] <= until for o in self.reported.get(finding_id, ())
        )
        return said if said or seen else None
