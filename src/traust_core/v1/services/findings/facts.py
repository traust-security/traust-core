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
from traust_core.v1.models.inventory import RepositoryRef, default_line
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.portfolio import Inventory


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
    lines: Mapping[UUID, bool]

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
            lines=_lines(
                [d for ds in decisions.values() for d in ds],
                {a.id: a for a in assessments if a.id},
                {
                    b.id: b
                    for b in AssessmentLog(uow).list_by_ids(
                        {a.baseline_assessment_id for a in assessments if a.baseline_assessment_id}
                    )
                },
                Inventory(uow).list_refs_of({f.repository_id for f in findings}),
            ),
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
        return Disposition.fold(finding_id, said, self.lines) if said else None


def _lines(
    decisions: Sequence[Decision],
    assessments: Mapping[UUID, Assessment],
    baselines: Mapping[UUID, Assessment],
    refs: Sequence[RepositoryRef],
) -> dict[UUID, bool]:
    """Decision id -> judged on the default line or another named one (data model §3b): a
    comparison's on its baseline's, an assessment's on its own, a person's on the commit they
    named. A bare commit off the default line ties a decision to no line; until a repository's
    default branch is observed its lines can't be told apart, so none of its refs splits them."""
    observed = {r.repository_id for r in refs if r.is_default}
    refs = [r for r in refs if r.repository_id in observed]
    on, named = default_line(refs), {r.id for r in refs if r.name is not None}
    lines: dict[UUID, bool] = {}
    for d in decisions:
        judged = assessments[d.assessment_id] if d.assessment_id else None
        if judged is not None and judged.baseline_assessment_id is not None:
            judged = baselines[judged.baseline_assessment_id]
        ref = judged.repository_ref_id if judged is not None else d.repository_ref_id
        if d.id is not None and ref is not None and (ref in on or ref in named):
            lines[d.id] = ref in on
    return lines
