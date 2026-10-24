from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from uuid import UUID

from traust_core.v1.errors import IntegrityError, NotFoundError
from traust_core.v1.models.findings import (
    Finding,
    FindingExternalRef,
    FindingView,
    Location,
    ReviewItem,
    ReviewItemCase,
    normalize_decision,
    normalize_finding,
)
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.findings.facts import FindingFacts
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
        *,
        facts: FindingFacts | None = None,
    ) -> list[FindingView]:
        facts = facts if facts is not None else FindingFacts.load(uow, findings, until=as_of)
        return self._views(uow, findings, as_of, facts)

    def _views(
        self,
        uow: TraustUnitOfWork,
        findings: Sequence[Finding],
        as_of: datetime | None,
        facts: FindingFacts,
    ) -> list[FindingView]:
        latest_ids = [
            seen[-1].id
            for finding in findings
            if finding.id and (seen := facts.reported_by(finding.id, as_of)) and seen[-1].id
        ]
        places: defaultdict[UUID, list[Location]] = defaultdict(list)
        for location in uow.locations.list_for_occurrences(latest_ids) if latest_ids else ():
            places[location.occurrence_id].append(location)
        return [
            view
            for finding in findings
            if (view := self.view(facts, finding, as_of, places)) is not None
        ]

    def review_cases(
        self, uow: TraustUnitOfWork, items: Sequence[ReviewItem]
    ) -> list[ReviewItemCase]:
        if not items:
            return []
        findings = uow.findings.list_by_ids({item.finding_id for item in items})
        facts = FindingFacts.load(uow, findings, until=None)
        by_id = {view.finding.id: view for view in self._views(uow, findings, None, facts)}
        histories = {
            finding_id: tuple(normalize_decision(row) for row in rows)
            for finding_id, rows in facts.decisions.items()
        }
        leads: defaultdict[UUID, list[FindingExternalRef]] = defaultdict(list)
        for lead in uow.finding_external_refs.list_for_findings(
            {item.finding_id for item in items}
        ):
            leads[lead.finding_id].append(lead)
        log = AssessmentLog(uow)
        assessment_ids = {
            finding_id: {
                occurrence.assessment_id for occurrence in facts.reported.get(finding_id, ())
            }
            | {decision.assessment_id for decision in rows if decision.assessment_id}
            for finding_id, rows in (
                (finding.id, facts.decisions.get(finding.id, ())) for finding in findings
            )
        }
        evidence: defaultdict[UUID, set[UUID]] = defaultdict(set)
        for finding in findings:
            assert finding.id is not None
            evidence[finding.id].update(
                decision.artifact_id
                for decision in facts.decisions.get(finding.id, ())
                if decision.artifact_id is not None
            )
            for lead in leads[finding.id]:
                if lead.system != "traust.validation":
                    continue
                prefix, separator, target = lead.ref.partition("#finding=")
                try:
                    if (
                        separator != "#finding="
                        or target != str(finding.id)
                        or not prefix.startswith("traust:artifact:")
                    ):
                        raise ValueError("not a validation artifact reference")
                    artifact_id = UUID(prefix.removeprefix("traust:artifact:"))
                except ValueError as error:
                    raise IntegrityError(f"validation reference {lead.id} is invalid") from error
                evidence[finding.id].add(artifact_id)
        artifact_ids = set().union(*evidence.values())
        held = {artifact.id: artifact for artifact in log.list_artifacts_by_ids(artifact_ids)}
        if missing := artifact_ids - held.keys():
            raise NotFoundError(f"review evidence artifacts not found: {sorted(missing, key=str)}")
        for finding_id, ids in evidence.items():
            for artifact_id in ids:
                if (assessment_id := held[artifact_id].assessment_id) is not None:
                    assessment_ids[finding_id].add(assessment_id)
        requested = set().union(*assessment_ids.values())
        assessments = [
            facts.assessments[assessment_id]
            for assessment_id in requested
            if assessment_id in facts.assessments
        ]
        if missing := requested - facts.assessments.keys():
            assessments.extend(log.list_by_ids(missing))
        documents: defaultdict[UUID, set[UUID]] = defaultdict(set)
        for assessment, artifact in log.documents(assessments, None):
            assert assessment.id is not None and artifact.id is not None
            documents[assessment.id].add(artifact.id)
        for finding_id, ids in assessment_ids.items():
            for assessment_id in ids:
                evidence[finding_id].update(documents[assessment_id])
        return [
            ReviewItemCase(
                review_item=item,
                finding=by_id[item.finding_id],
                history=histories.get(item.finding_id, ()),
                external_refs=tuple(leads[item.finding_id]),
                evidence_artifact_ids=tuple(sorted(evidence[item.finding_id], key=str)),
            )
            for item in items
        ]

    def view(
        self,
        facts: FindingFacts,
        finding: Finding,
        as_of: datetime | None,
        places: Mapping[UUID, Sequence[Location]],
    ) -> FindingView | None:
        assert finding.id is not None
        reported = facts.reported_by(finding.id, as_of)
        if as_of is not None and not reported:
            return None
        finding = normalize_finding(finding, facts.decided_by(finding.id, as_of))
        latest = reported[-1] if reported else None
        disposition = facts.disposition(finding.id, as_of)
        severity = self._rating.effective_severity(latest, disposition)
        due = None
        if latest is not None and (disposition is None or disposition.is_open()):
            opened = facts.at[reported[0].assessment_id]
            due = self._rating.sla_due(severity, opened, latest.cvss_score)
        return FindingView(
            finding=finding,
            occurrence=latest,
            disposition=disposition,
            effective_severity=severity,
            sla_due=due,
            locations=tuple(places.get(latest.id, ())) if latest and latest.id else (),
            cwes=tuple(sorted(facts.cwes.get(finding.id, ()))),
            labels=tuple(facts.labels.get(finding.id, ())),
        )
