from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConflictError, ForbiddenError, IntegrityError, ValidationError
from traust_core.v1.models.artifacts import (
    FindingClaimArtifact,
    FindingIntakeArtifact,
    ReportArtifact,
)
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.finding_claims import ClaimBase, ClaimLocation, FindingClaim
from traust_core.v1.models.findings import (
    RATIONALE_MIN_LENGTH,
    Decision,
    Finding,
    FindingCandidate,
    Label,
    ReviewItem,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import Fingerprint, sha256_hex
from traust_core.v1.models.vocabulary import DecisionReason, ReviewItemStatus, ReviewReason
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    stored_bytes,
)
from traust_core.v1.services.portfolio import Inventory

if TYPE_CHECKING:
    from traust_core.v1.services.findings.decisions import FindingDecisions
    from traust_core.v1.services.findings.intake import FindingIntake


@dataclass(frozen=True, slots=True)
class ApprovedClaim:
    decision: Decision
    document: FindingClaimArtifact
    base: ClaimBase
    claim: FindingClaim


def claim_value(document: FindingClaimArtifact) -> FindingClaim:
    value = document.claim
    return FindingClaim(
        title=value.title,
        description=value.description,
        fingerprint_algo=value.fingerprint_algo,
        fingerprint=value.fingerprint,
        cwes=tuple(value.cwes),
        category=value.category,
        locations=tuple(
            ClaimLocation(
                path=location.path,
                line_start=location.line_start,
                line_end=location.line_end,
                symbol=location.symbol,
            )
            for location in value.locations
        ),
    )


def claim_base(document: FindingClaimArtifact) -> ClaimBase:
    return ClaimBase(
        fingerprint_algo=document.base.fingerprint_algo,
        fingerprint=document.base.fingerprint,
        title=document.base.title,
        claim_decision_id=(
            UUID(document.base.claim_decision_id) if document.base.claim_decision_id else None
        ),
        occurrence_ids=tuple(UUID(value) for value in document.base.occurrence_ids),
    )


def retained_claim_artifact(uow: TraustUnitOfWork, decision: Decision) -> Artifact | None:
    if decision.reason != DecisionReason.BASELINE_REWRITE or decision.artifact_id is None:
        return None
    row = AssessmentLog(uow).get_artifact(decision.artifact_id)
    return row if row.kind == FindingClaimArtifact.schema else None


def approved_claims(
    uow: TraustUnitOfWork, objects: ObjectStore, finding: Finding
) -> list[ApprovedClaim]:
    assert finding.id is not None
    history = {decision.id: decision for decision in uow.decisions.list_for_finding(finding.id)}
    artifact_ids = {
        decision.artifact_id
        for decision in history.values()
        if decision.reason == DecisionReason.BASELINE_REWRITE and decision.artifact_id is not None
    }
    artifacts = {
        row.id: row
        for row in (AssessmentLog(uow).list_artifacts_by_ids(artifact_ids) if artifact_ids else ())
    }
    return _accepted_claims(
        uow, objects, finding, history, artifacts, uow.review_items.list_for_finding(finding.id)
    )


def _accepted_claims(
    uow: TraustUnitOfWork,
    objects: ObjectStore,
    finding: Finding,
    history: Mapping[UUID, Decision],
    artifacts: Mapping[UUID, Artifact],
    review_items: Sequence[ReviewItem],
) -> list[ApprovedClaim]:
    assert finding.id is not None
    claims: dict[UUID | None, ApprovedClaim] = {}
    for item in review_items:
        if (
            item.reason != ReviewReason.REBASELINE_MAPPING
            or item.status != ReviewItemStatus.ACCEPTED
            or item.decision_id is None
            or item.resolved_by_decision_id is None
        ):
            continue
        proposal = history.get(item.decision_id)
        decision = history.get(item.resolved_by_decision_id)
        row = _retained_claim_artifact(artifacts, proposal)
        if row is None:
            continue
        assert proposal is not None
        if (
            decision is None
            or decision.reason != DecisionReason.BASELINE_REWRITE
            or decision.restates_id != proposal.id
            or decision.artifact_id != proposal.artifact_id
            or not (decision.actor or "").startswith("human:")
            or decision.artifact_id is None
            or any(
                getattr(decision, field) is not None
                for field in (
                    "assessment_id",
                    "validity",
                    "severity",
                    "resolution",
                    "evidence_grade",
                )
            )
        ):
            raise IntegrityError(f"claim review {item.id} has an invalid acceptance")
        assert decision is not None
        document = FindingClaimArtifact.parse(stored_bytes(objects, row))
        if (
            UUID(document.finding_id) != finding.id
            or UUID(document.repository_id) != finding.repository_id
        ):
            raise IntegrityError(f"claim review {item.id} has another finding's document")
        base = claim_base(document)
        if base.claim_decision_id in claims:
            raise IntegrityError(f"finding {finding.id} has competing accepted claims")
        claims[base.claim_decision_id] = ApprovedClaim(
            decision, document, base, claim_value(document)
        )
    ordered: list[ApprovedClaim] = []
    previous = None
    while previous in claims:
        current = claims.pop(previous)
        ordered.append(current)
        previous = current.decision.id
    if claims:
        raise IntegrityError(f"finding {finding.id} has a broken claim history")
    return ordered


def _retained_claim_artifact(
    artifacts: Mapping[UUID, Artifact], decision: Decision | None
) -> Artifact | None:
    if decision is None or decision.reason != DecisionReason.BASELINE_REWRITE:
        return None
    if decision.artifact_id is None:
        return None
    row = artifacts.get(decision.artifact_id)
    return row if row is not None and row.kind == FindingClaimArtifact.schema else None


def approved_claims_for(
    uow: TraustUnitOfWork,
    objects: ObjectStore,
    findings: Sequence[Finding],
) -> dict[UUID, list[ApprovedClaim]]:
    """`approved_claims` for many findings: one query per table, not one loop per finding."""
    wanted = {f.id: f for f in findings if f.id is not None}
    if not wanted:
        return {}
    history = {decision.id: decision for decision in uow.decisions.list_for_findings(list(wanted))}
    artifact_ids = {
        decision.artifact_id
        for decision in history.values()
        if decision.reason == DecisionReason.BASELINE_REWRITE and decision.artifact_id is not None
    }
    artifacts = {
        row.id: row
        for row in (AssessmentLog(uow).list_artifacts_by_ids(artifact_ids) if artifact_ids else ())
    }
    items: dict[UUID, list[ReviewItem]] = defaultdict(list)
    for item in uow.review_items.list_for_findings(list(wanted)):
        items[item.finding_id].append(item)
    approved: dict[UUID, list[ApprovedClaim]] = {}
    for finding_id, finding in wanted.items():
        approved[finding_id] = _accepted_claims(
            uow, objects, finding, history, artifacts, items.get(finding_id, [])
        )
    return approved


class FindingClaims:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        objects: ObjectStore,
        publisher: ArtifactPublisher,
        intake: FindingIntake,
        decisions: FindingDecisions,
    ) -> None:
        self._uow = uow
        self._objects = objects
        self._publisher = publisher
        self._intake = intake
        self._decisions = decisions
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)

    @staticmethod
    def _authority(ticket: str, rationale: str, principal: Principal) -> None:
        if not principal.is_verified_human():
            raise ForbiddenError("a claim correction needs a verified human")
        if not ticket.strip():
            raise ValidationError("a claim correction names its authority: a ticket")
        if len(rationale.strip()) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")

    def claim(self, finding_id: UUID, as_of: datetime | None = None) -> FindingClaim | None:
        with self._uow as uow:
            claims = approved_claims(uow, self._objects, uow.findings.get(finding_id))
            kept = [
                claim for claim in claims if as_of is None or claim.decision.occurred_at <= as_of
            ]
            return kept[-1].claim if kept else None

    def request(
        self,
        finding_id: UUID,
        assessment_id: UUID,
        report: ReportArtifact,
        label: Label,
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
    ) -> ReviewItem:
        principal = Principal.model_validate(dict(principal))
        self._authority(ticket, rationale, principal)
        report = ReportArtifact.parse(report.payload)
        self._decisions.require_signable()
        with self._uow as uow:
            finding = uow.findings.get(finding_id)
            claim = self._reported_claim(finding, assessment_id, report, label)
            approved = approved_claims(uow, self._objects, finding)
            base = ClaimBase(
                fingerprint_algo=finding.fingerprint_algo,
                fingerprint=finding.fingerprint,
                title=finding.title,
                claim_decision_id=approved[-1].decision.id if approved else None,
                occurrence_ids=tuple(
                    sorted(
                        (row.id for row in uow.occurrences.list_for_finding(finding_id)),
                        key=str,
                    )
                ),
            )
            reviews = uow.review_items.list_for_finding(finding_id)
            for item in reviews:
                if item.reason != ReviewReason.REBASELINE_MAPPING or item.decision_id is None:
                    continue
                proposal = uow.decisions.get(item.decision_id)
                row = retained_claim_artifact(uow, proposal)
                if row is None:
                    continue
                assert proposal.artifact_id is not None
                retained = self._publisher.read(proposal.artifact_id, FindingClaimArtifact)
                if (
                    UUID(retained.finding_id) == finding_id
                    and UUID(retained.assessment_id) == assessment_id
                    and retained.label == label
                    and claim_value(retained) == claim
                    and proposal.ticket == ticket.strip()
                    and proposal.rationale == rationale.strip()
                    and proposal.actor == principal.ref
                    and (
                        (item.status == ReviewItemStatus.PENDING and claim_base(retained) == base)
                        or (
                            item.status == ReviewItemStatus.ACCEPTED
                            and item.resolved_by_decision_id == base.claim_decision_id
                        )
                    )
                ):
                    return item
            document = FindingClaimArtifact.from_document(
                {
                    "schema_version": "1.0",
                    "finding_id": str(finding_id),
                    "repository_id": str(finding.repository_id),
                    "assessment_id": str(assessment_id),
                    "label": str(label),
                    "base": base.model_dump(mode="json"),
                    "claim": claim.model_dump(mode="json"),
                }
            )
        staged = self._publisher.stage(document)
        with self._uow.write() as uow:
            locked = uow.findings.get_for_update(finding_id)
            reviews = uow.review_items.list_for_finding(finding_id)
            accepted_ids = {
                item.resolved_by_decision_id
                for item in reviews
                if item.status == ReviewItemStatus.ACCEPTED
                and item.decision_id is not None
                and retained_claim_artifact(uow, uow.decisions.get(item.decision_id)) is not None
            }
            if (
                locked.fingerprint_algo != base.fingerprint_algo
                or locked.fingerprint != base.fingerprint
                or locked.title != base.title
                or locked.repository_id != finding.repository_id
                or set(base.occurrence_ids)
                != {row.id for row in uow.occurrences.list_for_finding(finding_id)}
                or accepted_ids != {claim.decision.id for claim in approved}
            ):
                raise ConflictError("the base claim changed while preparing this correction")
            digest = sha256_hex(document.payload)
            for item in reviews:
                if (
                    item.reason != ReviewReason.REBASELINE_MAPPING
                    or item.status != ReviewItemStatus.PENDING
                    or item.decision_id is None
                ):
                    continue
                proposal = uow.decisions.get(item.decision_id)
                row = retained_claim_artifact(uow, proposal)
                if (
                    row is not None
                    and row.digest == digest
                    and proposal.ticket == ticket.strip()
                    and proposal.rationale == rationale.strip()
                    and proposal.actor == principal.ref
                ):
                    return item
            published = self._publisher.publish_staged(staged)
            proposal = self._decisions.append_claim(
                finding_id,
                published.artifact_id,
                principal,
                document=document,
                ticket=ticket,
                rationale=rationale,
            )
            for item in reviews:
                if (
                    item.reason == ReviewReason.REBASELINE_MAPPING
                    and item.status == ReviewItemStatus.PENDING
                    and item.decision_id is not None
                    and retained_claim_artifact(uow, uow.decisions.get(item.decision_id))
                    is not None
                ):
                    uow.review_items.update(
                        item.model_copy(update={"status": ReviewItemStatus.CLOSED_UNREVIEWED})
                    )
            saved = uow.review_items.add(
                ReviewItem(
                    finding_id=finding_id,
                    decision_id=proposal.id,
                    reason=ReviewReason.REBASELINE_MAPPING,
                    status=ReviewItemStatus.PENDING,
                )
            )
            uow.commit()
            return saved

    def _reported_claim(
        self, finding: Finding, assessment_id: UUID, report: ReportArtifact, label: Label
    ) -> FindingClaim:
        with self._uow as uow:
            occurrence = uow.occurrences.find(finding.id, assessment_id)
            if occurrence is None:
                raise ValidationError("the original assessment did not report this finding")
            assessment = self._log.get(assessment_id)
            ref, repository = self._inventory.resolve(assessment.repository_ref_id)
            if repository.id != finding.repository_id:
                raise ValidationError("the original assessment belongs to another repository")
            if report.metadata.repository != repository.url or report.metadata.commit != ref.sha:
                raise ValidationError(
                    "the corrected report must name the original repository and commit"
                )
            entries = [entry for entry in report.findings if entry.id == label]
            if len(entries) != 1:
                raise ValidationError("a corrected report must contain its label exactly once")
            originals = self._publisher.documents([assessment], ReportArtifact)
            if originals:
                for _, original_report in originals:
                    if (
                        original_report.metadata.repository != repository.url
                        or original_report.metadata.commit != ref.sha
                    ):
                        raise ValidationError(
                            "the original report must name the assessment repository and commit"
                        )
                original_entries = [
                    entry for _, doc in originals for entry in doc.findings if entry.id == label
                ]
                if len(original_entries) != 1:
                    raise ValidationError("the original report label does not bind this finding")
                original = FindingCandidate.of_report(original_entries, finding.repository_id)[0]
                original_id = self._intake.match(finding.repository_id, original)
            else:
                sources = self._publisher.documents([assessment], FindingIntakeArtifact)
                if not sources:
                    raise ValidationError(
                        "the original label needs a retained authoritative source"
                    )
                for _, source in sources:
                    if (
                        str(source.repository_id) != str(repository.id)
                        or str(source.repository_ref_id) != str(ref.id)
                        or source.repository != repository.url
                        or source.commit != ref.sha
                    ):
                        raise ValidationError(
                            "the original scanner binding must name "
                            "the assessment repository and commit"
                        )
                bindings = [
                    binding
                    for _, source in sources
                    for binding in source.bindings
                    if binding.label == label
                ]
                if len(bindings) != 1:
                    raise ValidationError("the original scanner label does not bind this finding")
                binding = bindings[0]
                original_id = self._intake.match(
                    finding.repository_id,
                    Fingerprint(binding.fingerprint_algo, binding.fingerprint),
                )
            if original_id != finding.id:
                raise ValidationError("the original source label does not bind this finding")
            entry = entries[0]
            candidate = FindingCandidate.of_report([entry], finding.repository_id)[0]
            fingerprint = self._intake.fingerprint(candidate)
            locations = []
            for location in entry.locations:
                lines = [int(value) for value in re.findall(r"\d+", location.lines or "")]
                locations.append(
                    ClaimLocation(
                        path=location.path,
                        line_start=lines[0] if lines else None,
                        line_end=lines[-1] if lines else None,
                    )
                )
            return FindingClaim(
                title=candidate.title,
                description=candidate.description,
                fingerprint_algo=fingerprint.algo,
                fingerprint=fingerprint.value,
                cwes=tuple(candidate.cwes),
                category=candidate.category,
                locations=tuple(locations),
            )

    def correct(
        self,
        review_item_id: UUID,
        *,
        ticket: str,
        rationale: str,
        principal: Principal,
        approvers: tuple[str, ...] = (),
    ) -> UUID:
        principal = Principal.model_validate(dict(principal))
        self._authority(ticket, rationale, principal)
        approved_by = self._decisions.authorize_claim(principal, approvers)
        self._decisions.require_signable()
        with self._uow.write() as uow:
            known = uow.review_items.get(review_item_id)
            finding = uow.findings.get_for_update(known.finding_id)
            item = uow.review_items.get_for_update(review_item_id)
            if item.reason != ReviewReason.REBASELINE_MAPPING or item.decision_id is None:
                raise ValidationError("this is not a retained claim correction review")
            proposal = uow.decisions.get(item.decision_id)
            if (
                proposal.finding_id != finding.id
                or proposal.reason != DecisionReason.BASELINE_REWRITE
                or proposal.artifact_id is None
                or proposal.restates_id is not None
            ):
                raise ValidationError("the review does not bind a claim correction proposal")
            if proposal.ticket != ticket.strip():
                raise ValidationError("the correction ticket must match the retained proposal")
            document = self._publisher.read(proposal.artifact_id, FindingClaimArtifact)
            if (
                UUID(document.finding_id) != finding.id
                or UUID(document.repository_id) != finding.repository_id
            ):
                raise ValidationError(
                    "the retained proposal belongs to another finding or repository"
                )
            assessment_id = UUID(document.assessment_id)
            if uow.occurrences.find(finding.id, assessment_id) is None:
                raise ValidationError("the retained assessment did not report this finding")
            assessment = self._log.get(assessment_id)
            _, repository = self._inventory.resolve(assessment.repository_ref_id)
            if repository.id != finding.repository_id:
                raise ValidationError("the retained assessment belongs to another repository")
            if item.status == ReviewItemStatus.ACCEPTED and item.resolved_by_decision_id:
                accepted = uow.decisions.get(item.resolved_by_decision_id)
                recorded = frozenset(
                    row.approver.removeprefix("human:")
                    for row in uow.decision_approvers.list_for_decision(accepted.id)
                )
                if (
                    accepted.restates_id == proposal.id
                    and accepted.artifact_id == proposal.artifact_id
                    and accepted.actor == principal.ref
                    and accepted.ticket == ticket.strip()
                    and accepted.rationale == rationale.strip()
                    and recorded == approved_by
                ):
                    return finding.id
                raise ConflictError("this correction has already been accepted")
            if item.status != ReviewItemStatus.PENDING:
                raise ConflictError("this correction review is already closed or superseded")
            approved = approved_claims(uow, self._objects, finding)
            base = claim_base(document)
            if (
                base.claim_decision_id != (approved[-1].decision.id if approved else None)
                or base.fingerprint_algo != finding.fingerprint_algo
                or base.fingerprint != finding.fingerprint
                or base.title != finding.title
                or set(base.occurrence_ids)
                != {row.id for row in uow.occurrences.list_for_finding(finding.id)}
            ):
                raise ConflictError("this correction proposal has a stale base claim")
            claim = claim_value(document)
            collision = self._intake.match(
                finding.repository_id, Fingerprint(claim.fingerprint_algo, claim.fingerprint)
            )
            if collision is not None and collision != finding.id:
                raise ConflictError("the corrected fingerprint already belongs to another finding")
            accepted = self._decisions.append_claim(
                finding.id,
                proposal.artifact_id,
                principal,
                document=document,
                ticket=ticket,
                rationale=rationale,
                restates_id=proposal.id,
                approvers=approved_by,
            )
            uow.findings.update(
                finding.model_copy(
                    update={
                        "title": claim.title,
                        "fingerprint_algo": claim.fingerprint_algo,
                        "fingerprint": claim.fingerprint,
                    }
                )
            )
            uow.review_items.update(
                item.model_copy(
                    update={
                        "status": ReviewItemStatus.ACCEPTED,
                        "resolved_by_decision_id": accepted.id,
                    }
                )
            )
            uow.commit()
            return finding.id
