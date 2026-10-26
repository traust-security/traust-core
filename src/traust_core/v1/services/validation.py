from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import ValidationArtifact, ValidationPlanArtifact
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import FindingView
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.validation import (
    Authorization,
    FindingChain,
    RefusalReason,
    TargetAttestation,
    TargetObservation,
    ValidationAttempt,
    ValidationDimension,
    ValidationFilter,
    ValidationInput,
    ValidationPlan,
    ValidationRecordingEvidence,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationRollup,
    ValidationRun,
    ValidationScope,
)
from traust_core.v1.models.vocabulary import AssessmentKind
from traust_core.v1.providers.validation import ValidationAdapter
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.service import FindingService


class ValidationService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        decisions: FindingDecisions,
        adapters: Sequence[ValidationAdapter],
        *,
        findings: FindingService | None = None,
        assessment: AssessmentService | None = None,
        publisher: ArtifactPublisher | None = None,
    ) -> None:
        self._uow = uow
        self._decisions = decisions
        self._adapters = adapters
        self._findings = findings
        self._assessment = assessment
        self._publisher = publisher

    def prepare(self, finding_id: UUID) -> ValidationInput:
        return self.prepare_many((finding_id,))[0]

    def prepare_many(self, finding_ids: Sequence[UUID]) -> tuple[ValidationInput, ...]:
        """Keep each source assessment and repository distinct in a multi-package run."""
        if self._findings is None or self._assessment is None or self._publisher is None:
            raise ConfigError("validation prepare needs finding, assessment and artifact reads")
        if not finding_ids or len(set(finding_ids)) != len(finding_ids):
            raise ValidationError("validation prepare needs distinct finding IDs")
        views = {view.finding.id: view for view in self._findings.list_by_ids(finding_ids)}
        by_source: dict[UUID, list[FindingView]] = {}
        for finding_id in finding_ids:
            view = views[finding_id]
            occurrence = view.occurrence
            if occurrence is None or occurrence.assessment_id is None:
                raise ValidationError(f"finding {finding_id} has no source assessment to validate")
            by_source.setdefault(occurrence.assessment_id, []).append(view)
        inputs = []
        for assessment_id, selected in by_source.items():
            assessment = self._assessment.get(assessment_id)
            prepared = self._assessment.prepare(
                assessment.repository_ref_id, AssessmentKind.VALIDATION
            )
            if any(v.finding.repository_id != prepared.subject.repository_id for v in selected):
                raise ValidationError(f"assessment {assessment_id} belongs to another repository")
            inputs.append(
                ValidationInput(
                    subject=prepared.subject.model_copy(update={"assessment_id": assessment_id}),
                    findings=prepared.findings,
                    prepared_at=prepared.prepared_at,
                    selected=tuple(selected),
                    source_artifacts=tuple(self._publisher.list_for_assessment(assessment_id)),
                    threat_model=prepared.threat_model,
                )
            )
        return tuple(inputs)

    def plan(self, doc: ValidationPlanArtifact) -> ArtifactRef:
        """Publish an immutable proposed plan; this does not authorize any step."""
        if self._publisher is None:
            raise ConfigError("validation plan needs an artifact publisher")
        step_ids = [step.id for step in doc.steps]
        chain_ids = [chain.chain_id for chain in doc.chains]
        if len(step_ids) != len(set(step_ids)) or len(chain_ids) != len(set(chain_ids)):
            raise ValidationError("validation plan has duplicate step or chain IDs")
        if unknown := {step.chain_ref for step in doc.steps if step.chain_ref} - set(chain_ids):
            raise ValidationError(f"validation plan refers to unknown chains: {sorted(unknown)}")
        preceding: set[str] = set()
        for step in doc.steps:
            required = step.preconditions or ()
            if set(required) - preceding:
                raise ValidationError(
                    f"validation plan step {step.id} has unresolved preconditions"
                )
            preceding.add(step.id)
        return self._publisher.publish_ref(doc)

    def chains(self, finding_ids: Sequence[UUID]) -> list[FindingChain]:
        raise NotImplementedError("stub: replaces validate-findings/chain.py")

    def authorize(
        self, plan_id: UUID, scope: ValidationScope, principal: Principal
    ) -> Authorization:
        raise NotImplementedError("stub: replaces validation/scope.build, approval mode")

    def attest_target(self, plan_id: UUID, observed: TargetObservation) -> TargetAttestation:
        raise NotImplementedError("stub: replaces attest_target.py")

    def execute(self, plan_id: UUID, authorization: Authorization) -> ValidationRun:
        raise NotImplementedError("stub: replaces validate-findings/execute.py, run.py")

    def record(
        self,
        doc: ValidationArtifact,
        provenance: Provenance,
        bindings: ValidationRecordInput,
    ) -> ValidationRecordResult:
        return self._decisions.record_validation(doc, provenance, bindings)

    def evidence(
        self, artifact_id: UUID, *, finding_id: UUID | None = None
    ) -> ValidationRecordingEvidence:
        return self._decisions.validation_evidence(artifact_id, finding_id=finding_id)

    def refuse(self, plan_id: UUID, reason: RefusalReason) -> ValidationPlan:
        raise NotImplementedError("stub: replaces validate-findings refusal records")

    def get_plan(self, plan_id: UUID) -> ValidationPlanArtifact:
        if self._publisher is None:
            raise ConfigError("validation plan reads need an artifact publisher")
        return self._publisher.read(plan_id, ValidationPlanArtifact)

    def attempts(self, finding_id: UUID) -> list[ValidationAttempt]:
        raise NotImplementedError("stub: replaces build_remediation_manifest.latest_validation")

    def list(self, filter: ValidationFilter, page: PageRequest) -> Page[ValidationAttempt]:
        raise NotImplementedError("stub: replaces validation_current")

    def summary(
        self, filter: ValidationFilter, group_by: ValidationDimension
    ) -> list[ValidationRollup]:
        raise NotImplementedError("stub: replaces validation_exposure, validation-fuzz dashboard")
