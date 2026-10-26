from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import ConfigError, ForbiddenError, ValidationError
from traust_core.v1.models.artifacts import (
    ValidationArtifact,
    ValidationAuthorizationArtifact,
    ValidationPlanArtifact,
)
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import FindingView
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.validation import (
    TargetAttestation,
    TargetObservation,
    ValidationAttempt,
    ValidationDimension,
    ValidationFilter,
    ValidationInput,
    ValidationRecordingEvidence,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationRollup,
    ValidationScope,
)
from traust_core.v1.models.vocabulary import (
    AssessmentKind,
    ScopeBindingMode,
    ValidationApprovalMode,
)
from traust_core.v1.providers.clock import Clock
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
        *,
        findings: FindingService | None = None,
        assessment: AssessmentService | None = None,
        publisher: ArtifactPublisher | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._uow = uow
        self._decisions = decisions
        self._findings = findings
        self._assessment = assessment
        self._publisher = publisher
        self._clock = clock

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

    def authorize(
        self,
        plan_id: UUID,
        scope: ValidationScope,
        principal: Principal,
        *,
        confirmed: bool,
        mode: ValidationApprovalMode,
        skip_step_ids: Sequence[str] = (),
        permit_destructive: bool = False,
    ) -> ArtifactRef:
        if self._publisher is None or self._clock is None:
            raise ConfigError("validation authorization needs an artifact publisher and clock")
        scope = ValidationScope.model_validate_json(scope.model_dump_json())
        principal = Principal.model_validate_json(principal.model_dump_json())
        try:
            mode = ValidationApprovalMode(mode)
        except (ValueError, TypeError) as e:
            raise ValidationError(f"invalid validation approval mode: {mode!r}") from e
        if confirmed is not True:
            raise ForbiddenError("validation plan was not approved")
        if mode == ValidationApprovalMode.DRY_RUN:
            raise ForbiddenError("dry-run cannot authorize execution")
        if principal.verified_by is None or (
            mode == ValidationApprovalMode.INTERACTIVE and not principal.is_verified_human()
        ):
            raise ForbiddenError("validation approval requires a verified caller")
        modes = frozenset(
            {ScopeBindingMode.EXPLICIT, ScopeBindingMode.INLINE, ScopeBindingMode.INFERRED}
        )
        if not scope.modes or not scope.modes <= modes:
            raise ForbiddenError("validation execution requires a bound scope")
        now = self._clock.now()
        if scope.expires is not None and now.date() > scope.expires:
            raise ForbiddenError(f"validation engagement expired {scope.expires}")
        if mode == ValidationApprovalMode.AUTO and (
            ScopeBindingMode.EXPLICIT not in scope.modes or scope.environment != "lab"
        ):
            raise ForbiddenError("automatic validation requires an explicit lab engagement")
        plan = self.get_plan(plan_id)
        binding = next(iter(scope.modes)).value if len(scope.modes) == 1 else "mixed"
        if plan.scope_binding_mode != binding:
            raise ValidationError(f"validation plan {plan_id} is not bound to {binding} scope")
        step_ids = {step.id for step in plan.steps}
        if len(set(skip_step_ids)) != len(skip_step_ids) or set(skip_step_ids) - step_ids:
            raise ValidationError("validation approval names duplicate or unknown steps")
        scope_doc = scope.model_dump(mode="json")
        scope_doc["modes"] = sorted(scope_doc["modes"])
        for cluster in scope_doc["clusters"]:
            cluster["explicit_namespaces"] = sorted(cluster["explicit_namespaces"])
            cluster["verbs_denied"] = sorted(cluster["verbs_denied"])
        for browser in scope_doc["browser"]:
            browser["allowed_verbs"] = sorted(browser["allowed_verbs"])
        for name in (
            "wasm_artifact_ids",
            "credential_probe_classes",
            "inventory_aws_profiles",
            "inventory_cluster_contexts",
        ):
            scope_doc[name] = sorted(scope_doc[name])
        doc = ValidationAuthorizationArtifact.from_document(
            {
                "artifact": "validation-authorization",
                "plan_id": str(plan_id),
                "plan_digest": sha256_hex(plan.payload),
                "approved_by": principal.ref,
                "approved_at": now.isoformat(),
                "mode": mode.value,
                "scope": scope_doc,
                "skip_step_ids": sorted(skip_step_ids),
                "permit_destructive": permit_destructive,
            }
        )
        return self._publisher.publish_ref(doc)

    def get_authorization(self, authorization_id: UUID) -> ValidationAuthorizationArtifact:
        if self._publisher is None:
            raise ConfigError("validation authorization reads need an artifact publisher")
        return self._publisher.read(authorization_id, ValidationAuthorizationArtifact)

    def attest_target(self, plan_id: UUID, observed: TargetObservation) -> TargetAttestation:
        plan = self.get_plan(plan_id)
        if observed.target != plan.target:
            raise ValidationError(f"target observation does not match validation plan {plan_id}")
        if not any(check.required for check in observed.checks):
            raise ValidationError("target attestation needs a required check")
        if len({check.name for check in observed.checks}) != len(observed.checks):
            raise ValidationError("target attestation has duplicate checks")
        return TargetAttestation.model_validate(
            {
                "artifact": "target-attestation",
                "plan_id": plan_id,
                "plan_digest": sha256_hex(plan.payload),
                "attested": all(check.ok for check in observed.checks if check.required),
                "generated_at": observed.observed_at.isoformat(),
                "harness_version": observed.harness_version,
                "fingerprint": observed.fingerprint.model_dump(exclude_none=True),
                "checks": [check.model_dump() for check in observed.checks],
            }
        )

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
