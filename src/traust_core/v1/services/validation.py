from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import ValidationError as ModelValidationError

from traust_core.v1.errors import (
    ConfigError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    ValidationArtifact,
    ValidationAuthorizationArtifact,
    ValidationPlanArtifact,
)
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.findings import Decision, FindingView, normalize_decision
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.validation import (
    TargetAttestation,
    TargetObservation,
    ValidationAttempt,
    ValidationDimension,
    ValidationFilter,
    ValidationInput,
    ValidationPrecedentCheck,
    ValidationRecordingEvidence,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationRollup,
    ValidationScope,
)
from traust_core.v1.models.vocabulary import (
    AssessmentKind,
    ScopeBindingMode,
    SourceType,
    ValidationApprovalMode,
    ValidationVerdict,
    Validity,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectStore
from traust_core.v1.services.artifact_publishing import AssessmentLog, stored_bytes

if TYPE_CHECKING:
    from traust_core.v1.services.artifact_publishing import ArtifactPublisher
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.findings.decisions import FindingDecisions
    from traust_core.v1.services.findings.records import FindingRecords
    from traust_core.v1.services.findings.service import FindingService

log = logging.getLogger(__name__)
VALIDATION_SYSTEM = "traust.validation"
VALIDATION_RECORDING = "validation-recording"
_EVIDENCE_ERRORS = (IntegrityError, NotFoundError, ValidationError, ModelValidationError)


def validation_link(companion_id: UUID, finding_id: UUID) -> str:
    return f"traust:artifact:{companion_id}#finding={finding_id}"


def _companion_id(link: str) -> UUID:
    try:
        return UUID(link.removeprefix("traust:artifact:").split("#finding=", 1)[0])
    except ValueError as e:
        raise IntegrityError(f"malformed validation reference {link!r}") from e


@dataclass(frozen=True)
class _ValidationMetadata:
    assessments: Mapping[UUID, Assessment]
    sources: Mapping[UUID, Assessment]
    reports: Mapping[tuple[UUID, str], Artifact]


class ValidationRecords:
    """Recorded validation evidence reads, independent of the services that write decisions."""

    def __init__(
        self, uow: TraustUnitOfWork, objects: ObjectStore, *, findings: FindingRecords
    ) -> None:
        self._objects = objects
        self._log = AssessmentLog(uow)
        self._findings = findings

    def _parse(self, artifact: Artifact) -> ValidationRecordingEvidence:
        if artifact.kind != VALIDATION_RECORDING:
            raise ValidationError("artifact is not validation recording evidence")
        return ValidationRecordingEvidence.model_validate_json(
            stored_bytes(self._objects, artifact)
        )

    def _metadata(
        self, parsed: Mapping[UUID, tuple[Artifact, ValidationRecordingEvidence]]
    ) -> _ValidationMetadata:
        assessments = {
            a.id: a
            for a in self._log.list_at(
                {
                    artifact.assessment_id: evidence.provenance.occurred_at
                    for artifact, evidence in parsed.values()
                    if artifact.assessment_id is not None
                }
            )
        }
        sources = self._log.list_by_ids(
            {a.baseline_assessment_id for a in assessments.values() if a.baseline_assessment_id}
        )
        return _ValidationMetadata(
            assessments,
            {a.id: a for a in sources},
            {
                (a.id, row.digest): row
                for a, row in self._log.documents(assessments.values(), [ValidationArtifact.schema])
            },
        )

    def _verify(
        self,
        artifact: Artifact,
        evidence: ValidationRecordingEvidence,
        metadata: _ValidationMetadata,
        documents: dict[UUID, ValidationArtifact],
    ) -> tuple[Assessment, Artifact, ValidationRecordingEvidence]:
        sources = [
            s for s in evidence.bindings.sources if s.source_report == evidence.source_report
        ]
        if len(sources) != 1:
            raise IntegrityError("validation evidence has no unambiguous source binding")
        if artifact.assessment_id is None:
            raise IntegrityError("validation evidence has no machine assessment provenance")
        assessment = metadata.assessments.get(artifact.assessment_id)
        if assessment is None:
            raise IntegrityError("validation evidence disagrees with its assessment timestamp")
        source = metadata.sources.get(sources[0].assessment_id)
        if (
            source is None
            or assessment.kind != AssessmentKind.VALIDATION
            or assessment.baseline_assessment_id != source.id
            or assessment.repository_ref_id != source.repository_ref_id
            or evidence.provenance.source != SourceType.VALIDATION_REPORT
        ):
            raise IntegrityError("validation evidence disagrees with its assessment provenance")
        report = metadata.reports.get((assessment.id, evidence.report_digest))
        if report is None:
            raise IntegrityError("validation evidence has no matching retained report")
        expected = {(row.source_id, row.finding_id) for row in sources[0].findings}
        actual = {(row.source_id, row.finding_id) for row in evidence.findings}
        if (
            expected != actual
            or len(expected) != len(sources[0].findings)
            or len(actual) != len(evidence.findings)
            or any(row.source_report != evidence.source_report for row in evidence.findings)
        ):
            raise IntegrityError("validation evidence does not match its finding bindings")
        if report.id not in documents:
            documents[report.id] = ValidationArtifact.parse(stored_bytes(self._objects, report))
        outcomes = tuple(
            o
            for o in evidence.bindings.outcomes(documents[report.id])
            if o.source_report == evidence.source_report
        )
        if outcomes != evidence.findings:
            raise IntegrityError("validation evidence disagrees with the retained report outcomes")
        return assessment, report, evidence

    def _read_many(
        self, artifact_ids: Collection[UUID]
    ) -> dict[UUID, tuple[Assessment, Artifact, ValidationRecordingEvidence]]:
        artifacts = self._log.list_artifacts_by_ids(artifact_ids)
        if missing := set(artifact_ids) - {a.id for a in artifacts}:
            raise NotFoundError(f"validation evidence artifacts {sorted(map(str, missing))}")
        parsed = {a.id: (a, self._parse(a)) for a in artifacts}
        metadata = self._metadata(parsed)
        documents: dict[UUID, ValidationArtifact] = {}
        return {key: self._verify(a, e, metadata, documents) for key, (a, e) in parsed.items()}

    def evidence(
        self, artifact_id: UUID, *, finding_id: UUID | None = None
    ) -> ValidationRecordingEvidence:
        _, _, evidence = self._read_many([artifact_id])[artifact_id]
        if finding_id is not None:
            if finding_id not in {row.finding_id for row in evidence.findings}:
                raise ValidationError("validation evidence is for a different finding")
            leads = self._findings.external_refs([finding_id], VALIDATION_SYSTEM)
            if not any(lead.ref == validation_link(artifact_id, finding_id) for lead in leads):
                raise IntegrityError("validation evidence has no matching finding reference")
        return evidence

    def attempts(self, filter: ValidationFilter) -> list[ValidationAttempt]:
        if filter.finding_id is not None:
            self._findings.get(filter.finding_id)
            refs = self._findings.external_refs([filter.finding_id], VALIDATION_SYSTEM)
            companions = {_companion_id(r.ref) for r in refs}
        else:
            runs = self._log.list_of(AssessmentKind.VALIDATION)
            companions = {row.id for _, row in self._log.documents(runs, [VALIDATION_RECORDING])}
        recorded = self._read_many(companions)
        wanted = {
            o.finding_id
            for a, _, e in recorded.values()
            for o in e.findings
            if filter.finding_id in (None, o.finding_id)
            and (filter.as_of is None or a.occurred_at <= filter.as_of)
        }
        if not wanted:
            return []
        links = {
            (r.finding_id, r.ref): r.id
            for r in self._findings.external_refs(wanted, VALIDATION_SYSTEM)
        }
        decisions: dict[tuple[UUID, UUID | None], UUID] = {}
        for d in self._findings.decisions(wanted):
            decisions.setdefault((d.finding_id, d.assessment_id), d.id)
        repositories = {f.id: f.repository_id for f in self._findings.list_by_ids(wanted)}
        attempts = []
        for companion, (assessment, report, evidence) in recorded.items():
            if filter.as_of is not None and assessment.occurred_at > filter.as_of:
                continue
            for outcome in evidence.findings:
                if outcome.finding_id not in wanted:
                    continue
                link = (outcome.finding_id, validation_link(companion, outcome.finding_id))
                if link not in links:
                    raise IntegrityError(
                        f"validation evidence {companion} has no reference for finding "
                        f"{outcome.finding_id}"
                    )
                attempts.append(
                    ValidationAttempt(
                        **outcome.model_dump(),
                        attempt_id=links[link],
                        repository_id=repositories[outcome.finding_id],
                        assessment_id=assessment.id,
                        artifact_id=report.id,
                        evidence_artifact_id=companion,
                        run_id=evidence.provenance.run_id,
                        occurred_at=assessment.occurred_at,
                        decision_id=decisions.get((outcome.finding_id, assessment.id)),
                    )
                )
        return sorted(
            (
                a
                for a in attempts
                if (filter.repository_ids is None or a.repository_id in filter.repository_ids)
                and filter.verdict in (None, a.verdict)
            ),
            key=lambda a: (a.occurred_at, a.attempt_id),
            reverse=True,
        )

    def check_refutations(
        self, decisions: Sequence[Decision]
    ) -> tuple[ValidationPrecedentCheck, ...]:
        """Verify each decision's own refutation; unavailable evidence is an explicit exclusion."""
        if not decisions:
            return ()
        if len(decisions) > 500:
            return tuple(
                check
                for start in range(0, len(decisions), 500)
                for check in self.check_refutations(decisions[start : start + 500])
            )
        assessments = self._log.list_by_ids({d.assessment_id for d in decisions if d.assessment_id})
        companions: dict[UUID, list[Artifact]] = defaultdict(list)
        for assessment, artifact in self._log.documents(assessments, [VALIDATION_RECORDING]):
            companions[assessment.id].append(artifact)
        parsed, failures = {}, {}
        for rows in companions.values():
            if len(rows) != 1:
                continue
            artifact = rows[0]
            try:
                parsed[artifact.id] = (artifact, self._parse(artifact))
            except _EVIDENCE_ERRORS as e:
                failures[artifact.id] = type(e).__name__
        metadata = self._metadata(parsed)
        documents: dict[UUID, ValidationArtifact] = {}
        verified = {}
        for key, (artifact, evidence) in parsed.items():
            try:
                verified[key] = self._verify(artifact, evidence, metadata, documents)
            except _EVIDENCE_ERRORS as e:
                failures[key] = type(e).__name__
        links = {
            (r.finding_id, r.ref)
            for r in self._findings.external_refs(
                {d.finding_id for d in decisions}, VALIDATION_SYSTEM
            )
        }
        checks = []
        for raw in decisions:
            decision = normalize_decision(raw)
            rows = companions.get(decision.assessment_id, ())
            reason = "missing-or-ambiguous-recording"
            if len(rows) == 1:
                artifact = rows[0]
                if artifact.id in failures:
                    reason = f"unverifiable-evidence:{failures[artifact.id]}"
                else:
                    assessment, report, evidence = verified[artifact.id]
                    outcomes = [o for o in evidence.findings if o.finding_id == decision.finding_id]
                    sound = [
                        o
                        for o in outcomes
                        if o.verdict == ValidationVerdict.REFUTED and not o.soundness_flag
                    ]
                    if (
                        not outcomes
                        or (decision.finding_id, validation_link(artifact.id, decision.finding_id))
                        not in links
                    ):
                        reason = "finding-binding-mismatch"
                    elif not sound:
                        reason = "not-a-sound-refutation"
                    elif (
                        decision.actor is not None
                        or decision.artifact_id != report.id
                        or decision.validity != Validity.FALSE_POSITIVE
                        or not any(
                            decision.evidence_grade == o.evidence_grade
                            and decision.rationale == o.rationale
                            for o in sound
                        )
                        or decision.occurred_at != assessment.occurred_at
                    ):
                        reason = "decision-evidence-mismatch"
                    else:
                        reason = None
            checks.append(ValidationPrecedentCheck(decision_id=decision.id, reason=reason))
            if reason:
                log.warning(
                    "validation precedent excluded: decision=%s reason=%s", decision.id, reason
                )
        return tuple(checks)


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
        """The finding's recorded validation attempts, newest first."""
        return self._decisions.validation_attempts(ValidationFilter(finding_id=finding_id))

    def list(self, filter: ValidationFilter, page: PageRequest) -> Page[ValidationAttempt]:
        after = page.position()
        rows = [
            a
            for a in self._decisions.validation_attempts(filter)
            if after is None or (a.occurred_at, a.attempt_id) < after
        ]
        return Page.of(rows[: page.limit + 1], page.limit, lambda a: (a.occurred_at, a.attempt_id))

    def summary(
        self, filter: ValidationFilter, group_by: ValidationDimension
    ) -> list[ValidationRollup]:
        """Each validated finding counted once, by its latest verdict as of `as_of`, per group,
        largest first; the filter's verdict keeps findings whose latest verdict it is."""
        latest: dict[UUID, ValidationAttempt] = {}
        for a in self._decisions.validation_attempts(filter.model_copy(update={"verdict": None})):
            latest.setdefault(a.finding_id, a)
        groups: defaultdict[str | None, Counter[ValidationVerdict]] = defaultdict(Counter)
        for a in latest.values():
            if filter.verdict in (None, a.verdict):
                key = {
                    ValidationDimension.REPOSITORY: str(a.repository_id),
                    ValidationDimension.VERDICT: a.verdict,
                    ValidationDimension.EVIDENCE_GRADE: a.evidence_grade,
                }[ValidationDimension(group_by)]
                groups[key][a.verdict] += 1
        return sorted(
            (
                ValidationRollup(key=key, findings=sum(counts.values()), by_verdict=dict(counts))
                for key, counts in groups.items()
            ),
            key=lambda r: (-r.findings, r.key is None, r.key or ""),
        )
