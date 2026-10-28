from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    IntegrityError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    ReportArtifact,
    ThreatModelArtifact,
    TriageArtifact,
    ValidationArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import (
    AssessedJudgment,
    Decision,
    DecisionApprover,
    Disposition,
    Finding,
    FindingContext,
    FindingExternalRef,
    Location,
    RecordDecision,
    Restatement,
    ReviewItem,
    StatementKey,
    TriageInput,
    TriageItem,
    normalize_decision,
    statement_key,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.validation import (
    ValidationAttempt,
    ValidationFilter,
    ValidationFindingOutcome,
    ValidationFindingResult,
    ValidationRecordingEvidence,
    ValidationRecordInput,
    ValidationRecordResult,
    ValidationSourceBinding,
)
from traust_core.v1.models.vocabulary import (
    ActorKind,
    DispositionResolution,
    EvidenceGrade,
    FindingKind,
    ReviewReason,
    SourceType,
    ValidationVerdict,
    Validity,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import AssessmentLog, record_artifact, stored_bytes
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.findings.restatement import RestatementPolicy
from traust_core.v1.services.findings.review import ReviewPolicy, request
from traust_core.v1.services.insight import TriageView
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint, LintContext, LintReport
from traust_core.v1.services.portfolio import Inventory
from traust_core.v1.services.validation import (
    VALIDATION_RECORDING,
    VALIDATION_SYSTEM,
    ValidationRecords,
    validation_link,
)

if TYPE_CHECKING:
    from traust_core.v1.services.operations import OpsService


log = logging.getLogger(__name__)

_CLASSIFIERS = {
    "validity": "validity",
    "resolution": "disposition_resolution",
    "evidence_grade": "evidence_grade",
    "reason": "decision_reason",
    "severity": "severity",
    "source_channel": "source_channel",
}
TRIAGE = AssessmentKind.TRIAGE
_VALIDITY = {
    "true_positive": Validity.CONFIRMED,
    "hardening": Validity.CONFIRMED,
    "false_positive": Validity.FALSE_POSITIVE,
}
# NEED(hardening-weight): legacy recorded the category-aware risk weight (lambda) on each hardening
# verdict; decision has no column for it, so it is not stored (rating reads it from config).

PRECEDENTS_PER_FINDING = 3


class FindingDecisions:
    """Decisions are the only writes to a finding's state; every read is a view over them."""

    def __init__(
        self,
        uow: TraustUnitOfWork,
        ledger: LedgerService | None,
        lint: Lint,
        precedents: FindingPrecedents,
        *,
        clock: Clock,
        objects: ObjectStore,
        review: ReviewPolicy,
        restatement: RestatementPolicy | None = None,
        validation_records: ValidationRecords | None = None,
        recording: OpsService | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._records = FindingRecords(uow)
        self._ledger = ledger
        self._lint = lint
        self._precedents = precedents
        self._clock = clock
        self._objects = objects
        self._review = review
        self._restatement = restatement or RestatementPolicy()
        self._recording = recording
        self._validation_records = validation_records or ValidationRecords(
            uow, objects, findings=self._records
        )

    def decide(self, command: RecordDecision, principal: Principal) -> Decision:
        """A person's statement, if they may make it; a retried statement is the same decision."""
        command = RecordDecision.model_validate(dict(command))
        principal = Principal.model_validate(dict(principal))
        self._validate_classifiers(command)
        with self._uow.write() as uow:
            finding = uow.findings.get_for_update(command.finding_id)
            self._check_refs(
                finding.repository_id, command.repository_ref_id, command.fixed_repository_ref_id
            )
            now = self._clock.now()
            draft = Decision(
                **command.model_dump(exclude={"occurred_at"}),
                actor=principal.ref,
                occurred_at=command.occurred_at or now,
                statement_key="pending",
            )
            draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
            Disposition.admit([], draft, principal, now)
            history = uow.decisions.list_for_finding(finding.id)
            if self._ledger is not None:
                self._ledger.require_intact(finding.repository_id)
            same = self._same(draft, history)
            if same is not None:
                return normalize_decision(same)
            Disposition.admit(self._admission_history(draft, history), draft, principal, now)
            saved = uow.decisions.add_statement(draft)
            if self._ledger is not None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
        log.info("decision %s on finding %s by %s", saved.id, finding.id, principal.ref)
        return normalize_decision(saved)

    @staticmethod
    def _validate_classifiers(command: RecordDecision | Restatement | Decision) -> None:
        for field, name in _CLASSIFIERS.items():
            if (value := getattr(command, field, None)) is not None:
                contracts.validate_enum(name, value)

    def _check_refs(self, repository_id: UUID, *refs: UUID | None) -> None:
        for ref_id in refs:
            if ref_id is not None:
                ref = self._inventory.get_ref(ref_id)
                if ref.repository_id != repository_id:
                    raise ValidationError(f"commit {ref.id} is not in finding's repository")

    def _same(self, draft: Decision, history: Sequence[Decision] | None = None) -> Decision | None:
        known = self._uow.decisions.find_by_statement(draft.finding_id, draft.statement_key)
        if known is not None:
            return known
        if history is None:
            history = self._uow.decisions.list_for_finding(draft.finding_id)
        return next(
            (row for row in history if self.statement_key(row) == draft.statement_key), None
        )

    def _admission_history(self, draft: Decision, history: list[Decision]) -> list[Decision]:
        if draft.resolution is None:
            return history
        line = self._line(draft)
        lines = {row.id: self._line(row) for row in history if row.resolution is not None}
        scoped = any(row.resolution is not None and lines[row.id] == line for row in history)
        target = line if scoped else None
        return [
            row
            if row.resolution is None or lines[row.id] == target
            else row.model_copy(update={"resolution": None})
            for row in history
        ]

    def _line(self, decision: Decision) -> str | None:
        ref_id = decision.repository_ref_id
        if decision.assessment_id is not None:
            ref_id = self._log.get(decision.assessment_id).repository_ref_id
        return None if ref_id is None else self._inventory.get_ref(ref_id).name

    def get(self, decision_id: UUID) -> Decision:
        with self._uow as uow:
            return normalize_decision(uow.decisions.get(decision_id))

    def list_for_finding(self, finding_id: UUID) -> list[Decision]:
        with self._uow as uow:
            uow.findings.get(finding_id)
            return [normalize_decision(row) for row in uow.decisions.list_for_finding(finding_id)]

    def for_repository(self, repository_id: UUID) -> list[Decision]:
        """Every decision on the repository's findings, restated ones included, judgement order."""
        with self._uow as uow:
            findings = self._records.ids_for_repository(repository_id)
            return (
                [normalize_decision(row) for row in uow.decisions.list_for_findings(findings)]
                if findings
                else []
            )

    def require_signable(self) -> None:
        """Refuse up front, writing nothing, when the ledger must sign and can't."""
        if self._ledger is not None:
            self._ledger.require_signable()

    def statement_key(self, decision: Decision) -> StatementKey:
        return statement_key(decision)

    def restate(self, restatement: Restatement, principal: Principal) -> Decision:
        """An administrator's correction: a new decision that replaces the one it restates."""
        restatement = Restatement.model_validate(dict(restatement))
        principal = Principal.model_validate(dict(principal))
        self._validate_classifiers(restatement)
        contracts.validate_enum("restatement_reason", restatement.reason)
        restatement.validate_authority()
        approvers = self._restatement.authorize(restatement, principal)
        with self._uow.write() as uow:
            original = uow.decisions.get(restatement.decision_id)
            finding = uow.findings.get_for_update(original.finding_id)
            restated = normalize_decision(original)
            history = uow.decisions.list_for_finding(restated.finding_id)
            commit = restated.repository_ref_id
            if restated.assessment_id is not None:
                commit = self._log.get(restated.assessment_id).repository_ref_id
            draft = restated.model_copy(
                update={
                    **restatement.changes(),
                    "id": None,
                    "created_at": None,
                    "assessment_id": None,
                    "repository_ref_id": commit,
                    "restates_id": restated.id,
                    "auto_accept_tier": False,
                    "actor": principal.ref,
                    "reason": restatement.reason,
                    "ticket": restatement.ticket.strip(),
                    "rationale": restatement.rationale,
                    "occurred_at": self._clock.now(),
                }
            )
            draft = Decision.model_validate(dict(draft))
            self._validate_classifiers(draft)
            self._check_refs(finding.repository_id, commit, draft.fixed_repository_ref_id)
            draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
            same = self._same(draft, history)
            if same is not None:
                return normalize_decision(same)
            draft = restatement.correct(
                restated,
                [normalize_decision(row) for row in history],
                principal,
                draft.occurred_at,
                commit,
            )
            if self._ledger is not None:
                self._ledger.require_intact(finding.repository_id)
            saved = uow.decisions.add_statement(draft)
            for approver in sorted(approvers):
                ref = f"{ActorKind.HUMAN}:{approver}"
                uow.decision_approvers.add(DecisionApprover(decision_id=saved.id, approver=ref))
            if self._ledger is not None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
        log.info("decision %s restated as %s by %s", restated.id, saved.id, principal.ref)
        return normalize_decision(saved)

    def prepare(self, assessment_id: UUID) -> TriageInput:
        """What a triage of one assessment judges: its findings as reported, where, precedents."""
        with self._uow as uow:
            assessment = self._log.get(assessment_id)
            subject = self._inventory.subject(assessment.repository_ref_id, assessment_id)
            occurrences = uow.occurrences.list_for_assessment(assessment_id)
            findings = {
                f.id: f for f in uow.findings.list_by_ids({o.finding_id for o in occurrences})
            }
            where: dict[UUID, list[Location]] = defaultdict(list)
            for loc in uow.locations.list_for_occurrences([o.id for o in occurrences]):
                where[loc.occurrence_id].append(loc)
        precedents = self._precedents.for_findings(
            {o.finding_id: where[o.id] for o in occurrences}, PRECEDENTS_PER_FINDING
        )
        return TriageInput(
            subject=subject,
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            assessor=assessment.assessor,
            items=tuple(
                TriageItem(
                    finding=findings[o.finding_id],
                    occurrence=o,
                    locations=tuple(where[o.id]),
                    precedents=tuple(precedents.get(o.finding_id, ())),
                )
                for o in occurrences
            ),
        )

    def check(self, doc: TriageArtifact, checkout: Path) -> LintReport:
        """Lint the triage against the target checkout: after the votes, before `record`."""
        return self._lint.run(doc, LintContext(files=WorkspaceFiles(checkout)))

    def render(self, doc: TriageArtifact) -> bytes:
        """The triage as Markdown: a projection of the document, never a second source."""
        return MarkdownRenderer().render(TriageView().report(doc))

    def record(
        self, assessment_id: UUID, doc: TriageArtifact, provenance: Provenance, checkout: Path
    ) -> list[Decision]:
        """A triage of one assessment: a triage assessment with its document, then one decision
        per verdict (review items where a person must look). Re-recording changes nothing."""
        doc = TriageArtifact.parse(doc.payload)
        lint_clean = {f.id for f in doc.findings} - {
            v.item for v in self.check(doc, checkout).violations
        }
        self.require_signable()
        with self._uow as uow:
            triaged = self._log.get(assessment_id)
            reported = uow.findings.list_by_ids(
                {o.finding_id for o in uow.occurrences.list_for_assessment(assessment_id)}
            )
            by_identity = {(f.fingerprint_algo, f.fingerprint): f for f in reported}
            verdicts = [
                (v, by_identity.get((v.fingerprint_algo, v.fingerprint)))
                for v in doc.findings
                if v.verdict != "duplicate"
            ]
            unknown = sorted(v.id for v, f in verdicts if f is None)
            if unknown:
                listed = ", ".join(unknown)
                raise ValidationError(
                    f"triage findings assessment {assessment_id} didn't report: {listed}"
                )
            triage, artifact, new_triage = self._triage_assessment(uow, triaged, doc, provenance)
            if new_triage:
                for verdict, finding in verdicts:
                    if verdict.kind is not None:
                        uow.findings.update(
                            finding.model_copy(update={"kind": FindingKind(verdict.kind)})
                        )
            uow.commit()
        recorded = []
        for verdict, finding in verdicts:
            with self._uow.write() as uow:
                decision = self._record_verdict(
                    uow,
                    triage.id,
                    artifact.id,
                    finding,
                    verdict,
                    verdict.id in lint_clean,
                )
                uow.commit()
            if decision is not None:
                recorded.append(decision)
        if self._ledger is not None:
            for repository_id in sorted({f.repository_id for _, f in verdicts if f}, key=str):
                self._ledger.seal(repository_id)  # one signature for the whole triage
        log.info(
            "triage %s of assessment %s: %d decisions", triage.id, assessment_id, len(recorded)
        )
        return recorded

    def _triage_assessment(
        self,
        uow: TraustUnitOfWork,
        triaged: Assessment,
        doc: TriageArtifact,
        provenance: Provenance,
    ) -> tuple[Assessment, Artifact, bool]:
        digest = sha256_hex(doc.payload)
        if recorded := self._log.find_recorded(
            [triaged.repository_ref_id], TRIAGE, TRIAGE, digest, baseline_id=triaged.id
        ):
            return *recorded[0], False
        contracts.validate_json("triage#/$defs/canonical_write", doc.payload)
        triage = self._log.open(
            Assessment(
                repository_ref_id=triaged.repository_ref_id,
                image_id=triaged.image_id,
                baseline_assessment_id=triaged.id,
                kind=TRIAGE,
                status=ASSESSMENT_COMPLETED,
                assessor=TRIAGE,
                assessor_version=str(doc.triage_context.harness_version),
                occurred_at=provenance.occurred_at,
            )
        )
        ref = self._objects.put(ObjectKey.parse(f"{TRIAGE}/{digest}.json"), doc.payload)
        artifact = record_artifact(
            uow, Artifact(assessment_id=triage.id, digest=ref.sha256, kind=TRIAGE, uri=str(ref.key))
        )
        return triage, artifact, True

    def _record_verdict(
        self,
        uow: TraustUnitOfWork,
        triage_id: UUID,
        artifact_id: UUID,
        finding: Finding,
        verdict: Any,
        lint_clean: bool,
    ) -> Decision | None:
        """A verdict as a decision, or a review item when nothing was proven (undetermined, or a
        confirmation static reasoning couldn't settle)."""
        if verdict.verdict == "undetermined" or verdict.verify_verdict == "needs_manual_test":
            reason = (
                ReviewReason.UNDETERMINED_FINDING
                if verdict.verdict == "undetermined"
                else ReviewReason.NEEDS_MANUAL_TEST
            )
            request(uow, finding.id, reason)
            return None
        validity = _VALIDITY[verdict.verdict]
        votes = verdict.vote_breakdown
        draft = Decision(
            finding_id=finding.id,
            assessment_id=triage_id,
            artifact_id=artifact_id,
            statement_key="pending",
            validity=validity,
            severity=(
                verdict.severity
                if verdict.verdict == "true_positive" and verdict.kind != FindingKind.WEAKNESS
                else None
            ),
            rationale=_rationale(verdict),
            auto_accept_tier=validity == Validity.FALSE_POSITIVE
            and self._review.auto_accepts(
                {k: getattr(votes, k) for k in ("true_positive", "hardening", "false_positive")}
                if votes
                else {},
                verdict.confidence,
                verdict.claimed_severity,
                lint_clean,
            ),
            occurred_at=self._clock.now(),
        )
        return self._state(uow, draft, finding.repository_id)[0]

    def record_assessed(
        self,
        assessment_id: UUID,
        artifact_id: UUID,
        judgments: Sequence[tuple[UUID, AssessedJudgment]],
    ) -> list[Decision]:
        """An assessor's own judgments on what it reported (finding id, judgment), one decision
        each, with a review item where it asks a person; its document is the evidence.
        Re-recording changes nothing and reopens no review."""
        self.require_signable()
        recorded, repositories = [], set()
        for finding_id, judgment in judgments:
            with self._uow as uow:
                if uow.occurrences.find(finding_id, assessment_id) is None:
                    raise ValidationError(
                        f"assessment {assessment_id} didn't report finding {finding_id}"
                    )
                finding = uow.findings.get(finding_id)
                draft = Decision(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    artifact_id=artifact_id,
                    statement_key="pending",
                    validity=judgment.validity,
                    severity=judgment.severity,
                    rationale=judgment.rationale,
                    occurred_at=self._clock.now(),
                )
                saved, new = self._state(uow, draft, finding.repository_id)
                if new and judgment.review is not None:
                    request(uow, finding_id, judgment.review, saved.id)
                uow.commit()
            recorded.append(saved)
            repositories.add(finding.repository_id)
        if self._ledger is not None:
            for repository_id in sorted(repositories, key=str):
                self._ledger.seal(repository_id)
        log.info("assessment %s: %d assessed decisions", assessment_id, len(recorded))
        return recorded

    def record_resolution(
        self,
        assessment_id: UUID,
        finding_ids: Sequence[UUID],
        resolution: DispositionResolution | None,
        reason: str,
        artifact_id: UUID | None = None,
        *,
        validity: Validity | None = None,
        fixed_repository_ref_id: UUID | None = None,
        rationales: Mapping[UUID, str] | None = None,
    ) -> list[Decision]:
        """An assessment's statement on where fixing its findings stands (a remediation step, a
        verification verdict), one decision each. Restating the same step changes nothing."""
        if validity is not None and resolution is not None:
            raise ValidationError("a statement is a validity or a resolution, never both")
        self.require_signable()
        recorded, repositories = [], set()
        for finding_id in finding_ids:
            with self._uow as uow:
                finding = uow.findings.get(finding_id)
                draft = Decision(
                    finding_id=finding_id,
                    assessment_id=assessment_id,
                    artifact_id=artifact_id,
                    statement_key="pending",
                    validity=validity,
                    resolution=resolution,
                    reason=reason,
                    fixed_repository_ref_id=fixed_repository_ref_id,
                    rationale=(rationales or {}).get(finding_id),
                    occurred_at=self._clock.now(),
                )
                recorded.append(self._state(uow, draft, finding.repository_id)[0])
                uow.commit()
            repositories.add(finding.repository_id)
        if self._ledger is not None:
            for repository_id in sorted(repositories, key=str):
                self._ledger.seal(repository_id)
        log.info("assessment %s: %s on %d findings", assessment_id, reason, len(recorded))
        return recorded

    def _state(
        self, uow: TraustUnitOfWork, draft: Decision, repository_id: UUID
    ) -> tuple[Decision, bool]:
        self._validate_classifiers(draft)
        draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
        if (same := self._same(draft)) is not None:
            return normalize_decision(same), False
        saved = uow.decisions.add_statement(draft)
        if (reason := self._review.needs_signoff(saved)) is not None:
            request(uow, saved.finding_id, reason, saved.id)
        if self._ledger is not None:
            self._ledger.append_decision(saved, repository_id, sign=False)
        return saved, True

    def record_validation_order(
        self,
        doc: ValidationArtifact,
        provenance: Provenance,
        bindings: ValidationRecordInput,
        run_order_id: UUID,
        principal: Principal,
    ) -> ValidationRecordResult:
        if self._recording is None:
            raise ConfigError("validation recording requires operations authorization")
        bindings = ValidationRecordInput.model_validate_json(bindings.model_dump_json())
        repositories = {
            self._inventory.get_ref(
                self._log.get(source.assessment_id).repository_ref_id
            ).repository_id
            for source in bindings.sources
        }
        if not repositories:
            raise ValidationError("validation recording requires a source assessment")
        if len(repositories) != 1:
            raise ForbiddenError("validation recording exceeds a single order's repository scope")
        (repository_id,) = repositories
        with self._recording.recording(
            run_order_id, principal, "validation", repository_id, provenance
        ):
            return self.record_validation(doc, provenance, bindings, run_order_id=run_order_id)

    def record_validation(
        self,
        doc: ValidationArtifact,
        provenance: Provenance,
        bindings: ValidationRecordInput,
        *,
        run_order_id: UUID | None = None,
    ) -> ValidationRecordResult:
        """Record one bound machine run atomically, including review-only evidence."""
        doc = ValidationArtifact.parse(doc.payload)
        provenance = Provenance.model_validate_json(provenance.model_dump_json())
        bindings = ValidationRecordInput.model_validate_json(bindings.model_dump_json())
        if provenance.source != SourceType.VALIDATION_REPORT:
            raise ValidationError("validation recording requires validation-report provenance")
        if provenance.occurred_at.tzinfo is None or provenance.occurred_at.utcoffset() is None:
            raise ValidationError("validation recording requires timezone-aware provenance")
        outcomes = bindings.outcomes(doc)
        if self._ledger is not None:
            self._ledger.require_signable()
        with self._uow.write() as uow:
            sources, findings = self._validation_bindings(uow, doc, bindings)
            for finding_id in sorted(findings, key=str):
                findings[finding_id] = uow.findings.get_for_update(finding_id)
            repositories = {
                self._inventory.get_ref(source.repository_ref_id).repository_id
                for _, source in sources
            }
            if self._ledger is not None:
                for repository_id in sorted(repositories, key=str):
                    self._ledger.require_intact(repository_id)
            if provenance.artifact is not None:
                published = self._log.get_artifact(provenance.artifact.id)
                if published.kind != ValidationArtifact.schema or published.digest != sha256_hex(
                    doc.payload
                ):
                    raise IntegrityError("validation provenance artifact does not match report")
            assessments, artifacts, evidence_ids, recorded, appended = [], [], [], [], set()
            for binding, source in sources:
                scoped = tuple(o for o in outcomes if o.source_report == binding.source_report)
                evidence = ValidationRecordingEvidence(
                    source_report=binding.source_report,
                    report_digest=sha256_hex(doc.payload),
                    provenance=provenance,
                    bindings=bindings,
                    findings=scoped,
                )
                assessment, artifact, companion = self._validation_assessment(
                    uow, source, doc, evidence, run_order_id
                )
                assessments.append(assessment.id)
                artifacts.append(artifact.id)
                evidence_ids.append(companion.id)
                for outcome in scoped:
                    finding = findings[outcome.finding_id]
                    decision, created = self._record_validation_outcome(
                        uow, finding, assessment, artifact, outcome
                    )
                    reasons = list(outcome.review_reasons)
                    if decision is not None:
                        if decision.validity == Validity.FALSE_POSITIVE:
                            reasons.append(ReviewReason.ANALYST_REVIEW)
                        if created:
                            appended.add(finding.repository_id)
                    reviews = tuple(
                        self._validation_review(uow, finding.id, reason, decision).id
                        for reason in reasons
                    )
                    link = validation_link(companion.id, finding.id)  # type: ignore[arg-type]
                    if not uow.finding_external_refs.list_for_ref(VALIDATION_SYSTEM, link):
                        uow.finding_external_refs.add(
                            FindingExternalRef(
                                finding_id=finding.id, system=VALIDATION_SYSTEM, ref=link
                            )
                        )
                    recorded.append(
                        ValidationFindingResult(
                            **outcome.model_dump(),
                            assessment_id=assessment.id,
                            artifact_id=artifact.id,
                            decision_id=decision.id if decision else None,
                            review_item_ids=reviews,
                        )
                    )
            if self._ledger is not None:
                for repository_id in sorted(appended, key=str):
                    self._ledger.seal(repository_id)
            uow.commit()
        log.info(
            "validation run %s: %d assessments, %d outcomes",
            provenance.run_id,
            len(assessments),
            len(recorded),
        )
        return ValidationRecordResult(
            assessment_ids=tuple(assessments),
            artifact_ids=tuple(artifacts),
            evidence_artifact_ids=tuple(evidence_ids),
            findings=tuple(recorded),
        )

    def _validation_bindings(
        self,
        uow: TraustUnitOfWork,
        doc: ValidationArtifact,
        bindings: ValidationRecordInput,
    ) -> tuple[list[tuple[ValidationSourceBinding, Assessment]], dict[UUID, Finding]]:
        reports = {source.path: source for source in doc.source_reports}
        if len(reports) != len(doc.source_reports):
            raise ValidationError("validation source report references must be unique")
        supplied = {source.source_report: source for source in bindings.sources}
        if len(supplied) != len(bindings.sources) or supplied.keys() != reports.keys():
            raise ValidationError("validation bindings must cover every source report exactly once")
        rows = [(row.source_report, row.source_id) for row in doc.validated_findings]
        bound = [
            (source.source_report, finding.source_id)
            for source in bindings.sources
            for finding in source.findings
        ]
        if len(set(rows)) != len(rows) or len(set(bound)) != len(bound) or set(rows) != set(bound):
            raise ValidationError("validation bindings must cover every finding exactly once")
        sources, findings = [], {}
        for binding in bindings.sources:
            source = self._log.get(binding.assessment_id)
            artifact = self._log.get_artifact(binding.artifact_id)
            if artifact.assessment_id != source.id:
                raise ValidationError("validation source artifact is not owned by its assessment")
            report = reports[binding.source_report]
            if report.sha256 is not None and artifact.digest != report.sha256:
                raise IntegrityError(
                    "validation source report digest does not match stored artifact"
                )
            parser = {
                "security-audit": ReportArtifact,
                "triage": TriageArtifact,
                "threat-model": ThreatModelArtifact,
            }[report.kind]
            if artifact.kind not in {parser.schema, report.kind}:
                raise ValidationError(
                    "validation source report kind does not match stored artifact"
                )
            document = parser.parse(stored_bytes(self._objects, artifact))
            labels = document.threats if report.kind == "threat-model" else document.findings
            by_label = {row.id: row for row in labels}
            if len(by_label) != len(labels):
                raise ValidationError("validation source artifact has ambiguous finding labels")
            membership = {
                occurrence.finding_id
                for occurrence in uow.occurrences.list_for_assessment(source.id)
            }
            if source.baseline_assessment_id is not None:
                baseline = self._log.get(source.baseline_assessment_id)
                if baseline.repository_ref_id != source.repository_ref_id:
                    raise ValidationError(
                        "validation source baseline uses a different repository ref"
                    )
                membership.update(
                    occurrence.finding_id
                    for occurrence in uow.occurrences.list_for_assessment(baseline.id)
                )
            repository_id = self._inventory.get_ref(source.repository_ref_id).repository_id
            for binding_finding in binding.findings:
                finding = uow.findings.get(binding_finding.finding_id)
                if finding.id not in membership or finding.repository_id != repository_id:
                    raise ValidationError("validation finding is outside its source assessment")
                if binding_finding.source_id not in by_label:
                    raise ValidationError("validation finding label is absent from source artifact")
                reported = by_label[binding_finding.source_id]
                if report.kind != "threat-model" and (
                    (
                        reported.fingerprint is not None
                        and reported.fingerprint != finding.fingerprint
                    )
                    or (
                        reported.fingerprint_algo is not None
                        and reported.fingerprint_algo != finding.fingerprint_algo
                    )
                ):
                    raise ValidationError("validation finding fingerprint disagrees with source")
                findings[finding.id] = finding
            sources.append((binding, source))
        return sources, findings

    def _validation_assessment(
        self,
        uow: TraustUnitOfWork,
        source: Assessment,
        doc: ValidationArtifact,
        evidence: ValidationRecordingEvidence,
        run_order_id: UUID | None = None,
    ) -> tuple[Assessment, Artifact, Artifact]:
        raw = evidence.model_dump_json().encode()
        digest = sha256_hex(raw)
        known = self._log.find_recorded(
            [source.repository_ref_id],
            AssessmentKind.VALIDATION,
            VALIDATION_RECORDING,
            digest,
            baseline_id=source.id,
        )
        if known:
            assessment, companion = known[0]
            if run_order_id is not None and assessment.run_order_id != run_order_id:
                raise ConflictError("validation replay belongs to a different or unbound run order")
            artifact = next(
                (
                    row
                    for _, row in self._log.documents([assessment], [ValidationArtifact.schema])
                    if row.digest == sha256_hex(doc.payload)
                ),
                None,
            )
            if artifact is None or artifact.kind != ValidationArtifact.schema:
                raise IntegrityError("validation replay is missing its retained report artifact")
            for retained in (artifact, companion):
                stored_bytes(self._objects, retained)
            return assessment, artifact, companion
        assessment = self._log.open(
            Assessment(
                repository_ref_id=source.repository_ref_id,
                image_id=source.image_id,
                baseline_assessment_id=source.id,
                run_order_id=run_order_id,
                kind=AssessmentKind.VALIDATION,
                status=ASSESSMENT_COMPLETED,
                assessor="validate-findings",
                assessor_version=doc.metadata.harness_version,
                occurred_at=evidence.provenance.occurred_at,
            )
        )
        report_ref = self._objects.put(
            ObjectKey.parse(f"artifacts/validation/{sha256_hex(doc.payload)}.json"), doc.payload
        )
        artifact = record_artifact(
            uow,
            Artifact(
                assessment_id=assessment.id,
                digest=report_ref.sha256,
                kind=ValidationArtifact.schema,
                uri=str(report_ref.key),
            ),
        )
        evidence_ref = self._objects.put(
            ObjectKey.parse(f"artifacts/validation-recording/{digest}.json"), raw
        )
        companion = record_artifact(
            uow,
            Artifact(
                assessment_id=assessment.id,
                digest=evidence_ref.sha256,
                kind=VALIDATION_RECORDING,
                uri=str(evidence_ref.key),
            ),
        )
        return assessment, artifact, companion

    def _record_validation_outcome(
        self,
        uow: TraustUnitOfWork,
        finding: Finding,
        assessment: Assessment,
        artifact: Artifact,
        outcome: ValidationFindingOutcome,
    ) -> tuple[Decision | None, bool]:
        if (
            outcome.soundness_flag
            or outcome.verdict not in (ValidationVerdict.CONFIRMED, ValidationVerdict.REFUTED)
            or any(reason != ReviewReason.SEVERITY_PROPOSAL for reason in outcome.review_reasons)
        ):
            return None, False
        draft = Decision(
            finding_id=finding.id,
            assessment_id=assessment.id,
            artifact_id=artifact.id,
            statement_key="pending",
            validity=(
                Validity.CONFIRMED
                if outcome.verdict == ValidationVerdict.CONFIRMED
                else Validity.FALSE_POSITIVE
            ),
            evidence_grade=outcome.evidence_grade,
            rationale=outcome.rationale,
            occurred_at=assessment.occurred_at,
        )
        return self._run_statement(uow, draft, finding.repository_id)

    def _run_statement(
        self, uow: TraustUnitOfWork, draft: Decision, repository_id: UUID
    ) -> tuple[Decision, bool]:
        """An assessment-bound statement, appended unsigned; the same statement again is kept."""
        self._validate_classifiers(draft)
        draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
        if (
            same := self._same(draft, uow.decisions.list_for_finding(draft.finding_id))
        ) is not None:
            return normalize_decision(same), False
        saved = uow.decisions.add_statement(draft)
        if self._ledger is not None:
            self._ledger.append_decision(saved, repository_id, sign=False)
        return saved, True

    def record_reproduced(
        self, assessment: Assessment, artifact_id: UUID, reproducers: Mapping[UUID, str | None]
    ) -> list[Decision]:
        """An execution run's confirmations (finding id -> the kept reproducing input's digest):
        validity confirmed at E0 on each finding with a reproducer, none without one."""
        assert assessment.id is not None
        kept = {f: digest for f, digest in reproducers.items() if digest}
        if not kept:
            return []
        self.require_signable()
        recorded, appended = [], set()
        with self._uow.write() as uow:
            findings = {f: uow.findings.get_for_update(f) for f in sorted(kept, key=str)}
            for finding_id in findings:
                if uow.occurrences.find(finding_id, assessment.id) is None:
                    raise ValidationError(
                        f"assessment {assessment.id} didn't report finding {finding_id}"
                    )
            if self._ledger is not None:
                for repository_id in sorted({f.repository_id for f in findings.values()}, key=str):
                    self._ledger.require_intact(repository_id)
            for finding_id, finding in findings.items():
                digest = kept[finding_id]
                decision, created = self._run_statement(
                    uow,
                    Decision(
                        finding_id=finding_id,
                        assessment_id=assessment.id,
                        artifact_id=artifact_id,
                        statement_key="pending",
                        validity=Validity.CONFIRMED,
                        evidence_grade=EvidenceGrade("E0"),
                        rationale=f"reproduced by a kept input (sha256 {digest})",
                        occurred_at=assessment.occurred_at,
                    ),
                    finding.repository_id,
                )
                recorded.append(decision)
                if created:
                    appended.add(finding.repository_id)
            if self._ledger is not None:
                for repository_id in sorted(appended, key=str):
                    self._ledger.seal(repository_id)
            uow.commit()
        log.info("assessment %s: %d reproduced findings", assessment.id, len(recorded))
        return recorded

    @staticmethod
    def _validation_review(
        uow: TraustUnitOfWork,
        finding_id: UUID,
        reason: ReviewReason,
        decision: Decision | None,
    ) -> ReviewItem:
        decision_id = decision.id if decision else None
        known = next(
            (
                item
                for item in uow.review_items.list_for_finding(finding_id)
                if item.reason == reason and item.decision_id == decision_id
            ),
            None,
        )
        return known or request(uow, finding_id, reason, decision_id)

    def validation_evidence(
        self, artifact_id: UUID, *, finding_id: UUID | None = None
    ) -> ValidationRecordingEvidence:
        return self._validation_records.evidence(artifact_id, finding_id=finding_id)

    def validation_attempts(self, filter: ValidationFilter) -> list[ValidationAttempt]:
        return self._validation_records.attempts(filter)


def _rationale(verdict: Any) -> str:
    """The verifiers' rationale, then why the verdict maps to this validity."""
    why = {
        "true_positive": (
            "(triage: weakness, exclusion rule 13: an accurate gap with no concrete exploit path)"
            if verdict.kind == FindingKind.WEAKNESS
            else ""
        ),
        "hardening": "(triage: hardening, exclusion rule 13: an accurate gap with no "
        "concrete exploit path)",
        "false_positive": "(triage: refuted: "
        f"{', '.join(verdict.refute_reasons) or 'see rationale'}; "
        f"exclusion rule {verdict.exclusion_rule or 'none'})",
    }[verdict.verdict]
    return " ".join(p for p in ((verdict.rationale or "").strip(), why) if p)
