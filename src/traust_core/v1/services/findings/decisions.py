from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import (
    Decision,
    DecisionApprover,
    Disposition,
    Finding,
    FindingContext,
    Location,
    RecordDecision,
    Restatement,
    StatementKey,
    SubjectRef,
    TriageInput,
    TriageItem,
    normalize_decision,
    statement_key,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import ActorKind, FindingKind, ReviewReason, Validity
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import record_artifact
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.restatement import RestatementPolicy
from traust_core.v1.services.findings.review import ReviewPolicy, request
from traust_core.v1.services.insight import TriageView
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint, LintContext, LintReport

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
_RATIONALE_CAP = 500

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
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._lint = lint
        self._precedents = precedents
        self._clock = clock
        self._objects = objects
        self._review = review
        self._restatement = restatement or RestatementPolicy()

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
            same = self._same(draft, history)
            if same is not None:
                return normalize_decision(same)
            Disposition.admit(self._admission_history(draft, history), draft, principal, now)
            if self._ledger is not None:
                self._ledger.require_intact(finding.repository_id)
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
                ref = self._uow.repository_refs.get(ref_id)
                if ref.repository_id != repository_id:
                    raise ValidationError(f"commit {ref.id} is not in finding's repository")

    def _same(self, draft: Decision, history: Sequence[Decision]) -> Decision | None:
        return self._uow.decisions.find_by_statement(draft.finding_id, draft.statement_key) or next(
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
            ref_id = self._uow.assessments.get(decision.assessment_id).repository_ref_id
        return None if ref_id is None else self._uow.repository_refs.get(ref_id).name

    def get(self, decision_id: UUID) -> Decision:
        with self._uow as uow:
            return normalize_decision(uow.decisions.get(decision_id))

    def list_for_finding(self, finding_id: UUID) -> list[Decision]:
        with self._uow as uow:
            uow.findings.get(finding_id)
            return [normalize_decision(row) for row in uow.decisions.list_for_finding(finding_id)]

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
                commit = uow.assessments.get(restated.assessment_id).repository_ref_id
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
            assessment = uow.assessments.get(assessment_id)
            ref = uow.repository_refs.get(assessment.repository_ref_id)
            repository = uow.repositories.get(ref.repository_id)
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
            subject=SubjectRef(
                repository_id=repository.id,
                repository_url=repository.url,
                repository_ref_id=ref.id,
                sha=ref.sha,
                assessment_id=assessment_id,
            ),
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
        lint_clean = {f.id for f in doc.findings} - {
            v.item for v in self.check(doc, checkout).violations
        }
        if self._ledger is not None:
            self._ledger.require_signable()
        with self._uow as uow:
            triaged = uow.assessments.get(assessment_id)
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
            triage, artifact = self._triage_assessment(uow, triaged, doc, provenance)
            uow.commit()
        recorded = []
        for verdict, finding in verdicts:
            with self._uow.write() as uow:
                decision = self._record_verdict(
                    uow, triage.id, artifact.id, finding, verdict, verdict.id in lint_clean
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
    ) -> tuple[Assessment, Artifact]:
        digest = sha256_hex(doc.payload)
        for earlier in uow.assessments.list_for_ref(triaged.repository_ref_id):
            if (
                earlier.kind == TRIAGE
                and earlier.baseline_assessment_id == triaged.id
                and (known := uow.artifacts.find(earlier.id, digest)) is not None
            ):
                return earlier, known
        triage = uow.assessments.add(
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
        return triage, artifact

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
        if verdict.verdict == "hardening":
            uow.findings.update(finding.model_copy(update={"kind": FindingKind.WEAKNESS}))
        votes = verdict.vote_breakdown
        draft = Decision(
            finding_id=finding.id,
            assessment_id=triage_id,
            artifact_id=artifact_id,
            statement_key="pending",
            validity=validity,
            severity=verdict.severity if verdict.verdict == "true_positive" else None,
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
        self._validate_classifiers(draft)
        key = self.statement_key(draft)
        if (same := uow.decisions.find_by_statement(finding.id, key)) is not None:
            return same
        saved = uow.decisions.add_statement(draft.model_copy(update={"statement_key": key}))
        if (reason := self._review.needs_signoff(saved)) is not None:
            request(uow, finding.id, reason, saved.id)
        if self._ledger is not None:
            self._ledger.append_decision(saved, finding.repository_id, sign=False)
        return saved


def _rationale(verdict: Any) -> str:
    """The verifiers' rationale, then why the verdict maps to this validity."""
    why = {
        "true_positive": "",
        "hardening": "(triage: hardening, exclusion rule 13: an accurate gap with no "
        "concrete exploit path)",
        "false_positive": "(triage: refuted: "
        f"{', '.join(verdict.refute_reasons) or 'see rationale'}; "
        f"exclusion rule {verdict.exclusion_rule or 'none'})",
    }[verdict.verdict]
    text = " ".join(p for p in ((verdict.rationale or "").strip(), why) if p)
    return text[:_RATIONALE_CAP]
