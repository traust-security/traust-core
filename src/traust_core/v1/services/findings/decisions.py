from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

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
    ReviewItem,
    StatementKey,
    SubjectRef,
    TriageInput,
    TriageItem,
    report_sources,
    statement_key,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import ActorKind, ReviewReason, SourceType, Validity
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

TRIAGE = AssessmentKind.TRIAGE
_VALIDITY = {
    "true_positive": Validity.CONFIRMED,
    "hardening": Validity.HARDENING,
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
        with self._uow as uow:
            finding = uow.findings.get(command.finding_id)
            if command.repository_ref_id is not None:
                judged = uow.repository_refs.get(command.repository_ref_id)
                if judged.repository_id != finding.repository_id:
                    raise ValidationError(
                        f"commit {judged.id} is not in finding {finding.id}'s repository"
                    )
            now = self._clock.now()
            draft = Decision(
                **command.model_dump(exclude={"occurred_at"}),
                actor=principal.ref,
                occurred_at=command.occurred_at or now,
                statement_key="pending",
            )
            draft = draft.model_copy(update={"statement_key": self.statement_key(draft)})
            same = uow.decisions.find_by_statement(finding.id, draft.statement_key)
            if same is not None:
                return same
            history = uow.decisions.list_for_finding(finding.id)
            Disposition.admit(history, draft, principal, now, self._sources(history))
            saved = uow.decisions.add(draft)
            if self._ledger is not None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
        log.info("decision %s on finding %s by %s", saved.id, finding.id, principal.ref)
        return saved

    def _sources(self, history: Sequence[Decision]) -> dict[UUID, SourceType]:
        ids = {d.assessment_id for d in history if d.assessment_id}
        return report_sources(self._uow.assessments.list_by_ids(ids))

    def statement_key(self, decision: Decision) -> StatementKey:
        return statement_key(decision)

    def restate(self, restatement: Restatement, principal: Principal) -> Decision:
        """An administrator's correction: a new decision that replaces the one it restates."""
        approvers = self._restatement.authorize(restatement, principal)
        with self._uow as uow:
            restated = uow.decisions.get(restatement.decision_id)
            commit = restated.repository_ref_id
            if restated.assessment_id is not None:
                commit = uow.assessments.get(restated.assessment_id).repository_ref_id
            history = uow.decisions.list_for_finding(restated.finding_id)
            correction = restatement.correct(
                restated, history, principal, self._clock.now(), commit
            )
            saved = uow.decisions.add(correction)
            for approver in sorted(approvers):
                ref = f"{ActorKind.HUMAN}:{approver}"
                uow.decision_approvers.add(DecisionApprover(decision_id=saved.id, approver=ref))
            if self._ledger is not None:
                repository_id = uow.findings.get(saved.finding_id).repository_id
                self._ledger.append_decision(saved, repository_id)
            uow.commit()
        log.info("decision %s restated as %s by %s", restated.id, saved.id, principal.ref)
        return saved

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
            with self._uow as uow:
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
        votes = verdict.vote_breakdown
        draft = Decision(
            finding_id=finding.id,
            assessment_id=triage_id,
            artifact_id=artifact_id,
            statement_key="pending",
            validity=validity,
            severity=verdict.severity if validity == Validity.CONFIRMED else None,
            rationale=_rationale(verdict, validity),
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
        key = self.statement_key(draft)
        if (same := uow.decisions.find_by_statement(finding.id, key)) is not None:
            return same
        saved = uow.decisions.add(draft.model_copy(update={"statement_key": key}))
        if (reason := self._review.needs_signoff(saved)) is not None:
            uow.review_items.add(
                ReviewItem(
                    finding_id=finding.id, decision_id=saved.id, reason=reason, status="pending"
                )
            )
        if self._ledger is not None:
            self._ledger.append_decision(saved, finding.repository_id, sign=False)
        return saved


def _rationale(verdict: Any, validity: Validity) -> str:
    """The verifiers' rationale, then why the verdict maps to this validity."""
    why = {
        Validity.CONFIRMED: "",
        Validity.HARDENING: "(triage: hardening, exclusion rule 13: an accurate gap with no "
        "concrete exploit path)",
        Validity.FALSE_POSITIVE: "(triage: refuted: "
        f"{', '.join(verdict.refute_reasons) or 'see rationale'}; "
        f"exclusion rule {verdict.exclusion_rule or 'none'})",
    }[validity]
    text = " ".join(p for p in ((verdict.rationale or "").strip(), why) if p)
    return text[:_RATIONALE_CAP]
