from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import (
    RATIONALE_MIN_LENGTH,
    RESTATABLE,
    Decision,
    DecisionApprover,
    Disposition,
    FindingContext,
    Location,
    RecordDecision,
    Restatement,
    StatementKey,
    SubjectRef,
    TriageInput,
    TriageItem,
    normalize_decision,
)
from traust_core.v1.models.identity import Principal, Role
from traust_core.v1.models.integrity import canonical_json, sha256_hex
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.sources import WorkspaceFiles
from traust_core.v1.repositories.contract import TraustUnitOfWork
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

_JUDGED = (
    "finding_id",
    "assessment_id",
    "actor",
    "repository_ref_id",
    "restates_id",
    "fixed_repository_ref_id",
)


class FindingDecisions:
    """Decisions are the only writes to a finding's state; every read is a view over them."""

    def __init__(
        self,
        uow: TraustUnitOfWork,
        ledger: LedgerService | None,
        lint: Lint,
        *,
        clock: Clock,
        restatement_approvers: int = 0,
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._lint = lint
        self._clock = clock
        self._restatement_approvers = restatement_approvers

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
            return [normalize_decision(row) for row in uow.decisions.list_for_finding(finding_id)]

    def statement_key(self, decision: Decision) -> StatementKey:
        """Hash normalized judged values, excluding transport and generated metadata."""
        decision = Decision.model_validate(dict(decision))
        judged = {k: str(v) if (v := getattr(decision, k)) is not None else None for k in _JUDGED}
        judged["classifiers"] = sorted(
            {
                (pair.enum, pair.value)
                for field, name in _CLASSIFIERS.items()
                if field != "source_channel" and (value := getattr(decision, field)) is not None
                for normalized in (contracts.normalize_enum(name, value),)
                if not normalized.dropped
                for pair in normalized.pairs
                if pair.enum in _CLASSIFIERS.values() and pair.enum != "source_channel"
            }
        )
        return StatementKey(sha256_hex(canonical_json(judged)))

    def restate(self, restatement: Restatement, principal: Principal) -> Decision:
        """An administrator's correction: a new decision that replaces the one it restates."""
        restatement = Restatement.model_validate(dict(restatement))
        principal = Principal.model_validate(dict(principal))
        self._validate_classifiers(restatement)
        contracts.validate_enum("restatement_reason", restatement.reason)
        approvers = self._authorize(restatement, principal)
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
            _check_correction(restatement, restated, [normalize_decision(row) for row in history])
            saved = uow.decisions.add_statement(draft)
            for approver in sorted(approvers):
                ref = f"{ActorKind.HUMAN}:{approver}"
                uow.decision_approvers.add(DecisionApprover(decision_id=saved.id, approver=ref))
            if self._ledger is not None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
        log.info("decision %s restated as %s by %s", restated.id, saved.id, principal.ref)
        return normalize_decision(saved)

    def _authorize(self, restatement: Restatement, principal: Principal) -> set[str]:
        """Who may restate, and on whose authority (traust-ledger's restatement gates)."""
        if not principal.is_verified_human():
            raise ForbiddenError(f"{principal.ref}: a restatement is a verified human's correction")
        if not principal.has_role(Role.RESTATE):
            raise ForbiddenError(f"{principal.ref}: restating needs the restate role")
        if not restatement.ticket.strip():
            raise ValidationError("a restatement names its authority: a ticket")
        if len(restatement.rationale) < RATIONALE_MIN_LENGTH:
            raise ValidationError(f"a rationale of at least {RATIONALE_MIN_LENGTH} characters")
        approvers = {a.strip().lower() for a in restatement.approvers if a.strip()}
        approvers.discard(principal.identity.strip().lower())
        if len(approvers) < self._restatement_approvers:
            raise ForbiddenError(
                f"a restatement needs {self._restatement_approvers} approvers besides its author;"
                f" it names {len(approvers)}"
            )
        return approvers

    def prepare(self, assessment_id: UUID) -> TriageInput:
        """Everything a triage of one assessment judges: its findings, as reported, and where."""
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
                    finding=findings[o.finding_id], occurrence=o, locations=tuple(where[o.id])
                )
                for o in occurrences
            ),
        )

    def check(self, doc: TriageArtifact, checkout: Path) -> LintReport:
        """Lint the triage against the target checkout: after the votes, before `record`."""
        return self._lint.run(doc, LintContext(files=WorkspaceFiles(checkout)))

    def record(self, doc: TriageArtifact, provenance: Provenance) -> list[Decision]:
        """A triage is an assessment (kind triage) and one decision per verdict, one transaction."""
        raise NotImplementedError("stub: replaces record_triage, emit_triage_ledger_events")


def _check_correction(
    restatement: Restatement, restated: Decision, history: list[Decision]
) -> None:
    """The change is real, replaces a value, restates the latest record and restores nothing."""
    if any(d.restates_id == restated.id for d in history):
        raise ConflictError(f"decision {restated.id} was already restated: restate the correction")
    changes = restatement.changes()
    if not changes:
        raise ValidationError("a restatement corrects at least one of " + ", ".join(RESTATABLE))
    by_id = {d.id: d for d in history}
    earlier, step = [], restated
    while step.restates_id is not None and (step := by_id.get(step.restates_id)) is not None:
        earlier.append(step)
    for field, value in changes.items():
        current = getattr(restated, field)
        if current is None:
            raise ValidationError(
                f"nothing to restate: {field} has no value yet; record it instead"
            )
        if value == current:
            raise ValidationError(f"the restatement changes nothing: {field} is already {value}")
        if value in {getattr(d, field) for d in earlier} - {current}:
            raise ValidationError(
                f"{field} {value} was already corrected away from; record why anew"
            )
