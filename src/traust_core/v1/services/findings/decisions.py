from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Principal, Provenance, Role
from traust_core.v1.models.findings import (
    Decision,
    RecordDecision,
    StatementKey,
    TriageInput,
)
from traust_core.v1.repositories.contract import TraustUnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.ledger import LedgerService
    from traust_core.v1.services.portfolio import PortfolioService

_CLASSIFIERS = {
    "validity": "validity",
    "resolution": "disposition_resolution",
    "evidence_grade": "evidence_grade",
    "reason": "decision_reason",
    "severity": "severity",
    "source_channel": "source_channel",
}


class FindingDecisions:
    """Decisions are the only writes to a finding's state; every read is a view over them."""

    def __init__(
        self,
        uow: TraustUnitOfWork,
        ledger: LedgerService | None = None,
        *,
        assessment: AssessmentService,
        portfolio: PortfolioService,
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._assessment = assessment
        self._portfolio = portfolio

    def decide(self, command: RecordDecision, *, principal: Principal | None = None) -> Decision:
        """Append idempotently; risk acceptance requires a matching verified human principal."""
        command = RecordDecision.model_validate(dict(command))
        self._validate(command, principal)
        decision = Decision(**command.model_dump(), statement_key="")
        decision = decision.model_copy(update={"statement_key": self.statement_key(decision)})
        with self._uow.write() as uow:
            finding = uow.findings.get_for_update(command.finding_id)
            refs = [command.repository_ref_id, command.fixed_repository_ref_id]
            if command.assessment_id is not None:
                refs.append(self._assessment.get(command.assessment_id).repository_ref_id)
            for ref_id in refs:
                if ref_id is not None:
                    ref = self._portfolio.get_ref(ref_id)
                    if ref.repository_id != finding.repository_id:
                        raise ValidationError("a decision must judge its finding's repository")
            if command.restates_id is not None:
                previous = uow.decisions.get(command.restates_id)
                if previous.finding_id != command.finding_id:
                    raise ValidationError("a restatement must judge the same finding")
                if command.reason is None:
                    raise ValidationError("a restatement needs a correction reason")
                if command.ticket is None or not command.ticket.strip():
                    raise ValidationError("a restatement needs an authority ticket")
                if command.rationale is None or not command.rationale.strip():
                    raise ValidationError("a restatement needs a rationale")
            existing = uow.decisions.find_by_statement(command.finding_id, decision.statement_key)
            if existing is None:
                history = uow.decisions.list_for_finding(command.finding_id)
                existing = next(
                    (row for row in history if self.statement_key(row) == decision.statement_key),
                    None,
                )
                if existing is None:
                    self._admit(command, [self._read(row) for row in history])
            saved = existing or uow.decisions.add_statement(decision)
            if self._ledger is not None and existing is None:
                self._ledger.append_decision(saved, finding.repository_id)
            uow.commit()
            return self._read(saved)

    def statement_key(self, decision: Decision) -> StatementKey:
        """Hash the data model's judged fields, never transport or generated metadata."""
        decision = Decision.model_validate(dict(decision))
        judged = {
            field: str(value) if value is not None else None
            for field in (
                "finding_id",
                "assessment_id",
                "actor",
                "repository_ref_id",
                "restates_id",
                "fixed_repository_ref_id",
            )
            for value in (getattr(decision, field),)
        }
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
        payload = json.dumps(judged, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return StatementKey(hashlib.sha256(payload.encode()).hexdigest())

    def restate(
        self, decision_id: UUID, correction: RecordDecision, *, principal: Principal
    ) -> Decision:
        """Append a linked correction with verified-human ADMIN or RESTATE authority."""
        correction = RecordDecision.model_validate(dict(correction))
        if correction.restates_id not in (None, decision_id):
            raise ValidationError("correction restates_id disagrees with the prior decision")
        return self.decide(
            correction.model_copy(update={"restates_id": decision_id}), principal=principal
        )

    def get(self, decision_id: UUID) -> Decision:
        with self._uow as uow:
            return self._read(uow.decisions.get(decision_id))

    def list_for_finding(self, finding_id: UUID) -> list[Decision]:
        with self._uow as uow:
            return [self._read(row) for row in uow.decisions.list_for_finding(finding_id)]

    @staticmethod
    def _validate(command: RecordDecision, principal: Principal | None) -> None:
        for field, name in _CLASSIFIERS.items():
            if (value := getattr(command, field)) is not None:
                contracts.validate_enum(name, value)
        if (command.assessment_id is None) == (command.actor is None):
            raise ValidationError("a decision needs either an assessment or an actor, not both")
        if command.actor is not None and not command.actor.strip():
            raise ValidationError("a decision actor must identify a principal")
        if command.assessment_id is not None and command.repository_ref_id is not None:
            raise ValidationError("an assessment decision uses its assessment's repository ref")
        if command.occurred_at.tzinfo is None or command.occurred_at.utcoffset() is None:
            raise ValidationError("a decision occurred_at must include a timezone")
        if command.resolution == "risk_accepted" or command.restates_id is not None:
            if principal is None:
                raise ValidationError("this judgement requires a verified human principal")
            principal = Principal.model_validate(dict(principal))
            if not principal.is_verified_human() or command.actor != principal.ref:
                raise ValidationError("the actor must match the verified human principal")
            if command.restates_id is not None and not (
                principal.has_role(Role.ADMIN) or principal.has_role(Role.RESTATE)
            ):
                raise ValidationError("a restatement requires restatement authority")

    def _admit(self, command: RecordDecision, history: Sequence[Decision]) -> None:
        ranks = {value: index for index, value in enumerate(("E0", "E1", "E2", "E3"))}
        grade = ranks.get(command.evidence_grade)
        prior_grades = [ranks[row.evidence_grade] for row in history if row.evidence_grade in ranks]
        if grade is not None and prior_grades and grade > min(prior_grades):
            raise ValidationError("weaker evidence cannot replace stronger recorded proof")
        for field in ("validity", "severity", "resolution"):
            value = getattr(command, field)
            if value is None or (field == "resolution" and value == "risk_accepted"):
                continue
            rows = history
            if field == "resolution":
                line = self._line(command)
                on_line = [
                    row for row in history if row.resolution is not None and self._line(row) == line
                ]
                rows = on_line or [
                    row for row in history if row.resolution is not None and self._line(row) is None
                ]
            current = next((row for row in reversed(rows) if getattr(row, field) is not None), None)
            if current is not None and getattr(current, field) != value:
                if grade is None:
                    raise ValidationError(f"an ungraded claim cannot override {field}")
                strength = [
                    ranks[row.evidence_grade]
                    for row in rows
                    if getattr(row, field) == getattr(current, field)
                    and row.evidence_grade in ranks
                ]
                if strength and grade > min(strength):
                    raise ValidationError(f"weaker evidence cannot override {field}")

    def _line(self, decision: RecordDecision | Decision) -> str | None:
        ref_id = decision.repository_ref_id
        if decision.assessment_id is not None:
            ref_id = self._assessment.get(decision.assessment_id).repository_ref_id
        return None if ref_id is None else self._portfolio.get_ref(ref_id).name

    @staticmethod
    def _read(decision: Decision) -> Decision:
        fields = {name: field for field, name in _CLASSIFIERS.items()}
        values = decision.model_dump()
        for field, name in _CLASSIFIERS.items():
            if (value := getattr(decision, field)) is None:
                continue
            normalized = contracts.normalize_enum(name, value)
            if normalized.dropped:
                values[field] = None
                continue
            for pair in normalized.pairs:
                target = fields.get(pair.enum)
                if target is not None and (target == field or values[target] is None):
                    values[target] = pair.value
        return Decision.model_validate(values)

    def prepare(self, assessment_id: UUID) -> TriageInput:
        raise NotImplementedError("stub: replaces the triage skill's query_index / precedent CLIs")

    def record(self, doc: TriageArtifact, provenance: Provenance) -> list[Decision]:
        """A triage is an assessment (kind triage) and one decision per verdict, one transaction."""
        raise NotImplementedError("stub: replaces record_triage, emit_triage_ledger_events")
