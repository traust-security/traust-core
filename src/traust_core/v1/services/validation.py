from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.storage import BindingContext
from traust_core.v1.models.validation import ValidationAttempt, ValidationPlan
from traust_core.v1.repositories.validation import ValidationUnitOfWork


class ValidationService:
    def __init__(self, uow: ValidationUnitOfWork) -> None:
        self._uow = uow

    def plan(self, finding_id: UUID) -> ValidationPlan:
        raise NotImplementedError("stub: replaces validate-findings plan.py")

    def authorize(self, plan_id: UUID) -> JobResult:
        raise NotImplementedError("stub: replaces validation/scope.py")

    def attest_target(self, plan_id: UUID) -> JobResult:
        raise NotImplementedError("stub: replaces attest_target.py")

    def record_validation(self, report: ValidationArtifact, context: BindingContext) -> JobResult:
        raise NotImplementedError("stub: replaces emit_validation_ledger_events.py")

    def history(self, finding_id: UUID) -> list[ValidationAttempt]:
        raise NotImplementedError("stub: replaces validation-audit.jsonl walks")
