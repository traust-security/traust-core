from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.compliance import ComplianceResult, ComplianceScope
from traust_core.v1.models.operations import JobResult
from traust_core.v1.repositories.compliance import ComplianceUnitOfWork


class ComplianceService:
    def __init__(self, uow: ComplianceUnitOfWork) -> None:
        self._uow = uow

    def set_scope(self, scope: ComplianceScope) -> None:
        raise NotImplementedError("stub: replaces compliance_scope_intake.py, compliance/scope.py")

    def evaluate(self, scope_id: UUID, framework: str) -> JobResult:
        raise NotImplementedError("stub: replaces compliance-check scripts")

    def latest(self, scope_id: UUID, framework: str) -> list[ComplianceResult]:
        raise NotImplementedError("stub: replaces compliance/dashboard.py reads")
