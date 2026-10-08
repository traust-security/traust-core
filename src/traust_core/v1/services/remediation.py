from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.remediation import WorkItem
from traust_core.v1.models.storage import BindingContext
from traust_core.v1.repositories.remediation import RemediationUnitOfWork


class RemediationService:
    def __init__(self, uow: RemediationUnitOfWork) -> None:
        self._uow = uow

    def open(self, finding_ids: Sequence[UUID]) -> WorkItem:
        raise NotImplementedError("stub: replaces remediate-finding manifest scripts")

    def open_fleet_fix(self, cwe: str, repository_ids: Sequence[UUID]) -> list[WorkItem]:
        raise NotImplementedError("stub: replaces fleet-fix scripts, fleet_targets.py")

    def next_pending(self) -> WorkItem | None:
        raise NotImplementedError("stub: replaces remediate-finding pending selection")

    def record_verification(
        self, report: VerificationArtifact, context: BindingContext
    ) -> JobResult:
        raise NotImplementedError(
            "stub: replaces emit_verification_ledger_events.py, route_regressions.py"
        )

    def propagated(self, work_item_id: UUID, code_line_id: UUID) -> bool:
        raise NotImplementedError("stub: replaces check_fix_propagation.py")
