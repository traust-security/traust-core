from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import DecisionApprover
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

DECISION_APPROVER = TableSpec(
    TRAUST,
    "decision_approver",
    lambda: (uuid_column("decision_id"), text_column("approver")),
    append_only=True,
)


class DecisionApproverRepository(RecordRepository[DecisionApprover], Protocol):
    def list_for_decision(self, decision_id: UUID) -> list[DecisionApprover]: ...


class SqlDecisionApproverRepository(SqlAppendOnlyRepository[DecisionApprover]):
    spec = DECISION_APPROVER
    record = DecisionApprover

    def list_for_decision(self, decision_id: UUID) -> list[DecisionApprover]:
        c = self.table.c
        return self._many(f"approvers of {decision_id}", c.decision_id == decision_id)
