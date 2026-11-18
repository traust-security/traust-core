from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.findings import FindingLabel
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING_LABEL = TableSpec(
    TRAUST,
    "finding_label",
    lambda: (uuid_column("finding_id"), text_column("taxonomy"), text_column("label")),
)


class FindingLabelRepository(MutableRecordRepository[FindingLabel], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingLabel]: ...
    def list_for_findings(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[FindingLabel]: ...

    def list_with(self, taxonomy: str, label: str) -> list[FindingLabel]: ...


class SqlFindingLabelRepository(SqlMutableRepository[FindingLabel]):
    spec = FINDING_LABEL
    record = FindingLabel

    def list_for_finding(self, finding_id: UUID) -> list[FindingLabel]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_with(self, taxonomy: str, label: str) -> list[FindingLabel]:
        c = self.table.c
        return self._many(f"list {taxonomy}:{label}", c.taxonomy == taxonomy, c.label == label)

    def list_for_findings(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[FindingLabel]:
        """Labels on these findings, read in bounded batches so a whole scope's ids cannot
        exceed the bind limit."""
        c = self.table.c
        return [
            label
            for batch in self._batches(finding_ids)
            for label in self._many(
                f"list for {len(finding_ids)} findings",
                c.finding_id.in_(batch),
                read_budget=read_budget,
            )
        ]
