from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import FindingCwe
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

FINDING_CWE = TableSpec(
    TRAUST, "finding_cwe", lambda: (uuid_column("finding_id"), uuid_column("cwe_id"))
)


class FindingCweRepository(MutableRecordRepository[FindingCwe], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingCwe]: ...
    def list_for_cwe(self, cwe_id: UUID) -> list[FindingCwe]: ...
    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[FindingCwe]: ...


class SqlFindingCweRepository(SqlMutableRepository[FindingCwe]):
    spec = FINDING_CWE
    record = FindingCwe

    def list_for_finding(self, finding_id: UUID) -> list[FindingCwe]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_cwe(self, cwe_id: UUID) -> list[FindingCwe]:
        return self._many(f"list for cwe {cwe_id}", self.table.c.cwe_id == cwe_id)

    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[FindingCwe]:
        c = self.table.c
        return self._many(
            f"list for {len(finding_ids)} findings", c.finding_id.in_(list(finding_ids))
        )
