from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import FindingExternalRef
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING_EXTERNAL_REF = TableSpec(
    TRAUST,
    "finding_external_ref",
    lambda: (uuid_column("finding_id"), text_column("system"), text_column("ref")),
)


class FindingExternalRefRepository(MutableRecordRepository[FindingExternalRef], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRef]: ...
    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRef]: ...
    def list_for_findings(
        self, finding_ids: Collection[UUID], system: str
    ) -> list[FindingExternalRef]: ...


class SqlFindingExternalRefRepository(SqlMutableRepository[FindingExternalRef]):
    spec = FINDING_EXTERNAL_REF
    record = FindingExternalRef

    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRef]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRef]:
        c = self.table.c
        return self._many(f"list {system}:{ref}", c.system == system, c.ref == ref)

    def list_for_findings(
        self, finding_ids: Collection[UUID], system: str
    ) -> list[FindingExternalRef]:
        c = self.table.c
        return self._many(
            f"list {system} for {len(finding_ids)} findings",
            c.finding_id.in_(finding_ids),
            c.system == system,
        )
