from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import Cwe
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

CWE = TableSpec(
    TRAUST,
    "cwe",
    lambda: (
        text_column("identifier"),
        text_column("abstraction", nullable=True),
        text_column("mapping_usage", nullable=True),
        text_column("catalog_version", nullable=True),
    ),
)


class CweRepository(MutableRecordRepository[Cwe], Protocol):
    def find_by_identifier(self, identifier: str) -> Cwe | None: ...
    def list_by_ids(self, cwe_ids: Collection[UUID]) -> list[Cwe]: ...
    def get_or_add(self, record: Cwe) -> Cwe: ...


class SqlCweRepository(SqlMutableRepository[Cwe]):
    spec = CWE
    record = Cwe

    def find_by_identifier(self, identifier: str) -> Cwe | None:
        return self._one(f"find {identifier}", self.table.c.identifier == identifier)

    def get_or_add(self, record: Cwe) -> Cwe:
        return self._get_or_add(
            record, ("identifier",), lambda: self.find_by_identifier(record.identifier)
        )

    def list_by_ids(self, cwe_ids: Collection[UUID]) -> list[Cwe]:
        return self._many(f"list {len(cwe_ids)} cwes", self.table.c.id.in_(cwe_ids))
