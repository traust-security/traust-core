from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.dependencies import Advisory
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

ADVISORY = TableSpec(
    TRAUST,
    "advisory",
    lambda: (
        uuid_column("alias_of_id", nullable=True),
        text_column("identifier"),
        timestamp_column("published_at", nullable=True),
    ),
)


class AdvisoryRepository(MutableRecordRepository[Advisory], Protocol):
    def find_by_identifier(self, identifier: str) -> Advisory | None: ...
    def list_aliases(self, advisory_id: UUID) -> list[Advisory]: ...
    def get_or_add(self, record: Advisory) -> Advisory: ...


class SqlAdvisoryRepository(SqlMutableRepository[Advisory]):
    spec = ADVISORY
    record = Advisory

    def find_by_identifier(self, identifier: str) -> Advisory | None:
        return self._one(f"find {identifier}", self.table.c.identifier == identifier)

    def list_aliases(self, advisory_id: UUID) -> list[Advisory]:
        return self._many(f"aliases of {advisory_id}", self.table.c.alias_of_id == advisory_id)

    def get_or_add(self, record: Advisory) -> Advisory:
        return self._get_or_add(
            record, ("identifier",), lambda: self.find_by_identifier(record.identifier)
        )
