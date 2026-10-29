from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import LocationHash
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

LOCATION_HASH = TableSpec(
    TRAUST,
    "location_hash",
    lambda: (uuid_column("location_id"), text_column("algorithm"), text_column("digest")),
    append_only=True,
)


class LocationHashRepository(RecordRepository[LocationHash], Protocol):
    def list_for_locations(self, location_ids: Collection[UUID]) -> list[LocationHash]: ...


class SqlLocationHashRepository(SqlAppendOnlyRepository[LocationHash]):
    spec = LOCATION_HASH
    record = LocationHash

    def list_for_locations(self, location_ids: Collection[UUID]) -> list[LocationHash]:
        return self._many_in("list for locations", self.table.c.location_id, location_ids)
