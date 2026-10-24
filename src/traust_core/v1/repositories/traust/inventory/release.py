from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.inventory import Release
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

RELEASE = TableSpec(TRAUST, "release", lambda: (uuid_column("product_id"), text_column("version")))


class ReleaseRepository(MutableRecordRepository[Release], Protocol):
    def get_or_add(self, record: Release) -> Release: ...
    def find(self, product_id: UUID, version: str) -> Release | None: ...
    def list_for_product(self, product_id: UUID) -> list[Release]: ...
    def list_by_ids(self, release_ids: Collection[UUID]) -> list[Release]: ...


class SqlReleaseRepository(SqlMutableRepository[Release]):
    spec = RELEASE
    record = Release

    def get_or_add(self, record: Release) -> Release:
        return self._get_or_add(
            record,
            ("product_id", "version"),
            lambda: self.find(record.product_id, record.version),
        )

    def find(self, product_id: UUID, version: str) -> Release | None:
        c = self.table.c
        return self._one(f"find {version}", c.product_id == product_id, c.version == version)

    def list_for_product(self, product_id: UUID) -> list[Release]:
        return self._many(f"list for {product_id}", self.table.c.product_id == product_id)

    def list_by_ids(self, release_ids: Collection[UUID]) -> list[Release]:
        return self._many_in(f"list {len(release_ids)} by id", self.table.c.id, release_ids)
