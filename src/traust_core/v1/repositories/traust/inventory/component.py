from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.inventory import Component
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

COMPONENT = TableSpec(
    TRAUST, "component", lambda: (uuid_column("release_id"), uuid_column("repository_ref_id"))
)


class ComponentRepository(MutableRecordRepository[Component], Protocol):
    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Component]: ...
    def get_or_add(self, record: Component) -> Component: ...
    def find(self, release_id: UUID, repository_ref_id: UUID) -> Component | None: ...
    def list_for_release(self, release_id: UUID) -> list[Component]: ...
    def list_for_ref(self, repository_ref_id: UUID) -> list[Component]: ...


class SqlComponentRepository(SqlMutableRepository[Component]):
    spec = COMPONENT
    record = Component

    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Component]:
        return self._page("search", limit=limit, after=after)

    def get_or_add(self, record: Component) -> Component:
        return self._get_or_add(
            record,
            ("release_id", "repository_ref_id"),
            lambda: self.find(record.release_id, record.repository_ref_id),
        )

    def find(self, release_id: UUID, repository_ref_id: UUID) -> Component | None:
        c = self.table.c
        return self._one(
            f"find {release_id}/{repository_ref_id}",
            c.release_id == release_id,
            c.repository_ref_id == repository_ref_id,
        )

    def list_for_release(self, release_id: UUID) -> list[Component]:
        return self._many(f"list for {release_id}", self.table.c.release_id == release_id)

    def list_for_ref(self, repository_ref_id: UUID) -> list[Component]:
        return self._many(
            f"list for ref {repository_ref_id}", self.table.c.repository_ref_id == repository_ref_id
        )
