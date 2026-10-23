from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.inventory import Repository
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

REPOSITORY = TableSpec(
    TRAUST,
    "repository",
    lambda: (
        uuid_column("upstream_id", nullable=True),
        text_column("url"),
        sa.Column("public", sa.Boolean, nullable=False),
        sa.Column("archived", sa.Boolean, nullable=True),
    ),
)


class RepositoryRepository(MutableRecordRepository[Repository], Protocol):
    def get_or_add(self, record: Repository) -> Repository: ...
    def find_by_url(self, url: str) -> Repository | None: ...
    def find_private_mirror(self, upstream_id: UUID) -> Repository | None: ...
    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Repository]: ...


class SqlRepositoryRepository(SqlMutableRepository[Repository]):
    spec = REPOSITORY
    record = Repository

    def get_or_add(self, record: Repository) -> Repository:
        return self._get_or_add(
            record,
            ("url",),
            lambda: self.find_by_url(record.url),
        )

    def find_by_url(self, url: str) -> Repository | None:
        return self._one(f"find {url}", self.table.c.url == url)

    def find_private_mirror(self, upstream_id: UUID) -> Repository | None:
        """The oldest non-public repository that forks `upstream_id`."""
        c = self.table.c
        mirrors = self._many(f"mirror of {upstream_id}", c.upstream_id == upstream_id, ~c.public)
        return mirrors[0] if mirrors else None

    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Repository]:
        return self._page("search", limit=limit, after=after)
