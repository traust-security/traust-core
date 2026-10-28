from __future__ import annotations

from collections.abc import Collection
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
    def get_or_add_with_status(self, record: Repository) -> tuple[Repository, bool]: ...
    def find_by_url(self, url: str) -> Repository | None: ...
    def list_by_urls(self, urls: Collection[str]) -> list[Repository]: ...
    def find_private_mirror(self, upstream_id: UUID) -> Repository | None: ...
    def list_by_ids(self, repository_ids: Collection[UUID]) -> list[Repository]: ...
    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Repository]: ...


class SqlRepositoryRepository(SqlMutableRepository[Repository]):
    spec = REPOSITORY
    record = Repository

    def get_or_add(self, record: Repository) -> Repository:
        return self.get_or_add_with_status(record)[0]

    def get_or_add_with_status(self, record: Repository) -> tuple[Repository, bool]:
        return self._get_or_add_with_status(
            record,
            ("url",),
            lambda: self.find_by_url(record.url),
        )

    def find_by_url(self, url: str) -> Repository | None:
        return self._one(f"find {url}", self.table.c.url == url)

    def list_by_urls(self, urls: Collection[str]) -> list[Repository]:
        return self._many_in(f"list {len(urls)} by url", self.table.c.url, urls)

    def find_private_mirror(self, upstream_id: UUID) -> Repository | None:
        """A non-public repository that forks `upstream_id` (the oldest, when several do)."""
        # NEED(contracts): an index on repository(upstream_id); until then this scans the
        # repository table (10k rows: 0.3 ms).
        c = self.table.c
        mirrors = self._many(f"mirror of {upstream_id}", c.upstream_id == upstream_id, ~c.public)
        return mirrors[0] if mirrors else None

    def list_by_ids(self, repository_ids: Collection[UUID]) -> list[Repository]:
        return self._many_in(f"list {len(repository_ids)} by id", self.table.c.id, repository_ids)

    def search(self, *, limit: int, after: tuple[datetime, UUID] | None) -> list[Repository]:
        return self._page("search", limit=limit, after=after)
