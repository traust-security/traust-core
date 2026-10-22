from __future__ import annotations

from typing import Protocol

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
    def find_by_url(self, url: str) -> Repository | None: ...


class SqlRepositoryRepository(SqlMutableRepository[Repository]):
    spec = REPOSITORY
    record = Repository

    def find_by_url(self, url: str) -> Repository | None:
        return self._one(f"find {url}", self.table.c.url == url)
