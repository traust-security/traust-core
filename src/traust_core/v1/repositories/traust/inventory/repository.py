from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.inventory import Repository
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
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
        # The unreachable disposition (foundry plan repo-unreachable); NULL = active.
        sa.Column("disposition", sa.Text, nullable=True),
        sa.Column("disposition_reason", sa.Text, nullable=True),
        sa.Column("disposition_evidence", sa.Text, nullable=True),
        timestamp_column("disposition_at", nullable=True),
        sa.Column("gone_streak", sa.Integer, nullable=False, default=0),
    ),
)


class RepositoryRepository(MutableRecordRepository[Repository], Protocol):
    def get_or_add(self, record: Repository) -> Repository: ...
    def get_or_add_with_status(self, record: Repository) -> tuple[Repository, bool]: ...
    def find_by_url(self, url: str) -> Repository | None: ...
    def get_for_update(self, repository_id: UUID) -> Repository: ...
    def find_by_url_casefold(self, url: str) -> Repository | None: ...
    def lock_url(self, url: str) -> None: ...
    def find_private_mirror(self, upstream_id: UUID) -> Repository | None: ...
    def list_by_upstream(self, upstream_id: UUID) -> list[Repository]: ...
    def list_by_ids(self, repository_ids: Collection[UUID]) -> list[Repository]: ...
    def list_all(self, *, read_budget: RecordBudget | None = None) -> list[Repository]: ...
    def search(
        self,
        *,
        limit: int,
        after: tuple[datetime, UUID] | None,
        dispositioned: bool | None = None,
    ) -> list[Repository]: ...


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

    def get_for_update(self, repository_id: UUID) -> Repository:
        """The row a metadata write reads, locked until the transaction ends (Postgres; SQLite's
        caller holds its write lock), so two writers can't put back a stale value."""
        stmt = self._select().where(self.table.c.id == repository_id).with_for_update()
        row = self._execute(f"lock repository {repository_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"repository {repository_id}")
        return self._to_record(row)

    def find_by_url_casefold(self, url: str) -> Repository | None:
        """The oldest repository whose URL matches ignoring case (GitHub's owner/repo)."""
        # NEED(contracts): an index on repository(lower(url)); until then this scans the
        # repository table, like find_private_mirror.
        found = self._many(f"find casefold {url}", sa.func.lower(self.table.c.url) == url.lower())
        return found[0] if found else None

    def lock_url(self, url: str) -> None:
        """Hold, until the transaction ends, a Postgres advisory lock covering this URL in any
        case, so two writers spelling one GitHub repository differently can't both insert a
        row. SQLite needs none: the caller holds its one write lock (`uow.write()`)."""
        # NEED(contracts): a unique index on repository(lower(url)) would make this a constraint.
        if self._connection.dialect.name == "postgresql":
            lock = sa.func.pg_advisory_xact_lock(sa.func.hashtext(url.lower()))
            self._execute(f"lock {url}", sa.select(lock))

    def list_by_upstream(self, upstream_id: UUID) -> list[Repository]:
        """Every repository whose upstream link points at `upstream_id`: its forks and
        mirrors, and — after a URL correction — the vacated-URL rows that record where
        the repository used to live (the same edge, read whole)."""
        c = self.table.c
        return self._many(f"upstream of {upstream_id}", c.upstream_id == upstream_id)

    def find_private_mirror(self, upstream_id: UUID) -> Repository | None:
        """A non-public repository that forks `upstream_id` (the oldest, when several do)."""
        # NEED(contracts): an index on repository(upstream_id); until then this scans the
        # repository table (10k rows: 0.3 ms).
        c = self.table.c
        mirrors = self._many(f"mirror of {upstream_id}", c.upstream_id == upstream_id, ~c.public)
        return mirrors[0] if mirrors else None

    def list_by_ids(self, repository_ids: Collection[UUID]) -> list[Repository]:
        return self._many_in(f"list {len(repository_ids)} by id", self.table.c.id, repository_ids)

    def list_all(self, *, read_budget: RecordBudget | None = None) -> list[Repository]:
        c = self.table.c
        return self._many(
            "list all",
            order_by=(c.created_at.desc(), c.id.desc()),
            read_budget=read_budget,
        )

    def search(
        self,
        *,
        limit: int,
        after: tuple[datetime, UUID] | None,
        dispositioned: bool | None = None,
    ) -> list[Repository]:
        """A keyset page of repositories; `dispositioned` narrows the universe the way the
        filter names it (None: every repository, False: only active, True: only the ones
        carrying the unreachable disposition)."""
        where = ()
        if dispositioned is not None:
            gone = self.table.c.disposition.is_not(None)
            where = (gone,) if dispositioned else (~gone,)
        return self._page("search", *where, limit=limit, after=after)
