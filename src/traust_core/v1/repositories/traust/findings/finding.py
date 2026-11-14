from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.findings import Finding
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING = TableSpec(
    TRAUST,
    "finding",
    lambda: (
        uuid_column("repository_id"),
        uuid_column("advisory_id", nullable=True),
        text_column("advisory_match", nullable=True),
        text_column("fingerprint_algo"),
        text_column("fingerprint"),
        text_column("kind", nullable=True),
        text_column("title"),
    ),
)


class FindingRepository(MutableRecordRepository[Finding], Protocol):
    def get_for_update(self, finding_id: UUID) -> Finding: ...

    def find_by_fingerprint(
        self, repository_id: UUID, fingerprint_algo: str | None, fingerprint: str
    ) -> Finding | None: ...

    def list_for_repository(self, repository_id: UUID) -> list[Finding]: ...
    def list_for_repositories(self, repository_ids: Collection[UUID]) -> list[Finding]: ...
    def census_for_repositories(
        self, repository_ids: Collection[UUID]
    ) -> list[tuple[UUID, UUID, str | None, str, datetime]]:
        """(id, repository_id, kind, title, created_at) per finding of the repositories,
        newest first in bounded batches: the census counts states, severities and labels
        without materializing a model per row, in the order the views' own fold counts."""
        ...

    def census_counts_for_repositories(
        self, repository_ids: Collection[UUID]
    ) -> list[tuple[UUID, int]]:
        """How many findings each repository holds, one narrow count row per repository:
        what bounds a census batch by findings, never by repository count alone."""
        ...

    def page_for_repositories(
        self,
        repository_ids: Collection[UUID],
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[Finding]: ...
    def list_for_advisory(self, advisory_id: UUID) -> list[Finding]: ...
    def list_by_ids(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Finding]: ...


class SqlFindingRepository(SqlMutableRepository[Finding]):
    spec = FINDING
    record = Finding

    def update(self, record: Finding) -> Finding:
        record = self._to_record(record)
        if record.id is not None and self.get(record.id).repository_id != record.repository_id:
            raise ValidationError("a finding's repository identity cannot change")
        return super().update(record)

    def get_for_update(self, finding_id: UUID) -> Finding:
        stmt = self._select().where(self.table.c.id == finding_id).with_for_update()
        row = self._execute(f"lock finding {finding_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"finding {finding_id}")
        return self._to_record(row)

    def find_by_fingerprint(
        self, repository_id: UUID, fingerprint_algo: str | None, fingerprint: str
    ) -> Finding | None:
        c = self.table.c
        conditions = [c.repository_id == repository_id, c.fingerprint == fingerprint]
        if fingerprint_algo is not None:
            conditions.append(c.fingerprint_algo == fingerprint_algo)
        stmt = self._select().where(*conditions).limit(2)
        rows = self._execute(f"find {fingerprint_algo}:{fingerprint}", stmt).mappings().all()
        if len(rows) > 1:
            raise ConflictError(
                f"ambiguous fingerprint {fingerprint!r} for repository {repository_id}; "
                "specify fingerprint_algo"
            )
        return None if not rows else self._to_record(rows[0])

    def list_for_repository(self, repository_id: UUID) -> list[Finding]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)

    def list_for_repositories(self, repository_ids: Collection[UUID]) -> list[Finding]:
        return self._many_in("list for repositories", self.table.c.repository_id, repository_ids)

    def census_for_repositories(
        self, repository_ids: Collection[UUID]
    ) -> list[tuple[UUID, UUID, str | None, str, datetime]]:
        """(id, repository_id, kind, title, created_at) per finding of the repositories,
        newest first in bounded batches: the census counts states, severities and labels
        without materializing a model per row, in the order the views' own fold counts."""
        c = self.table.c
        found: list[tuple[UUID, UUID, str | None, str, datetime]] = []
        for batch in self._batches(repository_ids):
            stmt = (
                sa.select(c.id, c.repository_id, c.kind, c.title, c.created_at)
                .where(c.repository_id.in_(batch))
                .order_by(c.created_at.desc(), c.id.desc())
            )
            rows = self._execute(f"census for {len(batch)} repositories", stmt)
            found.extend((row[0], row[1], row[2], row[3], row[4]) for row in rows)
        return found

    def census_counts_for_repositories(
        self, repository_ids: Collection[UUID]
    ) -> list[tuple[UUID, int]]:
        """How many findings each repository holds, one narrow count row per repository:
        what bounds a census batch by findings, never by repository count alone."""
        c = self.table.c
        found: list[tuple[UUID, int]] = []
        for batch in self._batches(repository_ids):
            stmt = (
                sa.select(c.repository_id, sa.func.count())
                .where(c.repository_id.in_(batch))
                .group_by(c.repository_id)
            )
            rows = self._execute(f"census counts for {len(batch)} repositories", stmt)
            found.extend((row[0], row[1]) for row in rows)
        return found

    def page_for_repositories(
        self,
        repository_ids: Collection[UUID],
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[Finding]:
        """The repositories' findings newest first, keyset-paged across the whole set: one
        indexed query over a page's worth of repositories (the `repository_ids` batch shape
        `OrderFilter` set), not one walk per repository. An empty set pages over nothing."""
        wanted = list(dict.fromkeys(repository_ids))
        return self._page(
            f"page for {len(wanted)} repositories",
            self.table.c.repository_id.in_(wanted),
            limit=limit,
            after=after,
        )

    def list_for_advisory(self, advisory_id: UUID) -> list[Finding]:
        return self._many(
            f"list for advisory {advisory_id}", self.table.c.advisory_id == advisory_id
        )

    def list_by_ids(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Finding]:
        return self._many_in("list by id", self.table.c.id, finding_ids, read_budget=read_budget)
