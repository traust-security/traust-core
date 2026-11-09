from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

REPOSITORY_REF = TableSpec(
    TRAUST,
    "repository_ref",
    lambda: (
        uuid_column("repository_id"),
        text_column("name", nullable=True),
        text_column("kind", nullable=True),
        sa.Column("is_default", sa.Boolean, nullable=False),
        timestamp_column("default_named_at", nullable=True),
        text_column("sha"),
        uuid_column("manifest_sbom_id", nullable=True),
        uuid_column("manifest_sbom_assessment_id", nullable=True),
    ),
)


class RepositoryRefRepository(MutableRecordRepository[RepositoryRef], Protocol):
    def get_or_add(self, record: RepositoryRef) -> RepositoryRef: ...
    def get_for_update(self, repository_ref_id: UUID) -> RepositoryRef:
        """The ref, locked until the transaction ends (Postgres; SQLite serialises writers)."""
        ...

    def find(self, repository_id: UUID, name: str | None, sha: str) -> RepositoryRef | None:
        """A named ref by (repository, name, sha); name None = the bare commit."""
        ...

    def list_for(
        self, repository_id: UUID, *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]: ...
    def list_for_repositories(
        self, repository_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]: ...
    def list_by_ids(self, repository_ref_ids: Collection[UUID]) -> list[RepositoryRef]: ...
    def default(self, repository_id: UUID) -> RepositoryRef | None: ...
    def list_defaults(self) -> list[RepositoryRef]: ...
    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]: ...
    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]: ...


class SqlRepositoryRefRepository(SqlMutableRepository[RepositoryRef]):
    spec = REPOSITORY_REF
    record = RepositoryRef

    def get_for_update(self, repository_ref_id: UUID) -> RepositoryRef:
        stmt = self._select().where(self.table.c.id == repository_ref_id).with_for_update()
        row = self._execute(f"lock ref {repository_ref_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"repository ref {repository_ref_id}")
        return self._to_record(row)

    def get_or_add(self, record: RepositoryRef) -> RepositoryRef:
        named = record.name is not None
        return self._get_or_add(
            record,
            ("repository_id", "name", "sha") if named else ("repository_id", "sha"),
            lambda: self.find(record.repository_id, record.name, record.sha),
            index_where=self.table.c.name.is_not(None) if named else self.table.c.name.is_(None),
        )

    def find(self, repository_id: UUID, name: str | None, sha: str) -> RepositoryRef | None:
        c = self.table.c
        named = c.name.is_(None) if name is None else c.name == name
        return self._one(
            f"find {name or 'bare'}@{sha}", c.repository_id == repository_id, named, c.sha == sha
        )

    def list_for(
        self, repository_id: UUID, *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]:
        return self._many(
            f"list for {repository_id}",
            self.table.c.repository_id == repository_id,
            read_budget=read_budget,
        )

    def list_for_repositories(
        self, repository_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]:
        return self._many_in(
            "list for repositories",
            self.table.c.repository_id,
            repository_ids,
            read_budget=read_budget,
        )

    def list_by_ids(self, repository_ref_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in(
            f"list {len(repository_ref_ids)} by id", self.table.c.id, repository_ref_ids
        )

    def default(self, repository_id: UUID) -> RepositoryRef | None:
        """The latest ref named the default branch; legacy rows fall back to their
        creation time, which ordered namings before default_named_at existed."""
        c = self.table.c
        named = sa.func.coalesce(c.default_named_at, c.created_at)
        stmt = (
            self._select()
            .where(c.repository_id == repository_id, c.is_default.is_(True))
            .order_by(named.desc(), c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"default for {repository_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_defaults(self) -> list[RepositoryRef]:
        """Each repository's current default head, one row per repository with a named line;
        `default` for the whole fleet at once."""
        c = self.table.c
        named = sa.func.coalesce(c.default_named_at, c.created_at)
        ranked = (
            self._select()
            .add_columns(
                sa.func.row_number()
                .over(partition_by=c.repository_id, order_by=(named.desc(), c.created_at.desc()))
                .label("rank")
            )
            .where(c.is_default.is_(True))
            .subquery()
        )
        stmt = (
            sa.select(*(ranked.c[col.name] for col in self.table.columns))
            .where(ranked.c.rank == 1)
            .order_by(ranked.c.repository_id, ranked.c.created_at, ranked.c.id)
        )
        rows = self._execute("list default heads", stmt).mappings().all()
        return [self._to_record(row) for row in rows]

    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]:
        return self.list_for_manifest_sboms([sbom_id])

    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in("list for sboms", self.table.c.manifest_sbom_id, sbom_ids)
