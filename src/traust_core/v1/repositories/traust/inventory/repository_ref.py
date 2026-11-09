from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.vocabulary import RefKind
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
    def list_by_ids(
        self, repository_ref_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]: ...
    def default(self, repository_id: UUID) -> RepositoryRef | None: ...
    def list_lines(
        self, repository_id: UUID | None = None, *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]: ...
    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]: ...
    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]: ...
    def list_with_manifest_sbom(self) -> list[RepositoryRef]: ...


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

    def list_by_ids(
        self, repository_ref_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]:
        return self._many_in(
            f"list {len(repository_ref_ids)} by id",
            self.table.c.id,
            repository_ref_ids,
            read_budget=read_budget,
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

    def list_lines(
        self, repository_id: UUID | None = None, *, read_budget: RecordBudget | None = None
    ) -> list[RepositoryRef]:
        """Each named branch line's latest ref — the tracked set's rows, one repository's or the
        fleet's. A line is attached by having a named branch ref at all; its latest commit is
        the newest naming or recording, never a tie."""
        c = self.table.c
        named = sa.func.coalesce(c.default_named_at, c.created_at)
        ranked = (
            self._select()
            .add_columns(
                sa.func.row_number()
                .over(
                    partition_by=sa.tuple_(c.repository_id, c.name),
                    order_by=(named.desc(), c.created_at.desc(), c.id.desc()),
                )
                .label("rank")
            )
            .where(c.kind == RefKind.BRANCH, c.name.is_not(None))
        )
        if repository_id is not None:
            ranked = ranked.where(c.repository_id == repository_id)
        latest = ranked.subquery()
        stmt = (
            sa.select(*(latest.c[col.name] for col in self.table.columns))
            .where(latest.c.rank == 1)
            .order_by(latest.c.repository_id, latest.c.name, latest.c.created_at, latest.c.id)
        )
        rows = self._execute(
            f"list lines{' of ' + str(repository_id) if repository_id else ''}", stmt
        ).mappings()
        tracked = [self._to_record(row) for row in rows]
        if read_budget is not None:
            read_budget.consume(len(tracked))
        return tracked

    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]:
        return self.list_for_manifest_sboms([sbom_id])

    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in("list for sboms", self.table.c.manifest_sbom_id, sbom_ids)

    def list_with_manifest_sbom(self) -> list[RepositoryRef]:
        """Every ref carrying a manifest SBOM, any line: what a stale tracked head is measured
        against (the partial index on manifest_sbom_id serves it)."""
        return self._many("list with manifest sbom", self.table.c.manifest_sbom_id.is_not(None))
