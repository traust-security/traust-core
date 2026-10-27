from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
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
        text_column("sha"),
        uuid_column("manifest_sbom_id", nullable=True),
    ),
)


class RepositoryRefRepository(MutableRecordRepository[RepositoryRef], Protocol):
    def get_or_add(self, record: RepositoryRef) -> RepositoryRef: ...
    def find(self, repository_id: UUID, name: str | None, sha: str) -> RepositoryRef | None:
        """A named ref by (repository, name, sha); name None = the bare commit."""
        ...

    def list_for(self, repository_id: UUID) -> list[RepositoryRef]: ...
    def list_for_repositories(self, repository_ids: Collection[UUID]) -> list[RepositoryRef]: ...
    def list_by_ids(self, repository_ref_ids: Collection[UUID]) -> list[RepositoryRef]: ...
    def default(self, repository_id: UUID) -> RepositoryRef | None: ...
    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]: ...
    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]: ...


class SqlRepositoryRefRepository(SqlMutableRepository[RepositoryRef]):
    spec = REPOSITORY_REF
    record = RepositoryRef

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

    def list_for(self, repository_id: UUID) -> list[RepositoryRef]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)

    def list_for_repositories(self, repository_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in("list for repositories", self.table.c.repository_id, repository_ids)

    def list_by_ids(self, repository_ref_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in(
            f"list {len(repository_ref_ids)} by id", self.table.c.id, repository_ref_ids
        )

    def default(self, repository_id: UUID) -> RepositoryRef | None:
        """The latest ref recorded as the default branch."""
        c = self.table.c
        stmt = (
            self._select()
            .where(c.repository_id == repository_id, c.is_default.is_(True))
            .order_by(c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"default for {repository_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_for_manifest_sbom(self, sbom_id: UUID) -> list[RepositoryRef]:
        return self.list_for_manifest_sboms([sbom_id])

    def list_for_manifest_sboms(self, sbom_ids: Collection[UUID]) -> list[RepositoryRef]:
        return self._many_in("list for sboms", self.table.c.manifest_sbom_id, sbom_ids)
