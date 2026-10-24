from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.dependencies import Package
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

PACKAGE = TableSpec(
    TRAUST,
    "package",
    lambda: (
        uuid_column("source_repository_id", nullable=True),
        uuid_column("sbom_id", nullable=True),
        text_column("ecosystem"),
        text_column("name"),
    ),
)


class PackageRepository(MutableRecordRepository[Package], Protocol):
    def find(self, ecosystem: str, name: str) -> Package | None: ...
    def list_by_ids(self, package_ids: Collection[UUID]) -> list[Package]: ...
    def list_from_repository(self, repository_id: UUID) -> list[Package]: ...
    def list_with_sbom(self, sbom_id: UUID) -> list[Package]: ...
    def list_with_sboms(self, sbom_ids: Collection[UUID]) -> list[Package]: ...
    def get_or_add(self, record: Package) -> Package: ...
    def get_or_add_many(self, records: Sequence[Package]) -> list[Package]: ...
    def list_from_repositories(self, repository_ids: Collection[UUID]) -> list[Package]: ...


class SqlPackageRepository(SqlMutableRepository[Package]):
    spec = PACKAGE
    record = Package

    def find(self, ecosystem: str, name: str) -> Package | None:
        c = self.table.c
        return self._one(f"find {ecosystem}/{name}", c.ecosystem == ecosystem, c.name == name)

    def list_by_ids(self, package_ids: Collection[UUID]) -> list[Package]:
        return self._many_in("list by ids", self.table.c.id, package_ids)

    def list_from_repository(self, repository_id: UUID) -> list[Package]:
        """Internal libraries the repository produces."""
        return self._many(
            f"list from {repository_id}", self.table.c.source_repository_id == repository_id
        )

    def list_with_sbom(self, sbom_id: UUID) -> list[Package]:
        """Image packages (base images) carrying this SBOM."""
        return self.list_with_sboms([sbom_id])

    def list_with_sboms(self, sbom_ids: Collection[UUID]) -> list[Package]:
        return self._many_in("list with sboms", self.table.c.sbom_id, sbom_ids)

    def get_or_add(self, record: Package) -> Package:
        return self._get_or_add(
            record, ("ecosystem", "name"), lambda: self.find(record.ecosystem, record.name)
        )

    def get_or_add_many(self, records: Sequence[Package]) -> list[Package]:
        """The stored package for each record, in order, adding those not seen yet."""
        unique = list({(r.ecosystem, r.name): r for r in records}.values())
        self._add_missing("get or add packages", unique, ("ecosystem", "name"))
        c = self.table.c
        found = {
            (p.ecosystem, p.name): p
            for p in self._many_in(
                "find packages",
                sa.tuple_(c.ecosystem, c.name),
                [(r.ecosystem, r.name) for r in unique],
            )
        }
        return [found[(r.ecosystem, r.name)] for r in records]

    def list_from_repositories(self, repository_ids: Collection[UUID]) -> list[Package]:
        """Internal libraries the repositories produce."""
        return self._many_in(
            "list from repositories", self.table.c.source_repository_id, repository_ids
        )
