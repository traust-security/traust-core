from __future__ import annotations

from typing import Protocol
from uuid import UUID

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
    def list_from_repository(self, repository_id: UUID) -> list[Package]: ...
    def list_with_sbom(self, sbom_id: UUID) -> list[Package]: ...
    def get_or_add(self, record: Package) -> Package: ...


class SqlPackageRepository(SqlMutableRepository[Package]):
    spec = PACKAGE
    record = Package

    def find(self, ecosystem: str, name: str) -> Package | None:
        c = self.table.c
        return self._one(f"find {ecosystem}/{name}", c.ecosystem == ecosystem, c.name == name)

    def list_from_repository(self, repository_id: UUID) -> list[Package]:
        """Internal libraries the repository produces."""
        return self._many(
            f"list from {repository_id}", self.table.c.source_repository_id == repository_id
        )

    def list_with_sbom(self, sbom_id: UUID) -> list[Package]:
        """Image packages (base images) carrying this SBOM."""
        return self._many(f"list with sbom {sbom_id}", self.table.c.sbom_id == sbom_id)

    def get_or_add(self, record: Package) -> Package:
        return self._get_or_add(
            record, ("ecosystem", "name"), lambda: self.find(record.ecosystem, record.name)
        )
