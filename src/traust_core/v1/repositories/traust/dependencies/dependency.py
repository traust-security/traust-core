from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.dependencies import Dependency
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

DEPENDENCY = TableSpec(
    TRAUST,
    "dependency",
    lambda: (
        uuid_column("sbom_id"),
        uuid_column("package_id"),
        text_column("version"),
        sa.Column("direct", sa.Boolean, nullable=False),
    ),
    append_only=True,
)


class DependencyRepository(RecordRepository[Dependency], Protocol):
    def list_for_sbom(self, sbom_id: UUID) -> list[Dependency]: ...
    def list_for_package(self, package_id: UUID) -> list[Dependency]: ...
    def list_for_packages(self, package_ids: Collection[UUID]) -> list[Dependency]: ...
    def list_versions(self) -> list[tuple[UUID, str]]: ...
    def add_many(self, records: Sequence[Dependency]) -> None: ...


class SqlDependencyRepository(SqlAppendOnlyRepository[Dependency]):
    spec = DEPENDENCY
    record = Dependency

    def list_for_sbom(self, sbom_id: UUID) -> list[Dependency]:
        return self._many(f"list for sbom {sbom_id}", self.table.c.sbom_id == sbom_id)

    def list_for_package(self, package_id: UUID) -> list[Dependency]:
        """SBOMs that include the package (advisory sweep, usage query)."""
        return self.list_for_packages([package_id])

    def list_for_packages(self, package_ids: Collection[UUID]) -> list[Dependency]:
        return self._many_in("list for packages", self.table.c.package_id, package_ids)

    def list_versions(self) -> list[tuple[UUID, str]]:
        """Every package version any SBOM holds, once (the fleet advisory sweep)."""
        c = self.table.c
        stmt = sa.select(c.package_id, c.version).distinct()
        return [(row.package_id, row.version) for row in self._execute("list versions", stmt)]

    def add_many(self, records: Sequence[Dependency]) -> None:
        """Add the rows; one already stored is kept as it is."""
        self._add_missing("add dependencies", records, ("sbom_id", "package_id", "version"))
