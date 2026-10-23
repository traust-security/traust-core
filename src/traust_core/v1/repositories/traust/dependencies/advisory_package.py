from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.dependencies import AdvisoryPackage
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    uuid_column,
)

ADVISORY_PACKAGE = TableSpec(
    TRAUST, "advisory_package", lambda: (uuid_column("advisory_id"), uuid_column("package_id"))
)


class AdvisoryPackageRepository(MutableRecordRepository[AdvisoryPackage], Protocol):
    def find(self, advisory_id: UUID, package_id: UUID) -> AdvisoryPackage | None: ...
    def list_for_advisory(self, advisory_id: UUID) -> list[AdvisoryPackage]: ...
    def list_for_package(self, package_id: UUID) -> list[AdvisoryPackage]: ...
    def get_or_add(self, record: AdvisoryPackage) -> AdvisoryPackage: ...


class SqlAdvisoryPackageRepository(SqlMutableRepository[AdvisoryPackage]):
    spec = ADVISORY_PACKAGE
    record = AdvisoryPackage

    def find(self, advisory_id: UUID, package_id: UUID) -> AdvisoryPackage | None:
        c = self.table.c
        return self._one(
            f"find {advisory_id}/{package_id}",
            c.advisory_id == advisory_id,
            c.package_id == package_id,
        )

    def list_for_advisory(self, advisory_id: UUID) -> list[AdvisoryPackage]:
        return self._many(f"list for {advisory_id}", self.table.c.advisory_id == advisory_id)

    def list_for_package(self, package_id: UUID) -> list[AdvisoryPackage]:
        return self._many(f"list for package {package_id}", self.table.c.package_id == package_id)

    def get_or_add(self, record: AdvisoryPackage) -> AdvisoryPackage:
        return self._get_or_add(
            record,
            ("advisory_id", "package_id"),
            lambda: self.find(record.advisory_id, record.package_id),
        )
