from __future__ import annotations

from collections.abc import Callable, Collection
from typing import Protocol
from uuid import UUID

from sqlalchemy.engine import Connection

from traust_core.v1.models.findings import FindingExternalRef
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableFactory,
    TableSpec,
    text_column,
    uuid_column,
)

FINDING_EXTERNAL_REF = TableSpec(
    TRAUST,
    "finding_external_ref",
    lambda: (
        uuid_column("finding_id"),
        uuid_column("assessment_id", nullable=True),
        text_column("system"),
        text_column("ref"),
    ),
)


class FindingExternalRefRepository(MutableRecordRepository[FindingExternalRef], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRef]: ...
    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRef]: ...
    def list_for_findings(
        self, finding_ids: Collection[UUID], system: str | None = None
    ) -> list[FindingExternalRef]: ...
    def list_for_assessments(
        self, assessment_ids: Collection[UUID]
    ) -> list[FindingExternalRef]: ...


class SqlFindingExternalRefRepository(SqlMutableRepository[FindingExternalRef]):
    spec = FINDING_EXTERNAL_REF
    record = FindingExternalRef

    def __init__(
        self,
        connection: Connection,
        tables: TableFactory,
        *,
        pairing: Callable[[FindingExternalRef], None],
    ) -> None:
        super().__init__(connection, tables)
        self._pairing = pairing

    def add(self, record: FindingExternalRef) -> FindingExternalRef:
        record = self._to_record(record)
        self._pairing(record)
        return super().add(record)

    def update(self, record: FindingExternalRef) -> FindingExternalRef:
        record = self._to_record(record)
        self._pairing(record)
        return super().update(record)

    def list_for_finding(self, finding_id: UUID) -> list[FindingExternalRef]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_ref(self, system: str, ref: str) -> list[FindingExternalRef]:
        c = self.table.c
        return self._many(f"list {system}:{ref}", c.system == system, c.ref == ref)

    def list_for_findings(
        self, finding_ids: Collection[UUID], system: str | None = None
    ) -> list[FindingExternalRef]:
        c = self.table.c
        conditions = [c.finding_id.in_(finding_ids)]
        if system is not None:
            conditions.append(c.system == system)
        return self._many(f"list refs for {len(finding_ids)} findings", *conditions)

    def list_for_assessments(self, assessment_ids: Collection[UUID]) -> list[FindingExternalRef]:
        return self._many_in("list assessment links", self.table.c.assessment_id, assessment_ids)
