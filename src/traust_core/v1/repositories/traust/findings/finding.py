from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.errors import NotFoundError
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
        self, repository_id: UUID, fingerprint_algo: str, fingerprint: str
    ) -> Finding | None: ...

    def list_for_repository(self, repository_id: UUID) -> list[Finding]: ...
    def list_for_advisory(self, advisory_id: UUID) -> list[Finding]: ...


class SqlFindingRepository(SqlMutableRepository[Finding]):
    spec = FINDING
    record = Finding

    def get_for_update(self, finding_id: UUID) -> Finding:
        stmt = self._select().where(self.table.c.id == finding_id).with_for_update()
        row = self._execute(f"lock finding {finding_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"finding {finding_id}")
        return self._to_record(row)

    def find_by_fingerprint(
        self, repository_id: UUID, fingerprint_algo: str, fingerprint: str
    ) -> Finding | None:
        c = self.table.c
        return self._one(
            f"find {fingerprint_algo}:{fingerprint}",
            c.repository_id == repository_id,
            c.fingerprint_algo == fingerprint_algo,
            c.fingerprint == fingerprint,
        )

    def list_for_repository(self, repository_id: UUID) -> list[Finding]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)

    def list_for_advisory(self, advisory_id: UUID) -> list[Finding]:
        return self._many(
            f"list for advisory {advisory_id}", self.table.c.advisory_id == advisory_id
        )
