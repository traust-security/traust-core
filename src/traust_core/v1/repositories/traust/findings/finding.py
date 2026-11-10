from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

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

    def list_for_advisory(self, advisory_id: UUID) -> list[Finding]:
        return self._many(
            f"list for advisory {advisory_id}", self.table.c.advisory_id == advisory_id
        )

    def list_by_ids(
        self, finding_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Finding]:
        return self._many_in("list by id", self.table.c.id, finding_ids, read_budget=read_budget)
