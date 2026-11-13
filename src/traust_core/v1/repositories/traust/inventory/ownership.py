from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.common import RecordBudget
from traust_core.v1.models.inventory import Ownership
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    timestamp_column,
    uuid_column,
)

OWNERSHIP = TableSpec(
    TRAUST,
    "ownership",
    lambda: (
        uuid_column("repository_id"),
        uuid_column("team_id"),
        timestamp_column("valid_from"),
        timestamp_column("valid_to", nullable=True),
    ),
)


class OwnershipRepository(MutableRecordRepository[Ownership], Protocol):
    def get_or_add(self, record: Ownership) -> Ownership: ...
    def find_current(self, repository_id: UUID, team_id: UUID) -> Ownership | None: ...
    def current(self, repository_id: UUID) -> list[Ownership]: ...
    def current_for_repositories(
        self, repository_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Ownership]: ...
    def as_of(self, repository_id: UUID, at: datetime) -> list[Ownership]: ...
    def as_of_for_repositories(
        self,
        repository_ids: Collection[UUID],
        at: datetime,
        *,
        read_budget: RecordBudget | None = None,
    ) -> list[Ownership]: ...
    def list_for_team(self, team_id: UUID) -> list[Ownership]: ...


class SqlOwnershipRepository(SqlMutableRepository[Ownership]):
    spec = OWNERSHIP
    record = Ownership

    def get_or_add(self, record: Ownership) -> Ownership:
        return self._get_or_add(
            record,
            ("repository_id", "team_id"),
            lambda: self.find_current(record.repository_id, record.team_id),
            index_where=self.table.c.valid_to.is_(None),
        )

    def find_current(self, repository_id: UUID, team_id: UUID) -> Ownership | None:
        c = self.table.c
        return self._one(
            f"current for {repository_id}/{team_id}",
            c.repository_id == repository_id,
            c.team_id == team_id,
            c.valid_to.is_(None),
        )

    def current(self, repository_id: UUID) -> list[Ownership]:
        c = self.table.c
        return self._many(
            f"current for {repository_id}", c.repository_id == repository_id, c.valid_to.is_(None)
        )

    def current_for_repositories(
        self, repository_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Ownership]:
        c = self.table.c
        rows = [
            row
            for batch in self._batches(repository_ids)
            for row in self._many(
                "current for repositories",
                c.repository_id.in_(batch),
                c.valid_to.is_(None),
                read_budget=read_budget,
            )
        ]
        return sorted(rows, key=lambda row: (row.created_at, row.id))

    def as_of(self, repository_id: UUID, at: datetime) -> list[Ownership]:
        c = self.table.c
        return self._many(
            f"as of {at} for {repository_id}",
            c.repository_id == repository_id,
            c.valid_from <= at,
            sa.or_(c.valid_to.is_(None), c.valid_to > at),
        )

    def as_of_for_repositories(
        self,
        repository_ids: Collection[UUID],
        at: datetime,
        *,
        read_budget: RecordBudget | None = None,
    ) -> list[Ownership]:
        c = self.table.c
        rows = [
            row
            for batch in self._batches(repository_ids)
            for row in self._many(
                f"as of {at} for {len(batch)} repositories",
                c.repository_id.in_(batch),
                c.valid_from <= at,
                sa.or_(c.valid_to.is_(None), c.valid_to > at),
                read_budget=read_budget,
            )
        ]
        return sorted(rows, key=lambda row: (row.created_at, row.id))

    def list_for_team(self, team_id: UUID) -> list[Ownership]:
        return self._many(f"list for team {team_id}", self.table.c.team_id == team_id)
