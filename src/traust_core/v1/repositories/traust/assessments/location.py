from __future__ import annotations

from collections.abc import Collection
from typing import Any, Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.findings import Location
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

LOCATION = TableSpec(
    TRAUST,
    "location",
    lambda: (
        uuid_column("occurrence_id"),
        text_column("path"),
        sa.Column("line_start", sa.Integer, nullable=True),
        sa.Column("line_end", sa.Integer, nullable=True),
        text_column("language", nullable=True),
        text_column("symbol", nullable=True),
    ),
    append_only=True,
)


class LocationRepository(RecordRepository[Location], Protocol):
    def list_for_occurrence(self, occurrence_id: UUID) -> list[Location]: ...
    def list_for_occurrences(self, occurrence_ids: Collection[UUID]) -> list[Location]: ...


class SqlLocationRepository(SqlAppendOnlyRepository[Location]):
    spec = LOCATION
    record = Location

    def list_for_occurrence(self, occurrence_id: UUID) -> list[Location]:
        c = self.table.c
        return self._many(
            f"list for {occurrence_id}",
            _of(c, c.occurrence_id == occurrence_id),
            order_by=(c.path, c.line_start),
        )

    def list_for_occurrences(self, occurrence_ids: Collection[UUID]) -> list[Location]:
        c = self.table.c
        return self._many(
            f"list for {len(occurrence_ids)} occurrences",
            _of(c, c.occurrence_id.in_(list(occurrence_ids))),
            order_by=(c.occurrence_id, c.path, c.line_start),
        )


def _of(c: Any, occurrences: sa.ColumnElement[bool]) -> sa.ColumnElement[bool]:
    """Postgres indexes location only by two partial unique indexes (line range, whole file);
    each arm implies one of their predicates, so the planner ORs them instead of a seq scan."""
    return sa.or_(
        sa.and_(occurrences, c.line_start.is_not(None)),
        sa.and_(occurrences, c.line_start.is_(None)),
    )
