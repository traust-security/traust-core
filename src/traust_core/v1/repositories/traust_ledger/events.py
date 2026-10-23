from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.ledger import Event
from traust_core.v1.repositories.tables import (
    TRAUST_LEDGER,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    uuid_column,
)

EVENTS = TableSpec(
    TRAUST_LEDGER,
    "events",
    lambda: (
        uuid_column("layer_id"),
        uuid_column("decision_id"),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_payload", sa.LargeBinary, nullable=False),
    ),
    append_only=True,
)


class EventRepository(RecordRepository[Event], Protocol):
    def find_by_decision(self, decision_id: UUID) -> Event | None: ...
    def list_for_layer(self, layer_id: UUID) -> list[Event]: ...
    def last_seq(self, layer_id: UUID) -> int | None: ...
    def page_for_layer(self, layer_id: UUID, after: int | None, limit: int) -> list[Event]: ...


class SqlEventRepository(SqlAppendOnlyRepository[Event]):
    spec = EVENTS
    record = Event

    def find_by_decision(self, decision_id: UUID) -> Event | None:
        return self._one(f"find for {decision_id}", self.table.c.decision_id == decision_id)

    def list_for_layer(self, layer_id: UUID) -> list[Event]:
        c = self.table.c
        return self._many(f"list for {layer_id}", c.layer_id == layer_id, order_by=(c.seq,))

    def last_seq(self, layer_id: UUID) -> int | None:
        c = self.table.c
        stmt = sa.select(sa.func.max(c.seq)).where(c.layer_id == layer_id)
        return self._execute(f"last seq {layer_id}", stmt).scalar_one()  # type: ignore[no-any-return]

    def page_for_layer(self, layer_id: UUID, after: int | None, limit: int) -> list[Event]:
        c = self.table.c
        stmt = self._select().where(c.layer_id == layer_id).order_by(c.seq).limit(limit)
        if after is not None:
            stmt = stmt.where(c.seq > after)
        return [self._to_record(r) for r in self._execute(f"page {layer_id}", stmt).mappings()]
