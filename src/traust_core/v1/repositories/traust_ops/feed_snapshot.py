from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

FEED_SNAPSHOT = TableSpec(
    TRAUST_OPS,
    "feed_snapshot",
    lambda: (
        uuid_column("run_order_id", nullable=True),
        uuid_column("artifact_id"),
        text_column("feed"),
        timestamp_column("retrieved_at"),
    ),
    append_only=True,
)


class FeedSnapshotRepository(RecordRepository[FeedSnapshot], Protocol):
    def latest(self, feed: str) -> FeedSnapshot | None: ...

    def for_run_order(self, feed: str, run_order_id: UUID) -> FeedSnapshot | None:
        """The newest snapshot of a feed that a run order recorded."""
        ...


class SqlFeedSnapshotRepository(SqlAppendOnlyRepository[FeedSnapshot]):
    spec = FEED_SNAPSHOT
    record = FeedSnapshot

    def latest(self, feed: str) -> FeedSnapshot | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.feed == feed)
            .order_by(c.retrieved_at.desc(), c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"latest {feed}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def for_run_order(self, feed: str, run_order_id: UUID) -> FeedSnapshot | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.feed == feed, c.run_order_id == run_order_id)
            .order_by(c.retrieved_at.desc(), c.created_at.desc())
            .limit(1)
        )
        row = self._execute(f"{feed} for a run order", stmt).mappings().first()
        return None if row is None else self._to_record(row)
