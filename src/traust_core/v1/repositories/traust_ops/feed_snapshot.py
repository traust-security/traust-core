from __future__ import annotations

from datetime import datetime
from typing import Protocol

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
    def latest(self, feed: str, as_of: datetime | None = None) -> FeedSnapshot | None: ...


class SqlFeedSnapshotRepository(SqlAppendOnlyRepository[FeedSnapshot]):
    spec = FEED_SNAPSHOT
    record = FeedSnapshot

    def latest(self, feed: str, as_of: datetime | None = None) -> FeedSnapshot | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.feed == feed)
            .order_by(c.retrieved_at.desc(), c.created_at.desc())
            .limit(1)
        )
        if as_of is not None:
            stmt = stmt.where(c.retrieved_at <= as_of)
        row = self._execute(f"latest {feed}", stmt).mappings().first()
        return None if row is None else self._to_record(row)
