from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.operations import RunBatch
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
)

RUN_BATCH = TableSpec(TRAUST_OPS, "run_batch", lambda: (text_column("kind"), text_column("period")))


class RunBatchRepository(MutableRecordRepository[RunBatch], Protocol):
    def find(self, kind: str, period: str) -> RunBatch | None: ...


class SqlRunBatchRepository(SqlMutableRepository[RunBatch]):
    spec = RUN_BATCH
    record = RunBatch

    def find(self, kind: str, period: str) -> RunBatch | None:
        """The batch for (kind, period), oldest first: (kind, period) carries no unique index,
        so a concurrent create can leave a second, empty one — the oldest is the one holding
        the orders."""
        c = self.table.c
        stmt = (
            self._select()
            .where(c.kind == kind, c.period == period)
            .order_by(c.created_at, c.id)
            .limit(1)
        )
        row = self._execute(f"find {kind}/{period}", stmt).mappings().first()
        return None if row is None else self._to_record(row)
