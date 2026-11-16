"""4 · Operations (traust_ops) - what traust ran, with what, and what it cost.

One repository per table. SQLite carries the namespace as the `ops_` prefix.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Protocol, Self

from traust_core.v1.repositories.traust_ops.assessment_input import (
    ASSESSMENT_INPUT,
    AssessmentInputRepository,
    SqlAssessmentInputRepository,
)
from traust_core.v1.repositories.traust_ops.feed_snapshot import (
    FEED_SNAPSHOT,
    FeedSnapshotRepository,
    SqlFeedSnapshotRepository,
)
from traust_core.v1.repositories.traust_ops.run_batch import (
    RUN_BATCH,
    RunBatchRepository,
    SqlRunBatchRepository,
)
from traust_core.v1.repositories.traust_ops.run_order import (
    RUN_ORDER,
    RunOrderRepository,
    SqlRunOrderRepository,
)
from traust_core.v1.repositories.traust_ops.spend_event import (
    SPEND_EVENT,
    SpendEventRepository,
    SqlSpendEventRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.models.operations import OrderQueryPosition, OrderQueryRequest, RunOrder

TABLES = (RUN_BATCH, RUN_ORDER, SPEND_EVENT, FEED_SNAPSHOT, ASSESSMENT_INPUT)


class OrderQueryReader(Protocol):
    """Composite order-history reads, including inventory's displayed reference."""

    def query(
        self, query: OrderQueryRequest, after: OrderQueryPosition | None
    ) -> list[tuple[RunOrder, str | None, str | int | None]]: ...


class OpsUnitOfWork(UnitOfWork, Protocol):
    run_batches: RunBatchRepository
    run_orders: RunOrderRepository
    order_reads: OrderQueryReader
    spend_events: SpendEventRepository
    feed_snapshots: FeedSnapshotRepository
    assessment_inputs: AssessmentInputRepository

    def write(self) -> AbstractContextManager[Self]: ...


__all__ = [
    "TABLES",
    "AssessmentInputRepository",
    "FeedSnapshotRepository",
    "OpsUnitOfWork",
    "OrderQueryReader",
    "RunBatchRepository",
    "RunOrderRepository",
    "SpendEventRepository",
    "SqlAssessmentInputRepository",
    "SqlFeedSnapshotRepository",
    "SqlRunBatchRepository",
    "SqlRunOrderRepository",
    "SqlSpendEventRepository",
]
