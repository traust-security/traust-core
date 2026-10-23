from __future__ import annotations

from collections.abc import Collection
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.operations import OPEN_ORDER_STATES, OrderState, RunOrder
from traust_core.v1.repositories.tables import (
    TRAUST_OPS,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

RUN_ORDER = TableSpec(
    TRAUST_OPS,
    "run_order",
    lambda: (
        uuid_column("run_batch_id", nullable=True),
        uuid_column("repository_id", nullable=True),
        uuid_column("artifact_id", nullable=True),
        text_column("rule", nullable=True),
        text_column("event_source", nullable=True),
        text_column("asset"),
        text_column("lane", nullable=True),
        text_column("state"),
        sa.Column("priority", sa.Integer, nullable=False),
        text_column("reason", nullable=True),
        text_column("requested_by"),
        text_column("lease_holder", nullable=True),
        timestamp_column("lease_expires_at", nullable=True),
        timestamp_column("started_at", nullable=True),
        timestamp_column("finished_at", nullable=True),
    ),
)


class RunOrderRepository(MutableRecordRepository[RunOrder], Protocol):
    def claim(self, worker: str, now: datetime, lease_for: timedelta) -> RunOrder | None:
        """Lease the next queued order (priority, then age); None when the queue is empty."""
        ...

    def get_for_update(self, order_id: UUID) -> RunOrder:
        """Read and row-lock an order until the transaction ends."""
        ...

    def requeue_expired(self, now: datetime) -> int: ...
    def list_for_batch(self, run_batch_id: UUID) -> list[RunOrder]: ...
    def list_for_repository(self, repository_id: UUID, state: OrderState) -> list[RunOrder]: ...
    def find_open(self, asset: str, repository_id: UUID | None) -> RunOrder | None:
        """An open order (planned through leased) for an asset and repository, if any."""
        ...

    def subjects(
        self, asset: str, states: Collection[OrderState], finished_after: datetime | None = None
    ) -> set[UUID | None]:
        """Repositories (None = fleet-wide) with an order of `asset` in `states`."""
        ...

    def search(
        self,
        *,
        states: Collection[OrderState] = (),
        asset: str | None = None,
        repository_id: UUID | None = None,
        run_batch_id: UUID | None = None,
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[RunOrder]: ...


class SqlRunOrderRepository(SqlMutableRepository[RunOrder]):
    spec = RUN_ORDER
    record = RunOrder

    def claim(self, worker: str, now: datetime, lease_for: timedelta) -> RunOrder | None:
        c = self.table.c
        # SKIP LOCKED on Postgres; SQLite serialises writers and drops FOR UPDATE.
        next_id = (
            sa.select(c.id)
            .where(c.state == OrderState.QUEUED)
            .order_by(c.priority, c.created_at, c.id)
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            sa.update(self.table)
            .where(c.id == next_id, c.state == OrderState.QUEUED)
            .values(
                state=OrderState.LEASED,
                lease_holder=worker,
                lease_expires_at=now + lease_for,
                started_at=now,
            )
            .returning(c.id)
        )
        claimed = self._execute(f"claim for {worker}", stmt).scalar_one_or_none()
        return None if claimed is None else self.get(claimed)

    def get_for_update(self, order_id: UUID) -> RunOrder:
        stmt = self._select().where(self.table.c.id == order_id).with_for_update()
        row = self._execute(f"lock {order_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"run_order {order_id}")
        return self._to_record(row)

    def requeue_expired(self, now: datetime) -> int:
        """Return expired leases to the queue; the count requeued."""
        c = self.table.c
        stmt = (
            sa.update(self.table)
            .where(c.state == OrderState.LEASED, c.lease_expires_at < now)
            .values(state=OrderState.QUEUED, lease_holder=None, lease_expires_at=None)
        )
        return self._execute(f"requeue expired at {now}", stmt).rowcount

    def list_for_batch(self, run_batch_id: UUID) -> list[RunOrder]:
        return self._many(
            f"list for batch {run_batch_id}", self.table.c.run_batch_id == run_batch_id
        )

    def list_for_repository(self, repository_id: UUID, state: OrderState) -> list[RunOrder]:
        c = self.table.c
        return self._many(
            f"list {state} for {repository_id}",
            c.repository_id == repository_id,
            c.state == state,
            order_by=(c.priority,),
        )

    def find_open(self, asset: str, repository_id: UUID | None) -> RunOrder | None:
        c = self.table.c
        subject = (
            c.repository_id.is_(None) if repository_id is None else c.repository_id == repository_id
        )
        stmt = (
            self._select().where(c.asset == asset, c.state.in_(OPEN_ORDER_STATES), subject).limit(1)
        )
        row = self._execute(f"find open {asset} for {repository_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def search(
        self,
        *,
        states: Collection[OrderState] = (),
        asset: str | None = None,
        repository_id: UUID | None = None,
        run_batch_id: UUID | None = None,
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[RunOrder]:
        c = self.table.c
        conditions = [
            cond
            for value, cond in (
                (states, c.state.in_(list(states))),
                (asset, c.asset == asset),
                (repository_id, c.repository_id == repository_id),
                (run_batch_id, c.run_batch_id == run_batch_id),
            )
            if value
        ]
        return self._page("search", *conditions, limit=limit, after=after)

    def subjects(
        self, asset: str, states: Collection[OrderState], finished_after: datetime | None = None
    ) -> set[UUID | None]:
        c = self.table.c
        where = [c.asset == asset, c.state.in_(list(states))]
        if finished_after is not None:
            where.append(c.finished_at > finished_after)
        stmt = sa.select(c.repository_id).where(*where).distinct()
        return set(self._execute(f"subjects of {asset}", stmt).scalars())
