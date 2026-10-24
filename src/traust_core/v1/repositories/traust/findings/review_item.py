from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from types import EllipsisType
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.findings import ReviewFilter, ReviewItem
from traust_core.v1.models.vocabulary import ReviewItemStatus
from traust_core.v1.repositories.tables import (
    TRAUST,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

REVIEW_ITEM = TableSpec(
    TRAUST,
    "review_item",
    lambda: (
        uuid_column("finding_id"),
        uuid_column("decision_id", nullable=True),
        uuid_column("resolved_by_decision_id", nullable=True),
        text_column("reason", nullable=True),
        text_column("status"),
    ),
)

PENDING = ReviewItemStatus.PENDING


class ReviewItemRepository(MutableRecordRepository[ReviewItem], Protocol):
    def get_for_update(self, review_item_id: UUID) -> ReviewItem: ...

    def list_for_finding(self, finding_id: UUID) -> list[ReviewItem]: ...
    def pending(self, limit: int | None = None) -> list[ReviewItem]:
        """Pending items oldest first; every one of them when `limit` is None."""
        ...

    def page(
        self,
        filter: ReviewFilter,
        after: tuple[datetime, UUID] | None,
        limit: int,
        statuses: Sequence[str],
    ) -> list[ReviewItem]: ...
    def find_pending(
        self, finding_id: UUID, reason: str, decision_id: UUID | EllipsisType | None = ...
    ) -> ReviewItem | None: ...
    def has_pending(self, finding_id: UUID) -> bool: ...


class SqlReviewItemRepository(SqlMutableRepository[ReviewItem]):
    spec = REVIEW_ITEM
    record = ReviewItem

    def get_for_update(self, review_item_id: UUID) -> ReviewItem:
        stmt = self._select().where(self.table.c.id == review_item_id).with_for_update()
        row = self._execute(f"lock review item {review_item_id}", stmt).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"review item {review_item_id}")
        return self._to_record(row)

    def list_for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def pending(self, limit: int | None = None) -> list[ReviewItem]:
        c = self.table.c
        stmt = self._select().where(c.status == PENDING).order_by(c.created_at).limit(limit)
        return [self._to_record(r) for r in self._execute("pending", stmt).mappings()]

    def page(
        self,
        filter: ReviewFilter,
        after: tuple[datetime, UUID] | None,
        limit: int,
        statuses: Sequence[str],
    ) -> list[ReviewItem]:
        c = self.table.c
        stmt = self._select().where(c.status.in_(statuses))
        if filter.finding_id is not None:
            stmt = stmt.where(c.finding_id == filter.finding_id)
        if filter.reason is not None:
            stmt = stmt.where(c.reason == filter.reason)
        if after is not None:
            stmt = stmt.where(sa.tuple_(c.created_at, c.id) > after)
        stmt = stmt.order_by(c.created_at, c.id).limit(limit)
        return [self._to_record(r) for r in self._execute("page", stmt).mappings()]

    def find_pending(
        self, finding_id: UUID, reason: str, decision_id: UUID | EllipsisType | None = ...
    ) -> ReviewItem | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(
                c.finding_id == finding_id,
                c.reason == reason,
                c.status == PENDING,
            )
            .where(c.decision_id == decision_id if decision_id is not ... else sa.true())
            .order_by(c.created_at)
            .limit(1)
        )
        row = self._execute(f"pending {reason} for {finding_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def has_pending(self, finding_id: UUID) -> bool:
        c = self.table.c
        stmt = sa.select(sa.exists().where(c.finding_id == finding_id, c.status == PENDING))
        return bool(self._execute(f"has pending for {finding_id}", stmt).scalar_one())
