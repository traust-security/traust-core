from __future__ import annotations

from collections.abc import Sequence
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
    def pending(self, limit: int) -> list[ReviewItem]: ...
    def page(
        self, filter: ReviewFilter, after: UUID | None, limit: int, statuses: Sequence[str]
    ) -> list[ReviewItem]: ...


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

    def pending(self, limit: int) -> list[ReviewItem]:
        c = self.table.c
        stmt = self._select().where(c.status == PENDING).order_by(c.created_at).limit(limit)
        return [self._to_record(r) for r in self._execute("pending", stmt).mappings()]

    def page(
        self, filter: ReviewFilter, after: UUID | None, limit: int, statuses: Sequence[str]
    ) -> list[ReviewItem]:
        c = self.table.c
        stmt = self._select().where(c.status.in_(statuses))
        if filter.finding_id is not None:
            stmt = stmt.where(c.finding_id == filter.finding_id)
        if filter.reason is not None:
            stmt = stmt.where(c.reason == filter.reason)
        if after is not None:
            row = self.get(after)
            stmt = stmt.where(sa.tuple_(c.created_at, c.id) > (row.created_at, row.id))
        stmt = stmt.order_by(c.created_at, c.id).limit(limit)
        return [self._to_record(r) for r in self._execute("page", stmt).mappings()]
