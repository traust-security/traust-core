from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.findings import ReviewItem
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

PENDING = "pending"  # classifier plan: ReviewItem.status; the partial index's predicate


class ReviewItemRepository(MutableRecordRepository[ReviewItem], Protocol):
    def list_for_finding(self, finding_id: UUID) -> list[ReviewItem]: ...
    def pending(self, limit: int) -> list[ReviewItem]: ...
    def find_pending(self, finding_id: UUID, reason: str) -> ReviewItem | None: ...


class SqlReviewItemRepository(SqlMutableRepository[ReviewItem]):
    spec = REVIEW_ITEM
    record = ReviewItem

    def list_for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        return self._many(f"list for {finding_id}", self.table.c.finding_id == finding_id)

    def pending(self, limit: int) -> list[ReviewItem]:
        c = self.table.c
        stmt = self._select().where(c.status == PENDING).order_by(c.created_at).limit(limit)
        return [self._to_record(r) for r in self._execute("pending", stmt).mappings()]

    def find_pending(self, finding_id: UUID, reason: str) -> ReviewItem | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.finding_id == finding_id, c.reason == reason, c.status == PENDING)
            .order_by(c.created_at)
            .limit(1)
        )
        row = self._execute(f"pending {reason} for {finding_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)
