from __future__ import annotations

from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ValidationError
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    ReviewFilter,
    ReviewItem,
)
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason, TenancyProfile
from traust_core.v1.repositories.contract import TraustUnitOfWork


class ReviewPolicy:
    def needs_signoff(
        self, decision: Decision, disposition: Disposition, profile: TenancyProfile
    ) -> ReviewReason | None:
        raise NotImplementedError(
            "stub: replaces emit_triage is_auto_accept, track-findings countersign rule"
        )


class FindingReview:
    def __init__(self, uow: TraustUnitOfWork, policy: ReviewPolicy) -> None:
        self._uow = uow
        self._policy = policy

    def queue(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]:
        filter = ReviewFilter.model_validate(dict(filter))
        page = PageRequest.model_validate(dict(page))
        if page.limit < 1:
            raise ValidationError("review page limit must be positive")
        try:
            after = UUID(page.cursor) if page.cursor is not None else None
        except ValueError as error:
            raise ValidationError("invalid review queue cursor") from error
        normalized = contracts.normalize_enum("review_item_status", filter.status)
        statuses = tuple(
            value
            for value in contracts.enum_values("review-item-status")
            if contracts.normalize_enum("review_item_status", value) == normalized
        )
        if not statuses:
            raise ValidationError(f"unknown review status: {filter.status!r}")
        with self._uow as uow:
            rows = uow.review_items.page(filter, after, page.limit + 1, statuses)
            items = tuple(self._read(row) for row in rows[: page.limit])
            cursor = Cursor(str(items[-1].id)) if len(rows) > page.limit else None
            return Page(items=items, next=cursor)

    def get(self, review_item_id: UUID) -> ReviewItem:
        with self._uow as uow:
            return self._read(uow.review_items.get(review_item_id))

    def record(self, item: ReviewItem) -> ReviewItem:
        """Create a review item using canonical classifiers, never historical spellings."""
        item = ReviewItem.model_validate(dict(item))
        if any(value is not None for value in (item.id, item.created_at, item.updated_at)):
            raise ValidationError("new review items cannot supply database identity or timestamps")
        self._validate(item)
        with self._uow as uow:
            uow.findings.get(item.finding_id)
            for decision_id in (item.decision_id, item.resolved_by_decision_id):
                if decision_id is not None:
                    decision = uow.decisions.get(decision_id)
                    if decision.finding_id != item.finding_id:
                        raise ValidationError("review decisions must judge the item's finding")
            saved = uow.review_items.add(item)
            uow.commit()
            return saved

    def import_item(self, item: ReviewItem, *, resolution_note: str | None = None) -> ReviewItem:
        """Project a historical source item without modifying its retained source artifact."""
        item = ReviewItem.model_validate(dict(item))
        item = self._read(item)
        if item.status == ReviewItemStatus.REJECTED and (resolution_note or "").startswith(
            "bulk-closed"
        ):
            item = item.model_copy(update={"status": ReviewItemStatus.CLOSED_UNREVIEWED})
        return self.record(item)

    def request_signoff(
        self, finding_id: UUID, reason: ReviewReason, *, decision_id: UUID | None = None
    ) -> ReviewItem:
        contracts.validate_enum("review_reason", reason)
        with self._uow as uow:
            for row in uow.review_items.list_for_finding(finding_id):
                if (
                    row.status == ReviewItemStatus.PENDING
                    and row.reason == reason
                    and row.decision_id == decision_id
                ):
                    return self._read(row)
            item = ReviewItem(
                finding_id=finding_id,
                decision_id=decision_id,
                reason=reason,
                status=ReviewItemStatus.PENDING,
            )
            saved = self.record(item)
            uow.commit()
            return saved

    def resolve(
        self,
        review_item_id: UUID,
        decision_id: UUID,
        *,
        status: ReviewItemStatus = ReviewItemStatus.ACCEPTED,
    ) -> ReviewItem:
        contracts.validate_enum("review_item_status", status)
        if status not in (ReviewItemStatus.ACCEPTED, ReviewItemStatus.REJECTED):
            raise ValidationError("a reviewed item must be accepted or rejected")
        with self._uow.write() as uow:
            item = self._read(uow.review_items.get_for_update(review_item_id))
            decision = uow.decisions.get(decision_id)
            if decision.finding_id != item.finding_id:
                raise ValidationError("the resolving decision must judge the item's finding")
            if decision.assessment_id is not None or not (decision.actor or "").startswith(
                ("user:", "human:")
            ):
                raise ValidationError("a review requires a human decision")
            if item.status != ReviewItemStatus.PENDING:
                if item.status == status and item.resolved_by_decision_id == decision_id:
                    return item
                raise ConflictError("review item is already closed")
            item = item.model_copy(
                update={"status": status, "resolved_by_decision_id": decision_id}
            )
            self._validate(item)
            saved = uow.review_items.update(item)
            uow.commit()
            return saved

    def close_unreviewed(self, review_item_id: UUID) -> ReviewItem:
        with self._uow.write() as uow:
            item = self._read(uow.review_items.get_for_update(review_item_id))
            if item.status == ReviewItemStatus.CLOSED_UNREVIEWED:
                return item
            if item.status != ReviewItemStatus.PENDING:
                raise ConflictError("review item is already closed")
            item = item.model_copy(update={"status": ReviewItemStatus.CLOSED_UNREVIEWED})
            self._validate(item)
            saved = uow.review_items.update(item)
            uow.commit()
            return saved

    @staticmethod
    def _validate(item: ReviewItem) -> None:
        contracts.validate_enum("review_item_status", item.status)
        if item.reason is not None:
            contracts.validate_enum("review_reason", item.reason)
        if (
            item.status in (ReviewItemStatus.PENDING, ReviewItemStatus.CLOSED_UNREVIEWED)
            and item.resolved_by_decision_id is not None
        ):
            raise ValidationError("an unreviewed item cannot identify a resolving decision")

    @staticmethod
    def _read(item: ReviewItem) -> ReviewItem:
        values = dict(item)
        for field, name in (("status", "review_item_status"), ("reason", "review_reason")):
            if (value := values[field]) is not None:
                normalized = contracts.normalize_enum(name, value)
                values[field] = next((p.value for p in normalized.pairs if p.enum == name), value)
        return ReviewItem.model_validate(values)
