from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ForbiddenError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    RecordDecision,
    ReviewFilter,
    ReviewItem,
    normalize_decision,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason, Validity
from traust_core.v1.repositories.contract import TraustUnitOfWork

if TYPE_CHECKING:
    from traust_core.v1.services.findings.decisions import FindingDecisions


class ReviewConfig(Model):
    valve_salt_env: str | None = None  # env var holding the audit-valve salt (a secret)


class ReviewPolicy:
    """Who must look before a machine verdict stands."""

    AUDIT_ONE_IN = 10
    _CLAIMED_LOW = frozenset({"low", "informational"})

    def __init__(self, valve_salt: str | None = None) -> None:
        self._salt = valve_salt

    def auto_accepts(
        self,
        votes: Mapping[str, int],
        confidence: float | None,
        claimed: str | None,
        lint_clean: bool,
    ) -> bool:
        """A machine FP may stand without countersign: at least two concurring FP votes and no
        dissent, a clean citation lint, confidence of 8 or more, a low / informational claim."""
        return (
            lint_clean
            and not votes.get("true_positive")
            and not votes.get("hardening")
            and votes.get("false_positive", 0) >= 2
            and (confidence or 0) >= 8
            and (claimed or "").strip().lower() in self._CLAIMED_LOW
        )

    def needs_signoff(self, decision: Decision) -> ReviewReason | None:
        """A salted 1-in-10 sample of auto-accepted FPs goes to a person; with no salt, all of them
        (an auto-accept tier without an audit valve isn't one)."""
        decision = normalize_decision(decision)
        if decision.validity != Validity.FALSE_POSITIVE or (decision.actor or "").startswith(
            "human:"
        ):
            return None
        if not decision.auto_accept_tier:
            return ReviewReason.ANALYST_REVIEW
        if self._salt is None:
            return ReviewReason.FP_AUDIT_VALVE
        digest = hmac.new(self._salt.encode(), decision.statement_key.encode(), hashlib.sha256)
        return (
            ReviewReason.FP_AUDIT_VALVE
            if int(digest.hexdigest(), 16) % self.AUDIT_ONE_IN == 0
            else None
        )


class FindingReview:
    def __init__(
        self, uow: TraustUnitOfWork, policy: ReviewPolicy, decisions: FindingDecisions
    ) -> None:
        self._uow = uow
        self._policy = policy
        self._decisions = decisions

    def queue(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]:
        filter = ReviewFilter.model_validate(dict(filter))
        page = PageRequest.model_validate(dict(page))
        after = page.position()
        if filter.reason is not None:
            contracts.validate_enum("review_reason", filter.reason)
        normalized = contracts.normalize_enum("review_item_status", filter.status)
        statuses = tuple(
            value
            for value in contracts.enum_values("review-item-status")
            if contracts.normalize_enum("review_item_status", value) == normalized
        )
        if not statuses:
            raise ValidationError(f"unknown review status: {filter.status!r}")
        with self._uow as uow:
            rows = [
                self._read(row)
                for row in uow.review_items.page(filter, after, page.limit + 1, statuses)
            ]
            return Page.of(rows, page.limit, lambda row: (row.created_at, row.id))

    def get(self, review_item_id: UUID) -> ReviewItem:
        with self._uow as uow:
            return self._read(uow.review_items.get(review_item_id))

    def for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        with self._uow as uow:
            uow.findings.get(finding_id)
            return [self._read(row) for row in uow.review_items.list_for_finding(finding_id)]

    def needs_signoff(self, decision: Decision) -> ReviewReason | None:
        return self._policy.needs_signoff(decision)

    def needs_review(self, finding_id: UUID) -> bool:
        with self._uow as uow:
            uow.findings.get(finding_id)
            if uow.review_items.has_pending(finding_id):
                return True
            history = uow.decisions.list_for_finding(finding_id)
            disposition = Disposition.fold(finding_id, history)
            return disposition.awaiting_signoff or disposition.fp_reassertion_blocked

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
        with self._uow.write() as uow:
            item = request(uow, finding_id, reason, decision_id)
            uow.commit()
            return self._read(item)

    def resolve(
        self,
        review_item_id: UUID,
        statement: RecordDecision,
        principal: Principal,
        *,
        status: ReviewItemStatus = ReviewItemStatus.ACCEPTED,
    ) -> ReviewItem:
        if statement is None:
            raise ValidationError("a review answer requires a decision on its finding")
        statement = RecordDecision.model_validate(dict(statement))
        principal = Principal.model_validate(dict(principal))
        if not principal.is_verified_human():
            raise ForbiddenError("a review answer needs a verified human")
        contracts.validate_enum("review_item_status", status)
        if status not in (ReviewItemStatus.ACCEPTED, ReviewItemStatus.REJECTED):
            raise ValidationError("a reviewed item must be accepted or rejected")
        with self._uow.write() as uow:
            known = uow.review_items.get(review_item_id)
            uow.findings.get_for_update(known.finding_id)
            item = self._read(uow.review_items.get_for_update(review_item_id))
            if statement.finding_id != item.finding_id:
                raise ValidationError("the resolving decision must judge the item's finding")
            if item.status not in (ReviewItemStatus.PENDING, status):
                raise ConflictError("review item is already closed")
            if item.status != ReviewItemStatus.PENDING:
                if item.resolved_by_decision_id is None:
                    raise ConflictError("review item is already closed")
                original = uow.decisions.get(item.resolved_by_decision_id)
                replay = Decision(
                    **statement.model_dump(exclude={"occurred_at"}),
                    actor=principal.ref,
                    occurred_at=statement.occurred_at or original.occurred_at,
                    statement_key="pending",
                )
                if (
                    self._decisions.statement_key(original) != self._decisions.statement_key(replay)
                    or (original.rationale or "").strip() != statement.rationale.strip()
                ):
                    raise ConflictError("review item is already closed")
            decision = self._decisions.decide(statement, principal)
            if (decision.rationale or "").strip() != statement.rationale.strip():
                raise ConflictError("this judgement already has a different recorded rationale")
            if item.status != ReviewItemStatus.PENDING:
                if item.resolved_by_decision_id == decision.id:
                    return item
                raise ConflictError("review item is already closed")
            saved = uow.review_items.update(
                item.model_copy(update={"status": status, "resolved_by_decision_id": decision.id})
            )
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


def request(
    uow: TraustUnitOfWork,
    finding_id: UUID,
    reason: ReviewReason,
    decision_id: UUID | None = None,
) -> ReviewItem:
    """The pending item for (finding, reason, proposal), inside the caller's write transaction."""
    contracts.validate_enum("review_reason", reason)
    uow.findings.get_for_update(finding_id)
    if decision_id is not None and uow.decisions.get(decision_id).finding_id != finding_id:
        raise ValidationError("review decisions must judge the item's finding")
    waiting = uow.review_items.find_pending(finding_id, reason, decision_id)
    if waiting is not None:
        return waiting
    return uow.review_items.add(
        ReviewItem(
            finding_id=finding_id,
            decision_id=decision_id,
            reason=reason,
            status=ReviewItemStatus.PENDING,
        )
    )
