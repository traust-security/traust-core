from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from uuid import UUID

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    ReviewCase,
    ReviewFilter,
    ReviewItem,
)
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason, Validity
from traust_core.v1.repositories.contract import TraustUnitOfWork


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
        if decision.validity != Validity.FALSE_POSITIVE or not decision.auto_accept_tier:
            return None
        if self._salt is None:
            return ReviewReason.FP_AUDIT_VALVE
        digest = hmac.new(self._salt.encode(), decision.statement_key.encode(), hashlib.sha256)
        return (
            ReviewReason.FP_AUDIT_VALVE
            if int(digest.hexdigest(), 16) % self.AUDIT_ONE_IN == 0
            else None
        )


class FindingReview:
    def __init__(self, uow: TraustUnitOfWork, policy: ReviewPolicy) -> None:
        self._uow = uow
        self._policy = policy

    def queue(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewCase]:
        raise NotImplementedError("stub: replaces countersign.discover_pending")

    def request_signoff(
        self, finding_id: UUID, reason: ReviewReason, decision_id: UUID | None = None
    ) -> ReviewItem:
        """Ask a person to look; a finding already waiting for the same reason waits once."""
        with self._uow as uow:
            item = request(uow, finding_id, reason, decision_id)
            uow.commit()
        return item

    def resolve(self, review_item_id: UUID, decision_id: UUID) -> ReviewItem:
        """A person answered with `decision_id`."""
        return self._close(review_item_id, ReviewItemStatus.CONFIRMED, decision_id)

    def reject(self, review_item_id: UUID) -> ReviewItem:
        """A person looked and nothing is recorded."""
        return self._close(review_item_id, ReviewItemStatus.REJECTED, None)

    def _close(
        self, review_item_id: UUID, status: ReviewItemStatus, decision_id: UUID | None
    ) -> ReviewItem:
        with self._uow as uow:
            item = uow.review_items.get(review_item_id)
            if item.status != ReviewItemStatus.PENDING:
                raise ConflictError(f"review item {review_item_id} is already {item.status}")
            closed = uow.review_items.update(
                item.model_copy(update={"status": status, "resolved_by_decision_id": decision_id})
            )
            uow.commit()
        return closed


def request(
    uow: TraustUnitOfWork,
    finding_id: UUID,
    reason: ReviewReason,
    decision_id: UUID | None = None,
) -> ReviewItem:
    """The pending item for (finding, reason), added if missing; inside the caller's work."""
    waiting = uow.review_items.find_pending(finding_id, reason)
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
