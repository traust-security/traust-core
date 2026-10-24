from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import (
    Decision,
    Disposition,
    ReviewCase,
    ReviewCaseKind,
    ReviewFilter,
    ReviewItem,
)
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason, Validity
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.facts import FindingFacts


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
        """What waits on a person, oldest first: every pending review item, and each finding whose
        fold awaits sign-off, overrode a false positive, blocks its reassertion or conflicts."""
        after = page.position()
        with self._uow as uow:
            pending = self.pending()
            if filter.repository_id is not None:
                findings = uow.findings.list_for_repository(filter.repository_id)
            else:
                candidates = uow.decisions.list_finding_ids_for_review()
                ids = {*candidates, *(i.finding_id for i in pending)}
                findings = uow.findings.list_by_ids(ids) if ids else []
            facts = FindingFacts.load(uow, findings, until=None)
        repository = {f.id: f.repository_id for f in findings}
        cases = [
            ReviewCase(
                kind=ReviewCaseKind.NEEDS_REVIEW,
                finding_id=i.finding_id,
                repository_id=repository[i.finding_id],
                since=i.created_at,  # type: ignore[arg-type]
                review_item=i,
            )
            for i in pending
            if i.finding_id in repository
        ]
        for finding in findings:
            assert finding.id is not None
            disposition = facts.disposition(finding.id, None)
            if disposition is not None and (kind := _attention(disposition)) is not None:
                cases.append(
                    ReviewCase(
                        kind=kind,
                        finding_id=finding.id,
                        repository_id=finding.repository_id,
                        since=disposition.last_decision_at,  # type: ignore[arg-type]
                        disposition=disposition,
                    )
                )
        kept = sorted((c for c in cases if filter.kind in (None, c.kind)), key=_oldest_first)
        if after is not None:
            kept = [c for c in kept if _oldest_first(c) > (after[0], str(after[1]))]
        return Page.of(kept, page.limit, key=lambda c: (c.since, _case_id(c)))

    def pending(self, limit: int | None = None) -> list[ReviewItem]:
        """Pending review items, oldest first, up to `limit`."""
        with self._uow as uow:
            return uow.review_items.pending(limit)

    def for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        with self._uow as uow:
            return uow.review_items.list_for_finding(finding_id)

    def get(self, review_item_id: UUID) -> ReviewItem:
        with self._uow as uow:
            return uow.review_items.get(review_item_id)

    def require_pending(self, review_item_id: UUID) -> ReviewItem:
        """The review item, still waiting on a person; ConflictError once it was answered."""
        item = self.get(review_item_id)
        if item.status != ReviewItemStatus.PENDING:
            raise ConflictError(f"review item {review_item_id} is already {item.status}")
        return item

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
            item = self.require_pending(review_item_id)
            closed = uow.review_items.update(
                item.model_copy(update={"status": status, "resolved_by_decision_id": decision_id})
            )
            uow.commit()
        return closed


def _attention(d: Disposition) -> ReviewCaseKind | None:
    """The worst fold state that needs a person, as countersign's queue ranked them."""
    if d.awaiting_signoff:
        return ReviewCaseKind.AWAITING_SIGNOFF
    if d.fp_overridden:
        return ReviewCaseKind.FP_OVERRIDDEN
    if d.fp_reassertion_blocked:
        return ReviewCaseKind.FP_REASSERTION_BLOCKED
    return ReviewCaseKind.CONFLICT if d.conflict else None


def _case_id(case: ReviewCase) -> UUID:
    item = case.review_item
    return item.id if item is not None and item.id is not None else case.finding_id


def _oldest_first(case: ReviewCase) -> tuple[datetime, str]:
    return (case.since, str(_case_id(case)))


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
