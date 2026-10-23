from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.attestation import (
    AttestationDecision,
    Comment,
    CommentSourceName,
    Statement,
    TrustTier,
)
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.findings import Decision, ReviewFilter, ReviewItem
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import Ownership
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.vocabulary import ReviewReason
from traust_core.v1.providers.collaboration import CommentSource
from traust_core.v1.repositories.traust.findings import FindingsUnitOfWork
from traust_core.v1.services.ledger import LedgerService


class StatementPolicy:
    def trust(
        self, comment: Comment, author: Principal | None, ownership: Ownership | None
    ) -> TrustTier:
        raise NotImplementedError("stub: replaces track-findings human-statement trust tiers")


class AttestationService:
    def __init__(
        self,
        uow: FindingsUnitOfWork,
        ledger: LedgerService | None,
        comments: CommentSource,
        policy: StatementPolicy,
    ) -> None:
        self._uow = uow
        self._ledger = ledger
        self._comments = comments
        self._policy = policy

    def request(
        self, finding_id: UUID, decision_id: UUID | None, reason: ReviewReason
    ) -> ReviewItem:
        raise NotImplementedError("stub: replaces countersign inbox writes, fleet-fix batch review")

    def attest(
        self,
        review_item_id: UUID,
        principal: Principal,
        decision: AttestationDecision,
        statement: Statement | None,
    ) -> Decision:
        """A human answer is a decision (actor set) that resolves the review item."""
        raise NotImplementedError("stub: replaces countersign.py, ledger cli countersign")

    def import_statements(self, source: CommentSourceName, ref: ExternalRef) -> list[Decision]:
        raise NotImplementedError("stub: replaces track-findings MR/Jira comment reads")

    def pending(self, filter: ReviewFilter, page: PageRequest) -> Page[ReviewItem]:
        raise NotImplementedError("stub: replaces countersign.discover_pending")

    def for_finding(self, finding_id: UUID) -> list[ReviewItem]:
        raise NotImplementedError("stub: replaces countersign baseline_for")
