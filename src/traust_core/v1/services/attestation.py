from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.attestation import Attestation, ReviewItem
from traust_core.v1.repositories.attestation import AttestationUnitOfWork


class AttestationService:
    def __init__(self, uow: AttestationUnitOfWork) -> None:
        self._uow = uow

    def request(self, subject_id: UUID, reason: str) -> ReviewItem:
        raise NotImplementedError("stub: replaces review-queue writes in countersign.py")

    def pending(self) -> list[ReviewItem]:
        raise NotImplementedError("stub: replaces countersign.py inbox")

    def attest(self, review_item_id: UUID, actor: str, verified: bool) -> Attestation:
        raise NotImplementedError(
            "stub: replaces countersign.py signoff and track-findings trust tiers"
        )
