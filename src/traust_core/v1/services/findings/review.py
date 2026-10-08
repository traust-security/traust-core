from __future__ import annotations

from uuid import UUID

from traust_core.v1.repositories.findings import FindingUnitOfWork


class FindingReview:
    def __init__(self, uow: FindingUnitOfWork) -> None:
        self._uow = uow

    def needs_review(self) -> list[UUID]:
        raise NotImplementedError("stub: replaces countersign.py inbox derivation")

    def apply_attestation(self, finding_id: UUID, attestation_id: UUID) -> None:
        raise NotImplementedError("stub: replaces countersign.py, traust-ledger resolve_handler.py")
