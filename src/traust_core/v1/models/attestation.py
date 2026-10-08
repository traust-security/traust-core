from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.base import Entity


class ReviewItem(Entity):
    subject_id: UUID
    reason: str


class Attestation(Entity):
    review_item_id: UUID
    actor: str
    verified: bool
    attested_at: datetime
