from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import Decision, ReviewItem
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    ReviewReason,
    SourceType,
    Validity,
)

CommentSourceName = NewType("CommentSourceName", str)
ExternalHandle = NewType("ExternalHandle", str)


class AttestationDecision(StrEnum):
    CONFIRM = "confirm"
    REJECT = "reject"


class TrustTier(StrEnum):
    RECORD = "record"
    QUEUE = "queue"


class Comment(Model):
    """What someone wrote in another system; `status` is a tracker transition, not free text."""

    source: SourceType
    author: ExternalHandle
    body: str
    at: datetime
    url: str | None = None
    bot: bool = False
    maintainer: bool = False
    status: str | None = None


class Statement(Model):
    """What one comment says about one finding, and whether it may be recorded as it stands."""

    source: SourceType
    author: ExternalHandle
    body: str
    url: str | None = None
    at: datetime
    trust: TrustTier
    finding_id: UUID | None = None
    label: str | None = None
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    reason: ReviewReason | None = None


class ImportReport(Model):
    recorded: tuple[Decision, ...] = ()
    queued: tuple[ReviewItem, ...] = ()
    unmatched: tuple[Statement, ...] = ()
    already_imported: int = 0
