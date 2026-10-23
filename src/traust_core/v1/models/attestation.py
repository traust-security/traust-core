from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import NewType

from traust_core.v1.models.base import Model
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import SourceType

CommentSourceName = NewType("CommentSourceName", str)
ExternalHandle = NewType("ExternalHandle", str)


class AttestationDecision(StrEnum):
    CONFIRM = "confirm"
    REJECT = "reject"


# Members land with the Attestation slice (track-findings trust tiers).
class TrustTier(StrEnum): ...


class Comment(Model):
    source: SourceType
    author: ExternalHandle
    body: str
    at: datetime
    url: str | None = None


class Statement(Model):
    source: SourceType
    author: Principal | None = None
    body: str
    url: str | None = None
    at: datetime
    trust: TrustTier
