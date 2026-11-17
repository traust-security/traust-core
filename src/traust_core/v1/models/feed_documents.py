"""A feed source's kept documents: the daily manifest naming each identifier's stored document."""

from __future__ import annotations

import json
from collections.abc import Mapping

import pydantic
from pydantic import AwareDatetime, Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model

_DIGEST = r"^[0-9a-f]{64}$"


class FeedDocument(Model):
    """One identifier's document in a manifest: its bytes' sha256 and when it was fetched."""

    digest: str = Field(pattern=_DIGEST)
    acquired_at: AwareDatetime


class FeedDocumentManifest(Model):
    """A source's documents on one refresh, by identifier; the bytes sit in the object store."""

    source: str = Field(min_length=1)
    documents: Mapping[str, FeedDocument]

    def to_bytes(self) -> bytes:
        # canonical: identical manifests are identical bytes, whatever the identifier order
        body = self.model_dump(mode="json")
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> FeedDocumentManifest:
        try:
            return cls.model_validate_json(raw)
        except pydantic.ValidationError as e:
            problems = e.error_count()
            raise ValidationError(f"not a feed document manifest ({problems} problem(s))") from e


class DocumentFailure(Model):
    identifier: str
    error: str


class DocumentRefresh(Model):
    """A refresh's outcome per identifier: fetched now, or failed; `carried` names the failed
    ones whose last manifest's document was kept instead."""

    source: str
    fetched: tuple[str, ...]
    failed: tuple[DocumentFailure, ...]
    carried: tuple[str, ...]


class AdvisoryDocumentsRefresh(Model):
    """One source's part of the advisory document refresh: how many identifiers it was asked
    for, and its refresh, or why the whole source failed (`error`)."""

    source: str
    requested: int
    refresh: DocumentRefresh | None = None
    error: str | None = None


class StoredDocument(Model):
    source: str
    identifier: str
    digest: str = Field(pattern=_DIGEST)
    acquired_at: AwareDatetime
    data: bytes
