import json
from datetime import UTC, datetime

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.feed_documents import FeedDocument, FeedDocumentManifest

AT = datetime(2026, 11, 17, tzinfo=UTC)


def test_a_manifest_round_trips_through_canonical_bytes() -> None:
    entry = FeedDocument(digest="a" * 64, acquired_at=AT)
    one = FeedDocumentManifest(source="nvd", documents={"CVE-2": entry, "CVE-1": entry})
    other = FeedDocumentManifest(source="nvd", documents={"CVE-1": entry, "CVE-2": entry})
    assert one.to_bytes() == other.to_bytes()  # identifier order never changes the bytes
    assert FeedDocumentManifest.from_bytes(one.to_bytes()) == other


def _entry(digest: str, at: str) -> bytes:
    entry = {"digest": digest, "acquired_at": at}
    return json.dumps({"source": "nvd", "documents": {"CVE-1": entry}}).encode()


@pytest.mark.parametrize(
    "raw",
    [
        b"{broken",
        b'{"source": "", "documents": {}}',
        _entry("short", "2026-11-17T00:00:00Z"),
        _entry("a" * 64, "2026-11-17T00:00:00"),  # no offset
        b'{"source": "nvd", "documents": {}, "extra": 1}',
    ],
)
def test_bytes_that_are_not_a_manifest_are_refused(raw: bytes) -> None:
    with pytest.raises(ValidationError, match=r"not a feed document manifest \(\d+ problem"):
        FeedDocumentManifest.from_bytes(raw)
