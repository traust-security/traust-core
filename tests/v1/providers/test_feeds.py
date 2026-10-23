import gzip
from datetime import UTC, datetime, timedelta

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import HttpFileFeed, validate_payload

AT = datetime(2026, 10, 22, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (gzip.compress(b"cve,epss\n", mtime=0), "epss_scores-current.csv.gz"),
        (b'{"a": 1}', "known_exploited_vulnerabilities.json"),
        (gzip.compress(b"[]", mtime=0), "index.json.gz"),
        (b"anything", "archive_latest.txt"),
    ],
)
def test_well_formed_payload_passes(raw: bytes, filename: str) -> None:
    validate_payload(raw, filename)


@pytest.mark.parametrize(
    ("raw", "filename"),
    [
        (b"", "kev.json"),
        (b"not a gzip payload", "epss.csv.gz"),
        (b"{broken", "kev.json"),
        (b"\xff\xfe", "rh-cve.csv"),
        (gzip.compress(b"", mtime=0), "epss_scores-current.csv.gz"),
        (gzip.compress(b"cve,epss\n", mtime=0)[:10] + b"\xff\xff", "epss_scores-current.csv.gz"),
    ],
)
def test_corrupt_payload_raises(raw: bytes, filename: str) -> None:
    with pytest.raises(ValidationError):
        validate_payload(raw, filename)


class _Fetcher:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        return self.body


def test_http_file_feed_fetches_its_url_with_provenance() -> None:
    fetcher = _Fetcher(b"payload")
    url = "https://feeds.test/epss_scores-current.csv.gz"
    feed = HttpFileFeed(
        "epss",
        url,
        "epss_scores-current.csv.gz",
        timedelta(hours=24),
        http=fetcher,  # type: ignore[arg-type]
        clock=FixedClock(AT),
    )
    result = feed.fetch()
    assert result.data == b"payload" and fetcher.urls == [url]
    assert result.acquisition.provider == "epss"
    assert result.acquisition.source == url and result.acquisition.acquired_at == AT
    assert feed.check().ready
