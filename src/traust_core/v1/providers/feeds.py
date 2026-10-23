from __future__ import annotations

import gzip
import json
import zlib
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Protocol

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.dependencies import AdvisoryIdentifier, AdvisoryRecord
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher


class FeedStatus(Dto):
    name: str
    fetched_at: datetime | None = None
    max_age: timedelta
    last_error: str | None = None

    def stale(self, now: datetime) -> bool:
        return self.fetched_at is None or now - self.fetched_at > self.max_age


class FeedProvider(Protocol):
    """Fetches one feed's bytes; snapshots and staleness belong to feed_snapshot."""

    name: str
    filename: str
    max_age: timedelta

    def check(self) -> Readiness: ...

    def fetch(self) -> Result[bytes]: ...


class HttpFileFeed:
    """A feed published as one file at a URL (EPSS, KEV)."""

    def __init__(
        self,
        name: str,
        url: str,
        filename: str,
        max_age: timedelta,
        *,
        http: HttpFetcher,
        clock: Clock,
    ) -> None:
        self.name = name
        self.url = url
        self.filename = filename
        self.max_age = max_age
        self._http = http
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def fetch(self) -> Result[bytes]:
        data = self._http.get(self.url)
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), source=self.url
        )
        return Result(data, acquisition)


class AdvisoryLookup(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]: ...


def validate_payload(raw: bytes, filename: str) -> None:
    """Raise ValidationError when ``raw`` doesn't decode as ``filename``'s type.

    For feeds that publish no checksum, "corrupt" means "not well-formed gzip /
    JSON / UTF-8 CSV", so a garbage 200 never replaces a good cached copy.
    """
    suffixes = PurePosixPath(filename).suffixes
    try:
        if suffixes[-1:] == [".gz"]:
            raw = gzip.decompress(raw)
            suffixes = suffixes[:-1]
        if suffixes[-1:] == [".json"]:
            json.loads(raw)
        elif suffixes[-1:] == [".csv"]:
            raw.decode("utf-8")
    except (OSError, EOFError, ValueError, zlib.error) as e:
        raise ValidationError(f"{filename}: corrupt payload: {e}") from e
    if not raw:  # after decompression: an empty gzip body is an empty payload
        raise ValidationError(f"{filename}: empty payload")
