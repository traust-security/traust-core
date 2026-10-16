from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Protocol, TypeVar

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.exposure import Advisory, Package, Version
from traust_core.v1.providers.base import Readiness, Result

Rec = TypeVar("Rec", covariant=True)


class FeedStatus(Dto):
    name: str
    fetched_at: datetime | None = None
    max_age: timedelta
    last_error: str | None = None

    def stale(self, now: datetime) -> bool:
        return self.fetched_at is None or now - self.fetched_at > self.max_age


class FeedProvider(Protocol[Rec]):
    name: str

    def check(self) -> Readiness: ...

    def refresh(self) -> FeedStatus: ...

    def status(self) -> FeedStatus: ...

    def read(self) -> Result[Rec]: ...


class AdvisoryLookup(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def query(self, package: Package, version: Version) -> Result[list[Advisory]]: ...


def validate_payload(raw: bytes, filename: str) -> None:
    """Raise ValidationError when ``raw`` doesn't decode as ``filename``'s type.

    For feeds that publish no checksum, "corrupt" means "not well-formed gzip /
    JSON / UTF-8 CSV", so a garbage 200 never replaces a good cached copy.
    """
    if not raw:
        raise ValidationError(f"{filename}: empty payload")
    suffixes = PurePosixPath(filename).suffixes
    try:
        if suffixes[-1:] == [".gz"]:
            raw = gzip.decompress(raw)
            suffixes = suffixes[:-1]
        if suffixes[-1:] == [".json"]:
            json.loads(raw)
        elif suffixes[-1:] == [".csv"]:
            raw.decode("utf-8")
    except (OSError, EOFError, ValueError) as e:
        raise ValidationError(f"{filename}: corrupt payload: {e}") from e
