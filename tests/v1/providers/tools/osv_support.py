"""An OSV lookup answering from OSV records (dicts) for the osv scanner tests."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    PackageVersion,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.osv import OSV_NAMES, parse_osv

NOW = datetime(2026, 10, 27, 12, tzinfo=UTC)
CLOCK = FixedClock(NOW)
STAMP = "2026-10-27T12:00:00Z"
Key = tuple[str, str, str]


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class FakeLookup:
    base_url = "https://osv.test/v1"

    def __init__(
        self,
        ids: Mapping[Key, Sequence[str]] | None = None,
        records: Mapping[str, dict[str, Any]] | None = None,
        *,
        failing: Mapping[str, Exception] | None = None,
        hits: Callable[[list[Key]], AdvisoryHits] | None = None,
    ) -> None:
        self.ids = dict(ids or {})
        self.records = dict(records or {})
        self.failing = dict(failing or {})
        self.hits = hits
        self.asked: list[Key] = []
        self.fetched: list[str] = []

    def affecting(self, queries: Sequence[PackageVersion]) -> Result[AdvisoryHits]:
        keys = [
            (OSV_NAMES[Ecosystem(q.package.ecosystem)], q.package.name, str(q.version))
            for q in queries
        ]
        self.asked += keys
        found = (
            self.hits(keys)
            if self.hits
            else AdvisoryHits(ids=tuple(tuple(self.ids.get(k, ())) for k in keys))
        )
        return Result(found, Acquisition(provider="osv", acquired_at=NOW))

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        self.fetched.append(identifier)
        if identifier in self.failing:
            raise self.failing[identifier]
        raw = self.records.get(identifier)
        record = parse_osv(json.dumps(raw).encode(), f"osv:{identifier}") if raw else None
        return Result(record, Acquisition(provider="osv", acquired_at=NOW))
