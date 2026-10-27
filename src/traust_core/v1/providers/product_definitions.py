"""The product-definitions registry's pull-through cache (`traust feeds fetch-products` fills it):
`product_definitions.json` and its `feeds-meta.json` entry in the feeds cache directory."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.models.product_definitions import (
    DEFINITION_KEYS,
    ProductDefinitionsSnapshot,
    ProductSource,
    ProductSourceStatus,
)
from traust_core.v1.providers.clock import Clock

FEED = "product-definitions"
FILENAME = "product_definitions.json"
# Example URL only: operators point the fetch at their registry; nothing VPN-only ships.
URL = "https://example.com/product-definitions/products.json"
MAX_AGE_HOURS = 24.0 * 30


class ProductDefinitionsCache:
    def __init__(self, cache_dir: Path | None, clock: Clock) -> None:
        self._dir = cache_dir
        self._clock = clock

    def read(self) -> ProductDefinitionsSnapshot:
        """The cached registry and its freshness. A missing or malformed cache is `unavailable`
        with the reason: the registry is an optional corroborating source, never a failed run."""
        if self._dir is None:
            return _unavailable("feeds cache not configured")
        try:
            document = json.loads((self._dir / FILENAME).read_text(encoding="utf-8"))
            missing = [k for k in DEFINITION_KEYS if not isinstance(document.get(k), dict)]
            if missing:
                raise ValueError(
                    "product-definitions cache is missing/malformed top-level key(s): "
                    + ", ".join(missing)
                )
        except (OSError, ValueError, AttributeError) as e:
            return _unavailable(str(e))
        retrieved_at, age = self._retrieved(self._dir)
        return ProductDefinitionsSnapshot(
            status=ProductSourceStatus.OK
            if age is not None and age <= MAX_AGE_HOURS
            else ProductSourceStatus.STALE,
            source=ProductSource(
                retrieved_at=retrieved_at,
                age_hours=None if age is None else round(age, 1),
                max_age_hours=MAX_AGE_HOURS,
                url=URL,
            ),
            document=document,
        )

    def _retrieved(self, cache_dir: Path) -> tuple[str | None, float | None]:
        try:
            meta = json.loads((cache_dir / "feeds-meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        retrieved_at = (meta.get(FEED) or {}).get("retrieved_at")
        try:
            at = datetime.strptime(retrieved_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except (TypeError, ValueError):
            return retrieved_at, None
        return retrieved_at, (self._clock.now() - at).total_seconds() / 3600


def _unavailable(detail: str) -> ProductDefinitionsSnapshot:
    return ProductDefinitionsSnapshot(
        status=ProductSourceStatus.UNAVAILABLE, source=ProductSource(detail=detail)
    )
