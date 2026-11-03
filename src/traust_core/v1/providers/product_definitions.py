"""The product-definitions registry's pull-through cache (`traust feeds fetch-products` fills it):
`product_definitions.json` and its `feeds-meta.json` entry in the feeds cache directory."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from traust_core.v1.models.product_definitions import (
    DEFINITION_KEYS,
    ProductDefinitionsSnapshot,
    ProductRegistryStatus,
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
        retrieved_at, age = self._retrieved()
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

    def status(self) -> ProductRegistryStatus:
        """Read registry retrieval metadata without fetching or treating absence as failure."""
        if self._dir is None:
            return ProductRegistryStatus()
        try:
            meta = json.loads((self._dir / "feeds-meta.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ProductRegistryStatus(
                detail="cached registry has no retrieval metadata"
                if (self._dir / FILENAME).exists()
                else None
            )
        except (OSError, ValueError) as e:
            return ProductRegistryStatus(detail=f"registry retrieval metadata: {e}")
        if not isinstance(meta, dict):
            return ProductRegistryStatus(detail="registry retrieval metadata must be an object")
        entry = meta.get(FEED)
        if entry is None:
            return ProductRegistryStatus(
                detail="cached registry has no retrieval metadata"
                if (self._dir / FILENAME).exists()
                else None
            )
        if not isinstance(entry, dict):
            return ProductRegistryStatus(detail="registry retrieval entry must be an object")
        retrieved_at = entry.get("retrieved_at")
        try:
            fetched_at = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
            if fetched_at.tzinfo is None:
                raise ValueError("retrieval timestamp must include a timezone")
        except (TypeError, AttributeError, ValueError) as e:
            return ProductRegistryStatus(
                retrieved_at=retrieved_at if isinstance(retrieved_at, str) else None,
                detail=f"registry retrieval timestamp: {e}",
            )
        if not (self._dir / FILENAME).is_file():
            return ProductRegistryStatus(
                fetched_at=fetched_at,
                retrieved_at=retrieved_at,
                detail="retrieved registry cache is missing",
            )
        return ProductRegistryStatus(fetched_at=fetched_at, retrieved_at=retrieved_at)

    def _retrieved(self) -> tuple[str | None, float | None]:
        status = self.status()
        age = (
            None
            if status.fetched_at is None
            else (self._clock.now() - status.fetched_at).total_seconds() / 3600
        )
        return status.retrieved_at, age


def _unavailable(detail: str) -> ProductDefinitionsSnapshot:
    return ProductDefinitionsSnapshot(
        status=ProductSourceStatus.UNAVAILABLE, source=ProductSource(detail=detail)
    )
