"""deps.dev's resolved dependency graphs and default versions, through the feeds registry's
`deps_dev` source. A failed lookup is a status, never an empty graph."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol
from urllib.parse import quote

from traust_core.v1.errors import ConfigError, ServiceError, TraustError, ValidationError
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedSource
from traust_core.v1.providers.http import failure_status

log = logging.getLogger(__name__)

LICENSE = "CC-BY-4.0"
ATTRIBUTION = (
    "Resolved dependency data: deps.dev (Google LLC), https://deps.dev, licensed under "
    "CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/); used unmodified as "
    "package/version pairs. API use is subject to the Google APIs Terms of Service."
)
# OSV ecosystem -> deps.dev system
SYSTEMS = {"npm": "NPM", "PyPI": "PYPI", "Maven": "MAVEN", "crates.io": "CARGO"}
CACHE_TTL = timedelta(hours=24)
WORKERS = 4

Key = tuple[str, str, str]
Node = tuple[str, str, str]  # (name, version, relation)


@dataclass(frozen=True, slots=True)
class Resolution:
    """`ok`, `not-found` (deps.dev has no such version), `unsupported`, or a failure status."""

    status: str
    nodes: tuple[Node, ...] = ()
    detail: str = ""
    cached: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class ResponseCache(Protocol):
    """Bytes kept under a key; Context backs it with the object store."""

    def get(self, key: str) -> bytes | None: ...

    def put(self, key: str, data: bytes) -> None: ...


class _Failure(Exception):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status


class DepsDevResolver:
    """deps.dev permits caching: answers (never failures) are kept in `cache` for a day."""

    def __init__(
        self, source: FeedSource, clock: Clock, *, cache: ResponseCache | None = None
    ) -> None:
        if source.template is None:
            raise ConfigError(f"{source.name} serves no per-identifier documents")
        self._source = source
        self._clock = clock
        self._cache = cache
        self.base_url = source.template.split("/systems/", 1)[0].removesuffix("/systems")

    def dependencies(self, ecosystem: str, name: str, version: str) -> Resolution:
        """The resolved graph of one package version, its own node left out."""
        if ecosystem not in SYSTEMS:
            return Resolution("unsupported", detail=f"deps.dev does not resolve {ecosystem}")
        key = (ecosystem, name, version)
        if (hit := self._cached(key)) is not None:
            return hit
        try:
            doc = self._get(
                f"{self._system(ecosystem)}/packages/{quote(name, safe='')}"
                f"/versions/{quote(version, safe='')}:dependencies"
            )
        except _Failure as f:
            res = Resolution(f.status, detail=str(f))
        else:
            nodes = {
                (vk["name"], vk["version"], node.get("relation") or "")
                for node in doc.get("nodes") or []
                if (vk := (node or {}).get("versionKey") or {})
                and node.get("relation") != "SELF"
                and vk.get("name")
                and vk.get("version")
            }
            res = Resolution("ok", tuple(sorted(nodes)))
        self._store(key, res)
        return res

    def default_version(self, ecosystem: str, name: str) -> Resolution:
        """The version deps.dev marks default (what an install gets today), as one `DEFAULT`
        node."""
        if ecosystem not in SYSTEMS:
            return Resolution("unsupported", detail=f"deps.dev does not resolve {ecosystem}")
        key = (ecosystem, name, "")
        if (hit := self._cached(key)) is not None:
            return hit
        try:
            doc = self._get(f"{self._system(ecosystem)}/packages/{quote(name, safe='')}")
        except _Failure as f:
            res = Resolution(f.status, detail=str(f))
        else:
            default = next(
                (
                    (v.get("versionKey") or {}).get("version")
                    for v in doc.get("versions") or []
                    if isinstance(v, dict) and v.get("isDefault")
                ),
                None,
            )
            res = (
                Resolution("ok", ((name, default, "DEFAULT"),))
                if default
                else Resolution("not-found", detail=f"no default version for {name}")
            )
        self._store(key, res)
        return res

    def probe(self, key: Key) -> tuple[str, str] | None:
        """One lookup before a run: None when deps.dev answers (a 404 is an answer)."""
        res = self.dependencies(*key)
        if res.status in ("ok", "not-found", "unsupported"):
            return None
        return res.status, res.detail

    def defaults_many(self, names: Iterable[tuple[str, str]]) -> dict[tuple[str, str], Resolution]:
        unique = sorted(set(names))
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            return dict(
                zip(unique, pool.map(lambda k: self.default_version(*k), unique), strict=True)
            )

    def resolve_many(self, keys: Iterable[Key]) -> tuple[dict[Key, Resolution], Counter[str]]:
        unique = sorted(set(keys))
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = dict(
                zip(unique, pool.map(lambda k: self.dependencies(*k), unique), strict=True)
            )
        return results, Counter(r.status for r in results.values())

    @staticmethod
    def _system(ecosystem: str) -> str:
        return SYSTEMS[ecosystem].lower()

    def _get(self, ident: str) -> dict[str, Any]:
        try:
            raw = self._source.document(ident).data
        except ServiceError as e:
            if e.status == 404:
                raise _Failure("not-found", str(e)) from e
            raise _Failure(failure_status(e), str(e)) from e
        except ValidationError as e:
            raise _Failure(failure_status(e), str(e)) from e
        try:
            doc = json.loads(raw)
        except ValueError as e:
            raise _Failure("error", f"unparseable response for {ident}: {e}") from e
        if not isinstance(doc, dict):
            raise _Failure("error", f"unexpected response shape for {ident}")
        return doc

    def _cached(self, key: Key) -> Resolution | None:
        if self._cache is None:
            return None
        try:
            raw = self._cache.get(_cache_key(key))
            doc = json.loads(raw) if raw is not None else None
        except (TraustError, ValueError) as e:
            log.warning("deps.dev cache entry for %s unreadable (refetched): %s", key, e)
            return None
        if not isinstance(doc, dict):
            return None
        fetched_at = doc.get("fetched_at")
        if doc.get("key") != list(key) or not isinstance(fetched_at, int | float):
            return None
        age = self._clock.now().timestamp() - fetched_at
        if age > CACHE_TTL.total_seconds():
            return None
        nodes = tuple((n[0], n[1], n[2]) for n in doc.get("nodes") or [])
        return Resolution(doc.get("status", "error"), nodes, cached=True)

    def _store(self, key: Key, res: Resolution) -> None:
        if self._cache is None or res.status not in ("ok", "not-found"):
            return
        doc = {
            "key": list(key),
            "fetched_at": self._clock.now().timestamp(),
            "status": res.status,
            "nodes": [list(n) for n in res.nodes],
        }
        try:
            self._cache.put(_cache_key(key), json.dumps(doc).encode())
        except TraustError as e:
            log.warning("deps.dev cache not written for %s (the answer is refetched): %s", key, e)


def _cache_key(key: Key) -> str:
    return f"{hashlib.sha256(chr(0).join(key).encode()).hexdigest()}.json"
