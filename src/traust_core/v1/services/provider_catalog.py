from __future__ import annotations

import importlib.metadata
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from typing import Any, Protocol

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.base import ProviderRegistry, Readiness
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.providers.model_catalog import ModelCatalog
from traust_core.v1.providers.tools import DatabaseStatus, ToolInspector, ToolProvider
from traust_core.v1.providers.tools.toolchain import UNSTAMPED_VERSION, version_at_least

__all__ = [
    "Capability",
    "CapabilityKind",
    "DatabaseStatus",
    "ProviderBinding",
    "ProviderCatalog",
    "ToolStamp",
    "ToolchainStamp",
    "core_version",
]

# Feed-source probes are network round trips; run them side by side, not one after another.
PROBE_WORKERS = 8


class CapabilityKind(StrEnum):
    TOOL = "tool"
    FEED = "feed"
    FEED_SOURCE = "feed-source"
    MODEL = "model"


class Capability(Dto):
    kind: CapabilityKind
    name: str


class ProviderBinding(Dto):
    """The provider serving a capability and whether it can run now."""

    capability: Capability
    readiness: Readiness
    version: str | None = None


class ToolStamp(Dto):
    tool: str
    version: str | None = None
    database: DatabaseStatus | None = None

    def render(self) -> str:
        """`grype 0.115.0 (db built 2026-08-24, schema 5)`, the report's `metadata.tools` entry."""
        db = self.database
        qualifiers = [
            q
            for q in (
                db and db.built_at and f"db built {db.built_at.date().isoformat()}",
                db and db.schema_version and f"schema {db.schema_version}",
            )
            if q
        ]
        return " ".join(
            p for p in (self.tool, self.version, qualifiers and f"({', '.join(qualifiers)})") if p
        )


class ToolchainStamp(Dto):
    """What ran: traust-core's version and each registered tool's version and database."""

    core_version: str
    tools: tuple[ToolStamp, ...] = ()


def core_version() -> str:
    try:
        return importlib.metadata.version("traust-core")
    except importlib.metadata.PackageNotFoundError:
        return UNSTAMPED_VERSION


class ProviderCatalog:
    """Which provider serves each capability, whether it is ready, and what versions ran.
    Tool version floors are pack policy, passed in by the caller; a callable is read on the
    first tool resolve, after that tool's provider is built."""

    def __init__(
        self,
        tools: ProviderRegistry[ToolProvider[Any]],
        feeds: ProviderRegistry[FeedProvider],
        *,
        sources: ProviderRegistry[FeedSource] | None = None,
        inspector: ToolInspector | None = None,
        models: ModelCatalog | None = None,
        floors: Mapping[str, str] | Callable[[], Mapping[str, str]] | None = None,
    ) -> None:
        self._tools = tools
        self._feeds = feeds
        self._sources = sources or ProviderRegistry[FeedSource]("feed-source")
        self._inspector = inspector
        self._models = models
        self._floor_source = floors if callable(floors) else lambda: floors or {}
        if not callable(floors):
            self._floors  # noqa: B018 - a given mapping is checked at construction, as before

    @cached_property
    def _floors(self) -> dict[str, str]:
        floors = dict(self._floor_source())
        uninspected = [n for n in sorted(floors) if not self._reports_itself(n)]
        if uninspected and self._inspector is None:
            raise ConfigError(
                f"tool floors for {uninspected} need a ToolInspector (NEED(engine: ToolInspector))"
            )
        return floors

    def resolve(self, capability: Capability) -> ProviderBinding:
        """The capability's provider and its readiness; ConfigError when none is registered."""
        if capability.kind is CapabilityKind.TOOL:
            return self._tool(capability)
        if capability.kind is CapabilityKind.FEED:
            readiness = self._feeds.get(capability.name).check()
            return ProviderBinding(capability=capability, readiness=readiness)
        if capability.kind is CapabilityKind.FEED_SOURCE:
            readiness = self._sources.get(capability.name).check()
            return ProviderBinding(capability=capability, readiness=readiness)
        if self._models is None:
            raise ConfigError(
                f"model {capability.name!r}: no model catalog is wired "
                "(Context.register_model_catalog)"
            )
        return ProviderBinding(capability=capability, readiness=self._models.check())

    def readiness(
        self, capability: Capability | None, *, network: bool = True
    ) -> list[ProviderBinding]:
        """One capability's binding, or every registered tool's, feed's and probed source's (and
        the model catalog's, when wired): the doctor and pre-flight check. `network=False` leaves
        out the feed sources, whose readiness is a network probe."""
        if capability is not None:
            return [self.resolve(capability)]
        local = [
            *(Capability(kind=CapabilityKind.TOOL, name=n) for n in self._tools.names()),
            *(Capability(kind=CapabilityKind.FEED, name=n) for n in self._feeds.names()),
        ]
        bindings = [self.resolve(c) for c in local]
        if network:
            bindings += self._probe_sources()
        if self._models is not None:
            bindings.append(self.resolve(Capability(kind=CapabilityKind.MODEL, name="registry")))
        return bindings

    def stamp(self) -> ToolchainStamp:
        return ToolchainStamp(
            core_version=core_version(),
            tools=tuple(
                ToolStamp(tool=n, version=i.version(), database=i.database())
                for n, i in self._inspections("stamp").items()
            ),
        )

    def databases(self) -> list[DatabaseStatus]:
        """Each registered tool's database as it stands; tools without one are left out."""
        inspections = self._inspections("databases").values()
        return [db for i in inspections if (db := i.database()) is not None]

    def fetch_databases(self) -> list[DatabaseStatus]:
        """Refresh every registered tool's database; tools without one are left out."""
        inspections = self._inspections("fetch_databases").values()
        return [i.update_database() for i in inspections if i.database() is not None]

    def _probe_sources(self) -> list[ProviderBinding]:
        # Built on this thread: ProviderRegistry.get caches without a lock.
        sources = {n: self._sources.get(n) for n in self._sources.names()}
        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            checks = list(pool.map(lambda s: s.check(), sources.values()))
        return [
            ProviderBinding(
                capability=Capability(kind=CapabilityKind.FEED_SOURCE, name=n), readiness=r
            )
            for n, r in zip(sources, checks, strict=True)
        ]

    def _tool(self, capability: Capability) -> ProviderBinding:
        name = capability.name
        provider = self._tools.get(name)
        floor = self._floors.get(name)
        readiness = provider.check()
        inspection = self._inspection(name, provider)
        if inspection is None or not readiness.ready:
            return ProviderBinding(capability=capability, readiness=readiness)
        version = inspection.version()
        problem = _version_problem(version, floor)
        db = inspection.database()
        if problem is None and db is not None and not db.exists:
            problem = f"vulnerability database not found at {db.path or 'its default path'}"
        return ProviderBinding(
            capability=capability,
            readiness=Readiness(ready=False, detail=problem) if problem else readiness,
            version=version,
        )

    def _reports_itself(self, name: str) -> bool:
        return name in self._tools.names() and isinstance(self._tools.get(name), ToolProvider)

    def _inspection(self, name: str, provider: object) -> _Inspection | None:
        if isinstance(provider, ToolProvider):
            return provider
        return _Inspected(self._inspector, name) if self._inspector is not None else None

    def _inspections(self, door: str) -> dict[str, _Inspection]:
        found = {n: self._inspection(n, self._tools.get(n)) for n in self._tools.names()}
        missing = [n for n, i in found.items() if i is None]
        if missing or (not found and self._inspector is None):
            named = f" for {missing}" if missing else ""
            raise ConfigError(f"{door} needs a ToolInspector{named} (NEED(engine: ToolInspector))")
        return {n: i for n, i in found.items() if i is not None}


class _Inspection(Protocol):
    def version(self) -> str | None: ...

    def database(self) -> DatabaseStatus | None: ...

    def update_database(self) -> DatabaseStatus: ...


@dataclass(frozen=True, slots=True)
class _Inspected:
    """A provider that can't report itself, asked through the deprecated ToolInspector."""

    inspector: ToolInspector
    tool: str

    def version(self) -> str | None:
        return self.inspector.version(self.tool)

    def database(self) -> DatabaseStatus | None:
        return self.inspector.database(self.tool)

    def update_database(self) -> DatabaseStatus:
        return self.inspector.update_database(self.tool)


def _version_problem(version: str | None, floor: str | None) -> str | None:
    if version == UNSTAMPED_VERSION:
        return (
            f"reports version {version}: the binary carries no version stamp (not installed "
            "from the module proxy); reinstall with a version query, upgrading won't help"
        )
    if floor is None:
        return None
    if version is None:
        return f"version unknown, need >= {floor}"
    if not version_at_least(version, floor):
        return f"version {version} is below the floor {floor}"
    return None
