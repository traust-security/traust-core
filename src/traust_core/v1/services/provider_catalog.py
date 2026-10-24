from __future__ import annotations

import importlib.metadata
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.base import ProviderRegistry, Readiness
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.model_catalog import ModelCatalog
from traust_core.v1.providers.tools import DatabaseStatus, ToolInspector, ToolProvider

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

# A version the Go toolchain stamps when it didn't install from the module proxy: not a version.
UNSTAMPED_VERSION = "0.0.0"


class CapabilityKind(StrEnum):
    TOOL = "tool"
    FEED = "feed"
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
    Tool version floors are pack policy, passed in by the caller."""

    def __init__(
        self,
        tools: ProviderRegistry[ToolProvider[Any]],
        feeds: ProviderRegistry[FeedProvider],
        *,
        inspector: ToolInspector | None = None,
        models: ModelCatalog | None = None,
        floors: Mapping[str, str] | None = None,
    ) -> None:
        self._tools = tools
        self._feeds = feeds
        self._inspector = inspector
        self._models = models
        self._floors = dict(floors or {})
        if self._floors and inspector is None:
            raise ConfigError(
                f"tool floors for {sorted(self._floors)} need a ToolInspector "
                "(NEED(engine: ToolInspector))"
            )

    def resolve(self, capability: Capability) -> ProviderBinding:
        """The capability's provider and its readiness; ConfigError when none is registered."""
        if capability.kind is CapabilityKind.TOOL:
            return self._tool(capability)
        if capability.kind is CapabilityKind.FEED:
            readiness = self._feeds.get(capability.name).check()
            return ProviderBinding(capability=capability, readiness=readiness)
        if self._models is None:
            raise ConfigError(
                f"model {capability.name!r}: no model catalog is wired "
                "(NEED(model-registry): ModelCatalog over the model registry)"
            )
        return ProviderBinding(capability=capability, readiness=self._models.check())

    def readiness(self, capability: Capability | None) -> list[ProviderBinding]:
        """One capability's binding, or every registered tool's and feed's (and the model
        catalog's, when wired): the doctor and pre-flight check."""
        if capability is not None:
            return [self.resolve(capability)]
        every = [
            *(Capability(kind=CapabilityKind.TOOL, name=n) for n in self._tools.names()),
            *(Capability(kind=CapabilityKind.FEED, name=n) for n in self._feeds.names()),
        ]
        if self._models is not None:
            every.append(Capability(kind=CapabilityKind.MODEL, name="registry"))
        return [self.resolve(c) for c in every]

    def stamp(self) -> ToolchainStamp:
        inspector = self._require_inspector("stamp")
        return ToolchainStamp(
            core_version=core_version(),
            tools=tuple(
                ToolStamp(tool=n, version=inspector.version(n), database=inspector.database(n))
                for n in self._tools.names()
            ),
        )

    def databases(self) -> list[DatabaseStatus]:
        """Each registered tool's database as it stands; tools without one are left out."""
        inspector = self._require_inspector("databases")
        return [db for n in self._tools.names() if (db := inspector.database(n)) is not None]

    def fetch_databases(self) -> list[DatabaseStatus]:
        """Refresh every registered tool's database; tools without one are left out."""
        inspector = self._require_inspector("fetch_databases")
        return [
            inspector.update_database(n)
            for n in self._tools.names()
            if inspector.database(n) is not None
        ]

    def _tool(self, capability: Capability) -> ProviderBinding:
        name = capability.name
        readiness = self._tools.get(name).check()
        if self._inspector is None or not readiness.ready:
            return ProviderBinding(capability=capability, readiness=readiness)
        version = self._inspector.version(name)
        problem = _version_problem(version, self._floors.get(name))
        db = self._inspector.database(name)
        if problem is None and db is not None and not db.exists:
            problem = f"vulnerability database not found at {db.path or 'its default path'}"
        return ProviderBinding(
            capability=capability,
            readiness=Readiness(ready=False, detail=problem) if problem else readiness,
            version=version,
        )

    def _require_inspector(self, door: str) -> ToolInspector:
        if self._inspector is None:
            raise ConfigError(f"{door} needs a ToolInspector (NEED(engine: ToolInspector))")
        return self._inspector


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
    if not _at_least(version, floor):
        return f"version {version} is below the floor {floor}"
    return None


def _at_least(version: str, floor: str) -> bool:
    try:
        return tuple(map(int, version.split("."))) >= tuple(map(int, floor.split(".")))
    except ValueError:
        return False
