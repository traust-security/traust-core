from __future__ import annotations

import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol, TypeVar, runtime_checkable

from traust_core.v1.errors import ConfigError, IntegrityError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.base import Readiness, Result

Res = TypeVar("Res", covariant=True)
T = TypeVar("T")


@runtime_checkable
class ToolProvider(Protocol[Res]):
    """A deterministic tool: whether it can run, its run over one target, its version and its
    database (None when it keeps none)."""

    name: str

    def check(self) -> Readiness: ...

    def acquire(self, request: ToolRequest) -> Result[Res]: ...

    def version(self) -> str | None: ...

    def database(self) -> DatabaseStatus | None: ...

    def update_database(self) -> DatabaseStatus:
        """Refresh the tool's database; NoDatabase when it keeps none."""
        ...


def acquire_over_text(tool: ToolProvider[T], filename: str, text: str) -> Result[T]:
    """The tool over a scratch directory holding one file of `text` (a patch, without a clone)."""
    with tempfile.TemporaryDirectory(prefix=f"traust-{tool.name}-") as root:
        (Path(root) / filename).write_text(text, encoding="utf-8")
        return tool.acquire(ToolRequest(workspace=Path(root)))


class NoDatabase(ConfigError):
    """`update_database` on a tool that keeps no database."""


@dataclass(frozen=True, slots=True)
class ToolRun:
    """Each requested tool's result over one checkout, by tool name."""

    results: Mapping[str, Result[object]]

    def data(self, tool: str, kind: type[T]) -> T:
        found = self.results[tool].data
        if not isinstance(found, kind):
            raise IntegrityError(
                f"tool {tool} returned {type(found).__name__}, not {kind.__name__}"
            )
        return found


class FactEnumerator(Protocol):
    kind: CodeFactKind

    def check(self) -> Readiness: ...

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]: ...


class DatabaseStatus(Dto):
    """A tool's local vulnerability database (grype's): present, when built, how old it may get."""

    tool: str
    exists: bool
    built_at: datetime | None = None
    schema_version: str | None = None
    max_age: timedelta | None = None
    path: str | None = None

    def stale(self, now: datetime) -> bool:
        return not self.exists or (
            self.max_age is not None
            and (self.built_at is None or now - self.built_at > self.max_age)
        )


# Deprecated: a ToolProvider reports its own version and database. ProviderCatalog asks this
# only for providers that don't, until traust-engine's adapters implement them (E1).
class ToolInspector(Protocol):
    """Asks an installed tool its version and its database's state, and refreshes the database."""

    def version(self, tool: str) -> str | None: ...

    def database(self, tool: str) -> DatabaseStatus | None:
        """None when the tool keeps no database."""
        ...

    def update_database(self, tool: str) -> DatabaseStatus: ...
