from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, TypeVar

from traust_core.v1.errors import IntegrityError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.base import Readiness, Result

Res = TypeVar("Res", covariant=True)
T = TypeVar("T")


class ToolProvider(Protocol[Res]):
    name: str

    def check(self) -> Readiness: ...

    def acquire(self, request: ToolRequest) -> Result[Res]: ...


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


# NEED(engine: ToolInspector): traust-engine implements it over core's ProcessRunner (version
# commands, `grype db status` / `grype db update`); core never runs tool processes itself.
class ToolInspector(Protocol):
    """Asks an installed tool its version and its database's state, and refreshes the database."""

    def version(self, tool: str) -> str | None: ...

    def database(self, tool: str) -> DatabaseStatus | None:
        """None when the tool keeps no database."""
        ...

    def update_database(self, tool: str) -> DatabaseStatus: ...
