from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from traust_core.v1.errors import IntegrityError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind
from traust_core.v1.providers.base import Readiness, Result

Res = TypeVar("Res", covariant=True)
T = TypeVar("T")


class ToolRequest(Dto):
    workspace: Path


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
