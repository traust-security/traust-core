"""A scanner adapter's `scan()` as a `ToolProvider`: readiness from PATH and a precondition, typed
errors and provenance around the scan, version and database from the toolchain."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

from traust_core.v1.errors import ServiceError, TraustError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.common import ToolRequest, ToolTarget
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase
from traust_core.v1.providers.tools.toolchain import POPULATABLE_TOOLS, Toolchain

Res = TypeVar("Res")


@dataclass(frozen=True, slots=True)
class AdapterTool(Generic[Res]):
    """One adapter over one kind of target. `binaries[0]` is the binary whose pin, version and
    database it reports (none: an API, not a binary); `toolchain` is read on first use."""

    name: str
    binaries: tuple[str, ...]
    scan: Callable[[Any], Res]
    clock: Clock
    toolchain: Callable[[], Toolchain]
    precondition: Callable[[], Readiness] | None = None
    target: ToolTarget = ToolTarget.CHECKOUT
    # The argv `scan` runs, for adapters that build it from the target alone.
    argv: Callable[[Any], Sequence[str]] | None = None

    @property
    def binary(self) -> str:
        return self.binaries[0] if self.binaries else ""

    def check(self) -> Readiness:
        if self.binaries and not (found := on_path(*self.binaries, missing=" not on PATH")).ready:
            return found
        return self.precondition() if self.precondition else Readiness(ready=True)

    def acquire(self, request: ToolRequest) -> Result[Res]:
        given, where = self._target(request)
        try:
            result = self.scan(given)
        except TraustError:
            raise
        except ValueError as e:
            raise ValidationError(f"{self.name} over {where}: {e}") from e
        except (OSError, RuntimeError) as e:  # missing binary, timeout, tool failure
            raise ServiceError(f"{self.name} over {where}: {e}") from e
        db = self.database()
        return Result(
            result,
            Acquisition(
                provider=self.name,
                acquired_at=self.clock.now(),
                version=_scanner_version(result),
                source=str(where.resolve()),
                argv_sha256=argv_digest(self.argv(given)) if self.argv else None,
                db_built_at=db.built_at if db else None,
            ),
        )

    def version(self) -> str | None:
        if not self.binary:
            return None
        toolchain = self.toolchain()
        pin = toolchain.pins.get(self.binary)
        return toolchain.version(
            self.binary,
            pin.version_cmd if pin else None,
            pin.version_regex if pin else None,
        )

    def database(self) -> DatabaseStatus | None:
        if self.binary not in POPULATABLE_TOOLS:
            return None
        found = self.toolchain().database(self.binary)
        return found.model_copy(update={"tool": self.name}) if found else None

    def update_database(self) -> DatabaseStatus:
        if self.binary not in POPULATABLE_TOOLS:
            raise NoDatabase(f"{self.name} keeps no vulnerability database to update")
        ok, message = self.toolchain().populate(self.binary)
        if not ok:
            raise ServiceError(message)
        status = self.database()
        if status is None:
            raise ServiceError(f"{self.name}: database updated but its status is unreadable")
        return status

    def _target(self, request: ToolRequest) -> tuple[Any, Path]:
        """The scan's input, and the path its errors and provenance name."""
        if request.target is not self.target:
            raise ValidationError(
                f"{self.name} runs over a {self.target.value}, not a {request.target.value}"
            )
        if (sbom := request.sbom) is not None:
            if not sbom.is_file():
                raise ValidationError(f"{self.name}: SBOM is not a file: {sbom}")
            return sbom, sbom
        query = request.symbols
        workspace = query.workspace if query else request.checkout()
        if not workspace.is_dir():
            raise ValidationError(f"{self.name}: workspace is not a directory: {workspace}")
        return query or workspace, workspace


def resolves(tool: str, resolve: Callable[[], object]) -> Readiness:
    """A precondition: ready when `resolve` returns, not ready with its ValueError otherwise."""
    try:
        resolve()
    except ValueError as e:
        return Readiness(ready=False, detail=f"{tool}: {e}")
    return Readiness(ready=True)


def _scanner_version(result: object) -> str | None:
    if isinstance(result, AdapterResultArtifact):
        return result.metadata.scanner_version or None
    return None
