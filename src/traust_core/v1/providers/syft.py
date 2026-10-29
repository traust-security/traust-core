"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import json

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest

# npm devDependencies count, as the retired portfolio graph counted them: without this syft
# drops them from package-lock (not from yarn.lock), measured 2026-10-28 (dependencies log).
_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}


class SyftSbom:
    name = "syft"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return on_path(self.name, missing=" not on PATH")

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        workspace = request.checkout()
        run = self._process.run(
            [self.name, "-q", f"dir:{workspace}", "-o", "cyclonedx-json"], check=False, env=_ENV
        )
        if run.returncode != 0:
            tail = run.stderr.decode(errors="replace").strip()[-300:] or "no stderr"
            raise ServiceError(f"syft exited {run.returncode}: {tail}")
        version = _tool_version(run.stdout)
        return Result(
            run.stdout,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                source=str(workspace),
                version=version,
                argv_sha256=argv_digest(run.argv),
            ),
        )

    def version(self) -> str | None:
        run = self._process.run([self.name, "version", "-o", "json"])
        try:
            return str(json.loads(run.stdout)["version"])
        except (ValueError, KeyError, TypeError) as e:
            raise ServiceError(f"syft version wrote no version: {e}") from e

    def database(self) -> DatabaseStatus | None:
        return None

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(f"{self.name} keeps no database to update")


def _tool_version(raw: bytes) -> str | None:
    try:
        tools = json.loads(raw)["metadata"]["tools"]
    except (ValueError, KeyError, TypeError) as e:
        raise ServiceError(f"syft wrote no CycloneDX metadata: {e}") from e
    listed = tools.get("components", []) if isinstance(tools, dict) else tools
    return next((str(t["version"]) for t in listed if t.get("name") == "syft"), None)
