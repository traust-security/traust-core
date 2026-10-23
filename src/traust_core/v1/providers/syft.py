"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import json
import shutil

from traust_core.v1.errors import ServiceError
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import ToolRequest


class SyftSbom:
    name = "syft"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        found = shutil.which(self.name) is not None
        return Readiness(ready=found, detail="" if found else "syft not on PATH")

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        run = self._process.run(
            [self.name, "-q", f"dir:{request.workspace}", "-o", "cyclonedx-json"], check=False
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
                source=str(request.workspace),
                version=version,
            ),
        )


def _tool_version(raw: bytes) -> str | None:
    try:
        tools = json.loads(raw)["metadata"]["tools"]
    except (ValueError, KeyError, TypeError) as e:
        raise ServiceError(f"syft wrote no CycloneDX metadata: {e}") from e
    listed = tools.get("components", []) if isinstance(tools, dict) else tools
    return next((str(t["version"]) for t in listed if t.get("name") == "syft"), None)
