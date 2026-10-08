from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.errors import TraustError
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.base import Provenance, Readiness, Result
from traust_core.v1.providers.process import ProcessRunner


class LineCountRequest(Dto):
    path: Path


class LineCountProvider:
    name = "line-count"

    def __init__(self, process: ProcessRunner) -> None:
        self._process = process

    def check(self) -> Readiness:
        try:
            self._process.run(["wc", "-l"], stdin=b"")
        except TraustError as e:
            return Readiness(ready=False, detail=str(e))
        return Readiness(ready=True)

    def acquire(self, request: LineCountRequest) -> Result[int]:
        out = self._process.run(["wc", "-l", "--", str(request.path)])
        count = int(out.stdout.split()[0])
        provenance = Provenance(
            provider=self.name, acquired_at=datetime.now(UTC), source=str(request.path)
        )
        return Result(count, provenance)
