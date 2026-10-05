from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from pydantic import Field

from traust_core.v1.domain.model import Dto
from traust_core.v1.domain.outcome import JobResult


class AssetRequest(Dto):
    asset: str
    run_id: str
    partition: str | None = None
    params: Mapping[str, str] = Field(default_factory=dict)


class Materializer(Protocol):
    asset: str

    def materialize(self, request: AssetRequest) -> JobResult: ...
