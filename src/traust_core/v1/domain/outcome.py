from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from pydantic import Field

from traust_core.v1.domain.model import Model


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    REFUSED = "refused"
    FAILED = "failed"


class JobResult(Model):
    outcome: Outcome
    degraded: Mapping[str, int] = Field(default_factory=dict)
    reason: str | None = None
    written: tuple[str, ...] = ()

    @classmethod
    def succeeded(cls, written: tuple[str, ...] = ()) -> JobResult:
        return cls(outcome=Outcome.SUCCEEDED, written=written)

    @classmethod
    def partly(cls, degraded: Mapping[str, int], written: tuple[str, ...] = ()) -> JobResult:
        if not degraded:
            return cls.succeeded(written)
        return cls(outcome=Outcome.DEGRADED, degraded=dict(degraded), written=written)

    @classmethod
    def refused(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.REFUSED, reason=reason)

    @classmethod
    def failed(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.FAILED, reason=reason)
