from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Dto, Entity, Model


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


class AssetRequest(Dto):
    asset: str
    run_id: str
    partition: str | None = None
    params: Mapping[str, str] = Field(default_factory=dict)


class Refusal(Dto):
    subject: str
    lane: str
    reason: str


class Route(Dto):
    lane: str | None
    priority: int
    reason: str


class Order(Entity):
    request: AssetRequest
    state: str  # order lifecycle states are pending the engine run loop


class Lease(Model):
    order_id: UUID
    worker: str
    expires_at: datetime


class SpendEvent(Model):
    order_id: UUID
    provider: str
    cost_usd: float | None = None
