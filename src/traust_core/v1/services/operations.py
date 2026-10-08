from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeVar
from uuid import UUID

from traust_core.v1.models.operations import (
    AssetRequest,
    JobResult,
    Lease,
    Order,
    Refusal,
    Route,
    SpendEvent,
)
from traust_core.v1.repositories.operations import OpsUnitOfWork

S = TypeVar("S", contravariant=True)
E = TypeVar("E", contravariant=True)


class Materializer(Protocol):
    asset: str

    def materialize(self, request: AssetRequest) -> JobResult: ...


class Router(Protocol[S, E]):
    def route(self, state: S, events: Sequence[E], refusals: Sequence[Refusal]) -> Route: ...


class OpsService:
    def __init__(self, uow: OpsUnitOfWork) -> None:
        self._uow = uow

    def submit(self, request: AssetRequest) -> Order:
        raise NotImplementedError("stub: replaces cron/subprocess orchestration, */ops.py facades")

    def claim(self, worker: str) -> Lease | None:
        raise NotImplementedError("stub: order lease for the traust-engine run loop")

    def heartbeat(self, lease: Lease) -> Lease:
        raise NotImplementedError("stub: order lease renewal for the traust-engine run loop")

    def complete(self, lease: Lease, result: JobResult) -> Order:
        raise NotImplementedError("stub: replaces per-CLI exit codes and progress files")

    def approve(self, order_id: UUID, attestation_id: UUID) -> Order:
        raise NotImplementedError("stub: replaces remediation push gates")

    def record_spend(self, event: SpendEvent) -> None:
        raise NotImplementedError("stub: replaces metrics/collect_spend.py, spend declarations")
