from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response
from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.operations import (
    AssetName,
    JobResult,
    OrderFilter,
    OrderState,
    RunOrder,
    StartRecordingRequest,
    WorkerId,
)
from traust_core.v1.providers.correlation import correlation_scope
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.ops.service import Ops, Runner

router = APIRouter()

MAX_LEASE_SECONDS = 24 * 60 * 60


@contextmanager
def _order_scope(request: Request, order_id: UUID) -> Iterator[None]:
    request.state.order_id = order_id
    with correlation_scope(
        request.state.request_id,
        order_id=order_id,
        actor_kind=getattr(request.state, "actor_kind", None),
    ):
        yield


class ClaimRequest(Model):
    lease_seconds: Annotated[int, Field(gt=0, le=MAX_LEASE_SECONDS)]
    assets: tuple[AssetName, ...] | None = None


class LeaseRequest(Model):
    lease_seconds: Annotated[int, Field(gt=0, le=MAX_LEASE_SECONDS)]


class CompleteRequest(Model):
    result: JobResult


@router.post(
    "/v1/orders/claim",
    response_model=RunOrder,
    responses={**PROBLEMS(401, 403, 422), 204: {"description": "The queue has no claimable order"}},
)
def claim(body: ClaimRequest, ops: Ops, runner: Runner) -> RunOrder | Response:
    """Lease the next queued order to the calling runner; 204 when nothing is queued for it."""
    order = ops.claim(WorkerId(runner.ref), timedelta(seconds=body.lease_seconds), body.assets)
    return order if order is not None else Response(status_code=204)


@router.post(
    "/v1/orders/start",
    responses=PROBLEMS(401, 403, 404, 409, 422),
)
def start(body: StartRecordingRequest, ops: Ops, caller: Caller, request: Request) -> RunOrder:
    """Start the caller's explicitly dispatched recording run within its server-owned scope."""
    order = ops.start_recording(body.order, caller, timedelta(seconds=body.lease_seconds))
    assert order.id is not None
    with _order_scope(request, order.id):
        return order


@router.get("/v1/orders", responses=PROBLEMS(401, 422))
def list_orders(
    ops: Ops,
    _: Caller,
    states: Annotated[list[OrderState] | None, Query()] = None,
    asset: AssetName | None = None,
    repository_id: UUID | None = None,
    run_batch_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[RunOrder]:
    """Orders by one indexed filter (states, a repository or a batch), newest first, paged."""
    filter = OrderFilter(
        states=tuple(states or ()),
        asset=asset,
        repository_id=repository_id,
        run_batch_id=run_batch_id,
    )
    return ops.list(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/orders/{order_id}", responses=PROBLEMS(401, 404))
def get_order(order_id: UUID, ops: Ops, _: Caller, request: Request) -> RunOrder:
    with _order_scope(request, order_id):
        return ops.get(order_id)


@router.post("/v1/orders/{order_id}/heartbeat", responses=PROBLEMS(401, 403, 404, 409))
def heartbeat(
    order_id: UUID, body: LeaseRequest, ops: Ops, runner: Runner, request: Request
) -> RunOrder:
    """Extend the runner's lease; 409 if the order is not leased to it or the lease has expired."""
    with _order_scope(request, order_id):
        return ops.heartbeat(order_id, WorkerId(runner.ref), timedelta(seconds=body.lease_seconds))


@router.post("/v1/orders/{order_id}/complete", responses=PROBLEMS(401, 403, 404, 409, 422))
def complete(
    order_id: UUID, body: CompleteRequest, ops: Ops, runner: Runner, request: Request
) -> RunOrder:
    """Finish the runner's order with its outcome; a repeated complete returns the same order."""
    with _order_scope(request, order_id):
        return ops.complete(order_id, WorkerId(runner.ref), body.result)
