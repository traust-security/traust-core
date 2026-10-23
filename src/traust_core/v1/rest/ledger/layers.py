from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.ledger import Event, Layer, VerifyResult
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.ledger.service import Ledger

router = APIRouter()


@router.get("/v1/repositories/{repository_id}/ledger/layers", responses=PROBLEMS(401, 404))
def list_layers(repository_id: UUID, ledger: Ledger, _: Caller) -> list[Layer]:
    return ledger.layers(repository_id)


@router.get("/v1/ledger/layers/{layer_id}", responses=PROBLEMS(401, 404))
def get_layer(layer_id: UUID, ledger: Ledger, _: Caller) -> Layer:
    return ledger.layer(layer_id)


@router.get("/v1/ledger/layers/{layer_id}/events", responses=PROBLEMS(401, 404, 422))
def list_events(
    layer_id: UUID,
    ledger: Ledger,
    _: Caller,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Event]:
    return ledger.events(layer_id, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/ledger/layers/{layer_id}/verification", responses=PROBLEMS(401, 404))
def verify_layer(layer_id: UUID, ledger: Ledger, _: Caller) -> VerifyResult:
    return ledger.verify(layer_id)
