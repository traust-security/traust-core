from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.inventory import Product, RepositoryRef
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Portfolio

router = APIRouter()


@router.get("/v1/products", responses=PROBLEMS(401, 422))
def list_products(
    portfolio: Portfolio,
    _: Caller,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Product]:
    return portfolio.list_products(PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/products/{product_id}", responses=PROBLEMS(401, 404))
def get_product(product_id: UUID, portfolio: Portfolio, _: Caller) -> Product:
    return portfolio.get_product(product_id)


@router.get("/v1/products/{product_id}/refs", responses=PROBLEMS(401))
def list_product_refs(product_id: UUID, portfolio: Portfolio, _: Caller) -> list[RepositoryRef]:
    return portfolio.list_product_refs(product_id)
