from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.inventory import (
    Product,
    Repository,
    RepositoryFilter,
    RepositoryRef,
    Team,
)
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Portfolio

router = APIRouter()


@router.get("/v1/repositories", responses=PROBLEMS(401, 422))
def list_repositories(
    portfolio: Portfolio,
    _: Caller,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Repository]:
    return portfolio.list_repositories(RepositoryFilter(), PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/repositories/{repository_id}", responses=PROBLEMS(401, 404))
def get_repository(repository_id: UUID, portfolio: Portfolio, _: Caller) -> Repository:
    return portfolio.get_repository(repository_id)


@router.get("/v1/repositories/{repository_id}/refs", responses=PROBLEMS(401))
def list_refs(repository_id: UUID, portfolio: Portfolio, _: Caller) -> list[RepositoryRef]:
    return portfolio.inventory.list_refs(repository_id)


@router.get("/v1/repositories/{repository_id}/owners", responses=PROBLEMS(401))
def list_owners(repository_id: UUID, portfolio: Portfolio, _: Caller) -> list[Team]:
    return portfolio.list_owners(repository_id)


@router.get("/v1/repositories/{repository_id}/products", responses=PROBLEMS(401))
def list_products_of(repository_id: UUID, portfolio: Portfolio, _: Caller) -> list[Product]:
    return portfolio.list_products_of(repository_id)


@router.get("/v1/refs/{repository_ref_id}", responses=PROBLEMS(401, 404))
def get_ref(repository_ref_id: UUID, portfolio: Portfolio, _: Caller) -> RepositoryRef:
    return portfolio.inventory.get_ref(repository_ref_id)
