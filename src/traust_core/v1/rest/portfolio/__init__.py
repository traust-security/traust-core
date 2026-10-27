"""The portfolio (inventory) REST resources: repositories, refs, owners and products."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.portfolio import products, repositories

router = APIRouter(tags=["portfolio"])
router.include_router(repositories.router)
router.include_router(products.router)

__all__ = ["router"]
