"""The portfolio (inventory) REST resources: repositories, refs, owners and products."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.portfolio import onboarding, products, repositories

router = APIRouter(tags=["portfolio"])
router.include_router(repositories.router)
router.include_router(products.router)
router.include_router(onboarding.router)

__all__ = ["router"]
