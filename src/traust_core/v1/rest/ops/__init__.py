"""The operations REST resources: the run-order queue (claim, lease, complete, reads) and feed."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.ops import feed, orders

router = APIRouter(tags=["ops"])
router.include_router(orders.router)
router.include_router(feed.router)

__all__ = ["router"]
