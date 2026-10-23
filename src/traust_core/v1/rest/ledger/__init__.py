"""The ledger's REST resources: layers and their events, verification, checkpoints."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.ledger import checkpoints, layers

router = APIRouter(tags=["ledger"])
router.include_router(layers.router)
router.include_router(checkpoints.router)

__all__ = ["router"]
