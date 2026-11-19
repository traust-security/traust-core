"""The dashboard REST resources: the metrics query and the presets."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.dashboards import presets, query

router = APIRouter(tags=["dashboards"])
router.include_router(query.router)
router.include_router(presets.router)

__all__ = ["router"]
