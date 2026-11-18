"""The dashboard REST resources: the metrics query."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.dashboards import query

router = APIRouter(tags=["dashboards"])
router.include_router(query.router)

__all__ = ["router"]
