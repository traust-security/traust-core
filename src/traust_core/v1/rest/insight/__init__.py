"""The insight REST resources: dashboards, rollups and exports, built on demand."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.insight import insights

router = APIRouter(tags=["insight"])
router.include_router(insights.router)

__all__ = ["router"]
