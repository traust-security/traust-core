"""The insight REST resources: every dashboard view, built on demand from the domain services."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.insight import views

router = APIRouter(tags=["insight"])
router.include_router(views.router)

__all__ = ["router"]
