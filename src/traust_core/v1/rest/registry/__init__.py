"""The model-registry REST resources: a role's resolved routing."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.registry import routes

router = APIRouter(tags=["registry"])
router.include_router(routes.router)

__all__ = ["router"]
