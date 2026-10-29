from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.artifacts import artifacts

router = APIRouter(tags=["artifacts"])
router.include_router(artifacts.router)

__all__ = ["router"]
