from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.base import Dto

router = APIRouter(tags=["health"])


class Health(Dto):
    status: str


@router.get("/v1/healthz")
async def healthz() -> Health:
    """Liveness: the process answers. No auth, no database."""
    return Health(status="ok")
