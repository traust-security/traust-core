"""Tier 2 settings over REST: list, show, set, history and diff."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.settings import settings

router = APIRouter(tags=["settings"])
router.include_router(settings.router)

__all__ = ["router"]
