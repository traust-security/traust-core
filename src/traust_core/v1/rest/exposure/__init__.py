"""The exposure REST resources: advisories, their blast radius, packages and dependents."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.exposure import advisories, dependencies

router = APIRouter(tags=["exposure"])
router.include_router(advisories.router)
router.include_router(dependencies.router)

__all__ = ["router"]
