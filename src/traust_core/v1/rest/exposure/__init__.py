"""The exposure REST resources: advisories, blast radius, packages, impacts and feeds."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.exposure import advisories, dependencies, impacts

router = APIRouter(tags=["exposure"])
router.include_router(advisories.router)
router.include_router(dependencies.router)
router.include_router(impacts.router)

__all__ = ["router"]
