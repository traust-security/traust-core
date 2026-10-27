"""The assessments REST resources: an assessment and the assessments of a ref or repository."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.assessments import assessments

router = APIRouter(tags=["assessments"])
router.include_router(assessments.router)

__all__ = ["router"]
