"""The report REST resources: request a report, follow its build, download its file."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.reports import reports

router = APIRouter(tags=["reports"])
router.include_router(reports.router)

__all__ = ["router"]
