from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.validation import records

router = APIRouter(tags=["validation"])
router.include_router(records.router)

__all__ = ["router"]
