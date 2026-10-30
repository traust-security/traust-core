from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.validation import attempts, records

router = APIRouter(tags=["validation"])
router.include_router(records.router)
router.include_router(attempts.router)

__all__ = ["router"]
