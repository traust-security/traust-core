from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.remediation import verification_records

router = APIRouter(tags=["remediation"])
router.include_router(verification_records.router)

__all__ = ["router"]
