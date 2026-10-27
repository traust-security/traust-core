"""The findings REST resources: findings, their decisions (countersign, restate), review queue."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.findings import decisions, findings, review

router = APIRouter(tags=["findings"])
# review first: its static /v1/findings/review-queue must precede /v1/findings/{finding_id}
router.include_router(review.router)
router.include_router(findings.router)
router.include_router(decisions.router)

__all__ = ["router"]
