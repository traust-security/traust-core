"""The findings REST resources: findings, their decisions (countersign, restate), review queue."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.rest.findings import (
    decisions,
    findings,
    repository_findings,
    review,
    triage_records,
)

router = APIRouter(tags=["findings"])
# review first: its static /v1/findings/review-queue must precede /v1/findings/{finding_id}
router.include_router(review.router)
router.include_router(findings.router)
router.include_router(decisions.router)
router.include_router(triage_records.router)
router.include_router(repository_findings.router)

__all__ = ["router"]
