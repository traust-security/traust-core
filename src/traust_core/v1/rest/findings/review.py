from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.findings import ReviewCase, ReviewCaseKind, ReviewFilter
from traust_core.v1.models.vocabulary import ReviewItemStatus, ReviewReason
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()


@router.get("/v1/findings/review-queue", responses=PROBLEMS(401, 422))
def review_queue(
    findings: Findings,
    _: Caller,
    status: ReviewItemStatus = ReviewItemStatus.PENDING,
    reason: ReviewReason | None = None,
    kind: ReviewCaseKind | None = None,
    finding_id: UUID | None = None,
    repository_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[ReviewCase]:
    """Fold states and pending review items needing a person, oldest first, cursor-paged."""
    filter = ReviewFilter(
        status=status, reason=reason, kind=kind, finding_id=finding_id, repository_id=repository_id
    )
    return findings.review.queue(filter, PageRequest(limit=limit, cursor=cursor))
