from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest, TimeBucket
from traust_core.v1.models.findings import (
    FindingDimension,
    FindingFilter,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
)
from traust_core.v1.models.vocabulary import Validity
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()


def finding_filter(
    repository_id: UUID,
    validity: Validity | None = None,
    open: bool | None = None,
    as_of: datetime | None = None,
) -> FindingFilter:
    return FindingFilter(repository_id=repository_id, validity=validity, open=open, as_of=as_of)


Filter = Annotated[FindingFilter, Depends(finding_filter)]


@router.get("/v1/repositories/{repository_id}/findings", responses=PROBLEMS(401, 422))
def list_findings(
    filter: Filter,
    findings: Findings,
    _: Caller,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[FindingView]:
    """The repository's findings newest first, narrowed by their folded disposition."""
    return findings.list(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/repositories/{repository_id}/findings/summary", responses=PROBLEMS(401, 422))
def summarize_findings(
    filter: Filter, findings: Findings, _: Caller, group_by: FindingDimension
) -> list[FindingRollup]:
    """The repository's findings counted by state per group, largest first."""
    return findings.summary(filter, group_by)


@router.get("/v1/repositories/{repository_id}/findings/timeline", responses=PROBLEMS(401, 422))
def finding_timeline(
    filter: Filter, findings: Findings, _: Caller, bucket: TimeBucket = TimeBucket.MONTH
) -> list[FindingSeriesPoint]:
    """The repository's findings replayed bucket by bucket up to `as_of`."""
    return findings.timeline(filter, bucket)
