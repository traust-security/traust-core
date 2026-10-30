from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest, TimeBucket
from traust_core.v1.models.dependencies import (
    Advisory,
    Ecosystem,
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    ExposureSeriesPoint,
    ImpactAnalysis,
    ImpactFilter,
)
from traust_core.v1.models.vocabulary import ImpactClassification
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.exposure.service import Exposure

router = APIRouter()


def exposure_filter(
    advisory_id: UUID | None = None,
    ecosystem: Ecosystem | None = None,
    as_of: datetime | None = None,
) -> ExposureFilter:
    return ExposureFilter(advisory_id=advisory_id, ecosystem=ecosystem, as_of=as_of)


Filter = Annotated[ExposureFilter, Depends(exposure_filter)]


@router.get("/v1/impacts", responses=PROBLEMS(401, 422))
def list_impacts(
    exposure: Exposure,
    _: Caller,
    advisory_id: UUID | None = None,
    repository_ref_id: UUID | None = None,
    classification: ImpactClassification | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[ImpactAnalysis]:
    """Recorded impact analyses newest first; an advisory's aliases count as it."""
    filter = ImpactFilter(
        advisory_id=advisory_id, repository_ref_id=repository_ref_id, classification=classification
    )
    return exposure.impacts(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/exposure/summary", responses=PROBLEMS(401, 422))
def summarize_exposure(
    filter: Filter, exposure: Exposure, _: Caller, group_by: ExposureDimension
) -> list[ExposureRollup]:
    """The latest analysis of each commit per advisory, counted per group, largest first."""
    return exposure.summary(filter, group_by)


@router.get("/v1/exposure/timeline", responses=PROBLEMS(401, 422))
def exposure_timeline(
    filter: Filter, exposure: Exposure, _: Caller, bucket: TimeBucket = TimeBucket.MONTH
) -> list[ExposureSeriesPoint]:
    """The summary's counts at each bucket's end, up to `as_of`."""
    return exposure.timeline(filter, bucket)


@router.get("/v1/findings/{finding_id}/advisories", responses=PROBLEMS(401, 404))
def advisories_for(finding_id: UUID, exposure: Exposure, _: Caller) -> list[Advisory]:
    """The advisory the finding is about, canonical first, then its aliases."""
    return exposure.advisories_for(finding_id)


@router.get("/v1/feeds", responses=PROBLEMS(401))
def feed_statuses(exposure: Exposure, _: Caller) -> list[FeedStatus]:
    """Each advisory feed with when it was last fetched and how stale it may get."""
    return exposure.feed_statuses()
