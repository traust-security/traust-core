from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.assessment import Assessment, AssessmentFilter, AssessmentKind
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.rest.assessments.service import Assessments
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter()

Status = Annotated[str | None, Query(max_length=64)]


@router.get("/v1/assessments", responses=PROBLEMS(401, 422))
def list_assessments(
    assessments: Assessments,
    _: Caller,
    repository_ref_id: UUID,
    kind: AssessmentKind | None = None,
    status: Status = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Assessment]:
    """A ref's assessments, newest first; repository_ref_id is required (the indexed scope)."""
    filter = AssessmentFilter(repository_ref_id=repository_ref_id, kind=kind, status=status)
    return assessments.list(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/assessments/{assessment_id}", responses=PROBLEMS(401, 404))
def get_assessment(assessment_id: UUID, assessments: Assessments, _: Caller) -> Assessment:
    return assessments.get(assessment_id)


@router.get("/v1/repositories/{repository_id}/assessments", responses=PROBLEMS(401))
def list_repository_assessments(
    repository_id: UUID,
    assessments: Assessments,
    _: Caller,
    kind: AssessmentKind | None = None,
) -> list[Assessment]:
    """Every assessment across the repository's refs, oldest first."""
    return assessments.list_for_repository(repository_id, kind)
