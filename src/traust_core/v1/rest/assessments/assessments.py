from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import SecurityAuditArtifact
from traust_core.v1.models.assessment import (
    Assessment,
    AssessmentFilter,
    AssessmentIntakeBindings,
    AssessmentKind,
    AssessmentRecordRequest,
    AssessmentRecordResult,
)
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.rest.assessments.service import Assessments
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter()

Status = Annotated[str | None, Query(max_length=64)]

# A page's worth of repositories per request, the batch routes' own bound (the orders
# filter's `repository_ids` shape): a set larger than this is a scope decision the
# route refuses to carry as one expanding statement.
MAX_REPOSITORY_IDS = 500


@router.get("/v1/assessments", responses=PROBLEMS(401, 422))
def list_assessments(
    assessments: Assessments,
    _: Caller,
    repository_ref_id: UUID | None = None,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    kind: AssessmentKind | None = None,
    status: Status = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[Assessment]:
    """A scope's assessments, newest first, cursor-paged — the batch findings
    listing's own shape (a collection narrowed by a query parameter). Exactly
    one scope: one ref's (`repository_ref_id`, the indexed single scope), or
    several repositories' (`repository_ids` — every ref of every repository
    named, one query per table over the set, never one per repository; a
    page's worth of ids per call, and no ids is a refusal, never a firehose
    of every assessment)."""
    has_ref, has_set = repository_ref_id is not None, bool(repository_ids)
    if has_ref == has_set:
        raise ValidationError(
            "list assessments for exactly one scope: a repository ref or a repository set"
        )
    if has_set:
        if len(repository_ids) > MAX_REPOSITORY_IDS:
            raise ValidationError(
                f"list assessments for at most {MAX_REPOSITORY_IDS} repositories per request"
            )
        return assessments.list_for_repositories(
            repository_ids, kind, PageRequest(limit=limit, cursor=cursor)
        )
    filter = AssessmentFilter(repository_ref_id=repository_ref_id, kind=kind, status=status)
    return assessments.list(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/assessments/{assessment_id}", responses=PROBLEMS(401, 404))
def get_assessment(assessment_id: UUID, assessments: Assessments, _: Caller) -> Assessment:
    return assessments.get(assessment_id)


@router.get(
    "/v1/assessments/{assessment_id}/intake",
    responses=PROBLEMS(401, 404, 409, 422),
)
def get_assessment_intake(
    assessment_id: UUID, assessments: Assessments, _: Caller
) -> AssessmentIntakeBindings:
    return assessments.intake_bindings(assessment_id)


@router.get("/v1/repositories/{repository_id}/assessments", responses=PROBLEMS(401))
def list_repository_assessments(
    repository_id: UUID,
    assessments: Assessments,
    _: Caller,
    kind: AssessmentKind | None = None,
) -> list[Assessment]:
    """Every assessment across the repository's refs, oldest first."""
    return assessments.list_for_repository(repository_id, kind)


@router.get(
    "/v1/repositories/{repository_id}/assessments/latest", responses=PROBLEMS(401, 404, 422)
)
def get_latest_recorded_assessment(
    repository_id: UUID, kind: AssessmentKind, assessments: Assessments, _: Caller
) -> Assessment:
    return assessments.latest_recorded(repository_id, kind)


@router.get("/v1/orders/{order_id}/assessments", responses=PROBLEMS(401))
def list_order_assessments(order_id: UUID, assessments: Assessments, _: Caller) -> list[Assessment]:
    """What a run order recorded, oldest first: how a consumer finds a finished order's results."""
    return assessments.list_for_order(order_id)


@router.post(
    "/v1/assessment-records",
    responses=PROBLEMS(401, 403, 404, 409, 422),
)
def record_assessment(
    body: AssessmentRecordRequest, assessments: Assessments, caller: Caller
) -> AssessmentRecordResult:
    try:
        payload = body.payload.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError("assessment payload must be UTF-8 text") from error
    return assessments.record_secure_code(
        SecurityAuditArtifact.parse(payload),
        body.repository_ref_id,
        body.assessor_version,
        body.provenance,
        run_order_id=body.run_order_id,
        principal=caller,
    )
