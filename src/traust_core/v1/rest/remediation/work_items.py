from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.remediation import (
    RemediationInput,
    Verification,
    VerificationFilter,
    VerificationInput,
    WorkItem,
    WorkItemFilter,
)
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.remediation.service import Remediation, Verifications

router = APIRouter()

Limit = Annotated[int, Query(ge=1, le=1000)]


@router.get("/v1/repositories/{repository_id}/work-items", responses=PROBLEMS(401, 422))
def list_work_items(
    repository_id: UUID,
    remediation: Remediation,
    _: Caller,
    status: RemediationStatus | None = None,
    limit: Limit = 100,
    cursor: Cursor | None = None,
) -> Page[WorkItem]:
    """The repository's remediation work items oldest first, optionally at one status."""
    filter = WorkItemFilter(repository_id=repository_id, status=status)
    return remediation.list(filter, PageRequest(limit=limit, cursor=cursor))


@router.get("/v1/work-items/{work_item_id}/remediation-input", responses=PROBLEMS(401, 404))
def prepare_remediation(
    work_item_id: UUID, remediation: Remediation, _: Caller
) -> RemediationInput:
    return remediation.prepare(work_item_id)


@router.get("/v1/work-items/{work_item_id}/verification-input", responses=PROBLEMS(401, 404))
def prepare_verification(
    work_item_id: UUID, verifications: Verifications, _: Caller
) -> VerificationInput:
    return verifications.prepare(work_item_id)


@router.get("/v1/repositories/{repository_id}/verifications", responses=PROBLEMS(401, 422))
def list_verifications(
    repository_id: UUID,
    verifications: Verifications,
    _: Caller,
    work_item_id: UUID | None = None,
    limit: Limit = 100,
    cursor: Cursor | None = None,
) -> Page[Verification]:
    """The repository's verifications oldest first, optionally those of one work item."""
    filter = VerificationFilter(repository_id=repository_id, work_item_id=work_item_id)
    return verifications.list(filter, PageRequest(limit=limit, cursor=cursor))
