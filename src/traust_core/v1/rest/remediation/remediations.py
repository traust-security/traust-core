from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.remediation import ExternalRef, ProgressReport, WorkItem
from traust_core.v1.models.remediation_scheduling import RemediationRequest, ScheduledEffort
from traust_core.v1.models.vocabulary import RemediationStatus
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.remediation.service import Remediation, Scheduling

router = APIRouter()

MAX_REPOSITORY_IDS = 500  # a page's worth, the orders filter's own bound


@router.post("/v1/remediations", responses=PROBLEMS(401, 403, 404, 409, 422))
def create_remediation(
    body: RemediationRequest, scheduling: Scheduling, caller: Caller
) -> ScheduledEffort:
    """Schedule a remediation — the fork the fix lands on and the findings to fix — opening
    the work item and the order that runs it. The entry point for SCI's automated trigger
    and the console's manual button: a verified person, or a machine granted
    `remediate_finding` on the repository in `recording.start`."""
    return scheduling.create(str(body.fork_url), body.fork_branch, body.findings, caller)


@router.get("/v1/remediations", responses=PROBLEMS(401, 422))
def list_remediations(
    scheduling: Scheduling,
    _: Caller,
    status: RemediationStatus | None = None,
    repository_id: UUID | None = None,
    finding_id: UUID | None = None,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[ScheduledEffort]:
    """Scheduled remediations, oldest first, a page at a time: at a status, on a repository,
    on a finding, or across several repositories (`repository_ids`, one read over the set —
    the batch shape the orders filter set; every filter given applies)."""
    if repository_ids and len(repository_ids) > MAX_REPOSITORY_IDS:
        raise ValidationError(
            f"list remediations for at most {MAX_REPOSITORY_IDS} repositories per request"
        )
    return scheduling.list(
        PageRequest(limit=limit, cursor=cursor),
        status=status,
        repository_id=repository_id,
        finding_id=finding_id,
        repository_ids=tuple(repository_ids or ()),
    )


@router.get("/v1/remediations/{work_item_id}", responses=PROBLEMS(401, 404))
def get_remediation(work_item_id: UUID, scheduling: Scheduling, _: Caller) -> ScheduledEffort:
    """One scheduled effort: its work item — the findings, the status folded from its
    decisions, the report once recorded — and the fork facts of the order that runs it."""
    return scheduling.get(work_item_id)


@router.post(
    "/v1/remediations/{work_item_id}/pull-request",
    responses=PROBLEMS(401, 403, 404, 409, 422),
)
def record_remediation_pull_request(
    work_item_id: UUID, body: ExternalRef, remediation: Remediation, caller: Caller
) -> WorkItem:
    """Attach the attempt's actual PR and advance it to `pr_opened`. A verified person, or
    a ServiceAccount granted `remediate_finding` on the repository in `recording.start` —
    the PR-filing loop records the PRs it opens, outside any order lease."""
    return remediation.record_pull_request(work_item_id, body, caller)


@router.post(
    "/v1/remediations/{work_item_id}/progress",
    responses=PROBLEMS(401, 403, 404, 409, 422),
)
def record_remediation_progress(
    work_item_id: UUID, body: ProgressReport, remediation: Remediation, caller: Caller
) -> WorkItem:
    """End a remediation attempt from outside a run — merged (the commit it merged as) or
    abandoned. The PR-filing loop's word: a verified person, or a machine granted
    `remediate_finding` on the repository in `recording.start`. A run's own statuses come
    from its report, never here."""
    return remediation.record_outcome(work_item_id, body, caller)
