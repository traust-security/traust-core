from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.findings import FindingSetFilter, FindingView
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()

# A page's worth of repositories per request, the orders filter's own bound for its
# `repository_ids` shape: a set larger than this is a scope decision the route refuses
# to carry as one expanding statement (and one expanding query string).
MAX_REPOSITORY_IDS = 500


@router.get("/v1/findings/{finding_id}", responses=PROBLEMS(401, 404))
def get_finding(finding_id: UUID, findings: Findings, _: Caller) -> FindingView:
    return findings.get(finding_id)


@router.get("/v1/findings", responses=PROBLEMS(401, 422))
def list_findings_in(
    findings: Findings,
    _: Caller,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    as_of: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[FindingView]:
    """Several repositories' findings newest first in one listing — `all_in` (the folded
    views of a repository set) paged with `list`'s cursor discipline, so a consumer whose
    scope spans repositories reads one paged walk instead of one listing per repository.
    A page's worth of repository ids per call, like the orders filter; no ids is a
    refusal, never a firehose of every finding."""
    if not repository_ids:
        raise ValidationError("list findings for named repositories; the set is required")
    if len(repository_ids) > MAX_REPOSITORY_IDS:
        raise ValidationError(
            f"list findings for at most {MAX_REPOSITORY_IDS} repositories per request"
        )
    return findings.list_in(
        FindingSetFilter(repository_ids=tuple(repository_ids), as_of=as_of),
        PageRequest(limit=limit, cursor=cursor),
    )
