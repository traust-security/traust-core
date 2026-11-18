from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.findings import (
    FindingCount,
    FindingExposure,
    FindingRollup,
    FindingSetFilter,
    FindingSort,
    FindingView,
    SortDirection,
)
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings
from traust_core.v1.services.findings.service import FindingWindow

router = APIRouter()

# A page's worth of repositories per request, the orders filter's own bound for its
# `repository_ids` shape: a set larger than this is a scope decision the route refuses
# to carry as one expanding statement (and one expanding query string).
MAX_REPOSITORY_IDS = 500


def _set_filter(
    repository_ids: list[UUID] | None,
    as_of: datetime | None,
    exposure: FindingExposure | None,
    severity: list[str] | None,
) -> FindingSetFilter:
    """The batch routes' shared refusal bounds and the set filter they serve: a named
    repository set (a page's worth, never a firehose of every finding), narrowed by the
    worklist's own cut — the census exposure classification and the effective-severity
    set, lowercased so a caller's spelling of a severity matches the fold's."""
    if not repository_ids:
        raise ValidationError("list findings for named repositories; the set is required")
    if len(repository_ids) > MAX_REPOSITORY_IDS:
        raise ValidationError(
            f"list findings for at most {MAX_REPOSITORY_IDS} repositories per request"
        )
    return FindingSetFilter(
        repository_ids=tuple(repository_ids),
        as_of=as_of,
        exposure=exposure.value if exposure is not None else None,
        severity=tuple(value.strip().lower() for value in severity or () if value.strip()),
    )


# Declared before /v1/findings/{finding_id}: a literal path must not be captured as a
# finding id the UUID parse would refuse.
@router.get("/v1/findings/summaries", responses=PROBLEMS(401, 422))
def summarize_findings_in(
    findings: Findings,
    _: Caller,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    as_of: datetime | None = None,
) -> list[FindingRollup]:
    """Several repositories' findings counted by state per repository — the batched
    `summary` under its one set-scoped dimension, so a consumer that renders each
    repository's census reads one call per bounded set instead of one summary per
    repository. A page's worth of repository ids per call, like the batch listing; no
    ids is a refusal, never a firehose of every finding. The per-repository route's
    other dimensions (severity, cwe, category) stay per repository: they span
    repositories, and a set-scoped group of them is the insight views' own shape."""
    if not repository_ids:
        raise ValidationError("summarize findings for named repositories; the set is required")
    if len(repository_ids) > MAX_REPOSITORY_IDS:
        raise ValidationError(
            f"summarize findings for at most {MAX_REPOSITORY_IDS} repositories per request"
        )
    return findings.summary_in(repository_ids, as_of)


# Declared before /v1/findings/{finding_id}: a literal path must not be captured as a
# finding id the UUID parse would refuse.
@router.get("/v1/findings/count", responses=PROBLEMS(401, 422))
def count_findings_in(
    findings: Findings,
    _: Caller,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    as_of: datetime | None = None,
    exposure: FindingExposure | None = None,
    severity: Annotated[list[str] | None, Query()] = None,
) -> FindingCount:
    """The filtered total a paged listing's pager reads: the same repository set and the
    same worklist cut as the batch listing, counted in one bounded census fold that
    holds no views — so a consumer serves its pager's number without walking every
    page of every row. The listing's refusal bounds are the count's own."""
    return findings.count_in(_set_filter(repository_ids, as_of, exposure, severity))


@router.get("/v1/findings/{finding_id}", responses=PROBLEMS(401, 404))
def get_finding(finding_id: UUID, findings: Findings, _: Caller) -> FindingView:
    return findings.get(finding_id)


@router.get("/v1/findings", responses=PROBLEMS(401, 422))
def list_findings_in(
    findings: Findings,
    _: Caller,
    repository_ids: Annotated[list[UUID] | None, Query()] = None,
    as_of: datetime | None = None,
    exposure: FindingExposure | None = None,
    severity: Annotated[list[str] | None, Query()] = None,
    sort: FindingSort = FindingSort.NEWEST,
    direction: SortDirection = SortDirection.ASC,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[FindingView]:
    """Several repositories' findings in one listing — `all_in` (the folded views of a
    repository set) paged with `list`'s cursor discipline, so a consumer whose scope
    spans repositories reads one paged walk instead of one listing per repository. A
    page's worth of repository ids per call, like the orders filter; no ids is a
    refusal, never a firehose of every finding.

    The worklist's own cut — the census exposure classification and the
    effective-severity set — applies inside the listing, and a sorted window (any
    `sort` but newest) serves the set's first `limit` rows under that column's order
    (`direction` flips it) as one bounded top-K fold with no cursor to follow: a
    consumer paging a worklist asks for the window its page needs (a wider `limit`)
    instead of walking every row itself. Columns the fold cannot order — a consumer's
    own repository or product spellings — stay the consumer's sort."""
    filter = _set_filter(repository_ids, as_of, exposure, severity)
    if sort is not FindingSort.NEWEST and cursor is not None:
        raise ValidationError("a sorted window pages by a wider limit, not a cursor")
    return findings.list_in(
        filter,
        PageRequest(limit=limit, cursor=cursor),
        FindingWindow(column=sort, direction=direction),
    )
