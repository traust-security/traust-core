from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.models.common import Cursor, Page, PageRequest
from traust_core.v1.models.validation import ValidationAttempt, ValidationFilter
from traust_core.v1.models.vocabulary import ValidationVerdict
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.validation.service import Validation

router = APIRouter()


@router.get("/v1/validation-attempts", responses=PROBLEMS(401, 404, 422))
def list_validation_attempts(
    validation: Validation,
    _: Caller,
    finding_id: UUID | None = None,
    repository_id: Annotated[list[UUID] | None, Query()] = None,
    verdict: ValidationVerdict | None = None,
    as_of: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    cursor: Cursor | None = None,
) -> Page[ValidationAttempt]:
    """Recorded validation attempts newest first, narrowed to a finding, repositories or verdict."""
    filter = ValidationFilter(
        finding_id=finding_id,
        repository_ids=frozenset(repository_id) if repository_id else None,
        verdict=verdict,
        as_of=as_of,
    )
    return validation.list(filter, PageRequest(limit=limit, cursor=cursor))
