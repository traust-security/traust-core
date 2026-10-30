from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import SerializeAsAny

from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.insight.service import Insight

router = APIRouter()

Ids = Annotated[list[UUID] | None, Query()]


@router.get("/v1/views/{view}", responses=PROBLEMS(401, 404, 422))
def build_view(
    view: ViewName,
    insight: Insight,
    _: Caller,
    product_id: Ids = None,
    team_id: Ids = None,
    as_of: datetime | None = None,
    bucket: TimeBucket = TimeBucket.MONTH,
    artifact_id: UUID | None = None,
) -> SerializeAsAny[ViewModel]:
    """One dashboard view's model for a scope (products, teams) at `as_of`; one door for every
    view, so a new view needs no new route."""
    filter = ViewFilter(
        product_ids=tuple(product_id or ()),
        team_ids=tuple(team_id or ()),
        as_of=as_of,
        bucket=bucket,
        artifact_id=artifact_id,
    )
    return insight.build(view, filter)
