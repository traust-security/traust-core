from __future__ import annotations

from decimal import Decimal
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import SerializeAsAny

from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewModel, ViewName
from traust_core.v1.rest.common.aware_datetime import UtcDatetime
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.insight.service import Insight

router = APIRouter()

Ids = Annotated[list[UUID] | None, Query()]


@router.get("/v1/insights/{name}", responses=PROBLEMS(401, 404, 422))
def get_insight(
    name: ViewName,
    insight: Insight,
    _: Caller,
    product_id: Ids = None,
    team_id: Ids = None,
    category: Annotated[list[str] | None, Query()] = None,
    as_of: UtcDatetime | None = None,
    bucket: TimeBucket = TimeBucket.MONTH,
    artifact_id: UUID | None = None,
    panel: Annotated[list[ExecutivePanel] | None, Query()] = None,
    by_segment: bool = False,
    exclude_segment: Annotated[list[str] | None, Query()] = None,
    assessment_id: UUID | None = None,
    report_stem: str | None = None,
    compare_as_of: UtcDatetime | None = None,
    first_party_divisor: Annotated[Decimal | None, Query(gt=0, allow_inf_nan=False)] = None,
    reprice_spend: bool = False,
    workstation_spend: bool = False,
) -> SerializeAsAny[ViewModel]:
    """One insight (a dashboard, rollup or export such as SARIF) for a scope at `as_of`, built on
    demand; one route for every insight, so a new one needs no route or SDK release."""
    filter = ViewFilter(
        product_ids=tuple(product_id or ()),
        team_ids=tuple(team_id or ()),
        categories=tuple(category or ()),
        as_of=as_of,
        bucket=bucket,
        artifact_id=artifact_id,
        executive_panels=tuple(panel or ()),
        by_segment=by_segment,
        exclude_segments=tuple(("ansible",) if exclude_segment is None else exclude_segment),
        assessment_id=assessment_id,
        report_stem=report_stem,
        compare_as_of=compare_as_of,
        first_party_divisor=first_party_divisor,
        reprice_spend=reprice_spend,
        workstation_spend=workstation_spend,
    )
    return insight.build(name, filter)
