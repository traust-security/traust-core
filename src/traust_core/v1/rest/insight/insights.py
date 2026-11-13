from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Response
from pydantic import SerializeAsAny

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.rest.common.aware_datetime import UtcDatetime
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.insight.service import Insight

router = APIRouter()

Ids = Annotated[list[UUID] | None, Query()]
Labels = Annotated[list[str] | None, Query()]


@router.get("/v1/insights/{name}", responses=PROBLEMS(401, 404, 422))
def get_insight(
    name: ViewName,
    insight: Insight,
    _: Caller,
    response: Response,
    product_id: Ids = None,
    team_id: Ids = None,
    as_of: UtcDatetime | None = None,
    bucket: TimeBucket = TimeBucket.MONTH,
    artifact_id: UUID | None = None,
    repository_id: UUID | None = None,
    category: Labels = None,
    window_start: UtcDatetime | None = None,
    window_end: UtcDatetime | None = None,
    repository_ref_id: Ids = None,
    chokepoint: Labels = None,
    framework: ComplianceFramework | None = None,
    precision_gate: Annotated[float | None, Query(ge=0, le=1, allow_inf_nan=False)] = None,
    refresh: Annotated[
        bool, Query(description="Fold the view on demand, ignoring any stored census build.")
    ] = False,
) -> SerializeAsAny[ViewModel]:
    """One insight (a dashboard, rollup or export such as SARIF) for a scope at `as_of`; one
    route for every insight, so a new one needs no route or SDK release.

    An unscoped census read (findings-rollup, coverage, remediation-index, findings-trend) is
    served from the newest stored build — one GLOBAL census, up to one dashboards cadence
    (5-15 minutes) stale, never past a person's judgement, never past the serving bound
    (30 minutes: a stalled builder folds instead of lying), and never when a build has yet to
    be recorded (the first read folds). `X-Traust-View-Built-At` names the moment the served
    census was read. A scoped filter, or `refresh`, folds on demand."""
    if (window_start is None) != (window_end is None):
        raise ValidationError("insight window requires both window_start and window_end")
    filter = ViewFilter(
        product_ids=tuple(product_id or ()),
        team_ids=tuple(team_id or ()),
        categories=tuple(category or ()),
        as_of=as_of,
        bucket=bucket,
        window=(
            TimeWindow(start=window_start, end=window_end)
            if window_start is not None and window_end is not None
            else None
        ),
        artifact_id=artifact_id,
        repository_id=repository_id,
        repository_ref_ids=None if repository_ref_id is None else tuple(repository_ref_id),
        pqc_chokepoints=tuple(chokepoint or ()),
        framework=framework,
        precision_gate=precision_gate,
    )
    served = insight.serve(name, filter, refresh=refresh)
    if served.built_at is not None:
        response.headers["X-Traust-View-Built-At"] = served.built_at.isoformat()
    return served.model
