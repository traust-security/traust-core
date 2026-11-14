from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from pydantic import SerializeAsAny

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import ExecutivePanel, ViewFilter, ViewModel, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.rest.common.aware_datetime import UtcDatetime
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.insight.service import Insight

router = APIRouter()

Ids = Annotated[list[UUID] | None, Query()]
Labels = Annotated[list[str] | None, Query()]
Panels = Annotated[
    list[ExecutivePanel] | None,
    Query(description="The executive summary's optional panels to build (repeatable)."),
]


def scope(
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
    executive_panel: Panels = None,
) -> ViewFilter:
    """The view filter both insight routes read from their query: the JSON model and its
    rendered report scope the same way."""
    if (window_start is None) != (window_end is None):
        raise ValidationError("insight window requires both window_start and window_end")
    return ViewFilter(
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
        executive_panels=tuple(dict.fromkeys(executive_panel or ())),
    )


Scope = Annotated[ViewFilter, Depends(scope)]


@router.get("/v1/insights/{name}", responses=PROBLEMS(401, 404, 422))
def get_insight(
    name: ViewName,
    insight: Insight,
    _: Caller,
    response: Response,
    filter: Scope,
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
    served = insight.serve(name, filter, refresh=refresh)
    if served.built_at is not None:
        response.headers["X-Traust-View-Built-At"] = served.built_at.isoformat()
    return served.model


ReportFormat = Literal["markdown", "html", "csv"]
_MEDIA = {"markdown": "text/markdown", "html": "text/html", "csv": "text/csv"}
_SUFFIX = {"markdown": "md", "html": "html", "csv": "csv"}
_TEXT = {"type": "string"}


@router.get(
    "/v1/insights/{name}/report",
    response_class=Response,
    responses={
        **PROBLEMS(401, 404, 422),
        200: {"content": {media: {"schema": _TEXT} for media in _MEDIA.values()}},
    },
)
def get_insight_report(
    name: ViewName,
    insight: Insight,
    _: Caller,
    filter: Scope,
    format: Annotated[
        ReportFormat,
        Query(description="markdown or html for every insight; csv for one with an export table."),
    ] = "markdown",
) -> Response:
    """The insight rendered as a report on demand: the same view, scope and contract check
    as `GET /v1/insights/{name}`, built now (never a stored census build) and returned as one
    file, named by `Content-Disposition`. Nothing is stored. Titles, URLs and other recorded
    text are escaped in HTML and kept as data in Markdown and CSV."""
    rendered = insight.publish(name, filter)
    body = {"markdown": rendered.markdown, "html": rendered.html, "csv": rendered.csv}[format]
    if body is None:
        raise ValidationError(f"{name.value} has no export table; ask for markdown or html")
    return Response(
        content=body.encode(),
        media_type=f"{_MEDIA[format]}; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{rendered.stem}.{_SUFFIX[format]}"'
        },
    )
