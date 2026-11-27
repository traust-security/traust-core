"""Reports as jobs: a request answers with the last ready build of the same request (200),
or the build queued or already in flight (202); a build that failed answers 409, naming
why. The file downloads once it is ready."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Response

from traust_core.v1.errors import ConflictError
from traust_core.v1.models.insight import ReportFormat
from traust_core.v1.models.reports import Report, ReportRequest, ReportStatus
from traust_core.v1.rest.common.deps import Caller, CoreServices
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter(tags=["reports"])

_FILE = {
    "description": "The built file, named by `Content-Disposition`",
    "content": {
        # json is the report document itself: the view's model, an object whose shape varies
        # by report; the other formats are its text renders. json first: generators type a
        # download by its first media type.
        f.media_type: {
            "schema": {"type": "object"} if f is ReportFormat.JSON else {"type": "string"}
        }
        for f in sorted(ReportFormat, key=lambda f: f is not ReportFormat.JSON)
    },
    "headers": {
        "Content-Disposition": {
            "description": "`attachment`; the built file's name",
            "schema": {"type": "string"},
        }
    },
}


@router.post("/v1/reports", responses={**PROBLEMS(401, 422, 409), 202: {"model": Report}})
def request_report(
    request: ReportRequest, caller: Caller, services: CoreServices, response: Response
) -> Report:
    """The last ready build of this report, format and scope (200), or the build queued or
    already in flight (202); a failed build is a 409, not an eternal in-progress. `refresh`
    builds anew; two callers asking at once share one build."""
    report = services.reports.request(request, caller)
    if report.status is ReportStatus.FAILED:
        raise ConflictError(
            f"report {report.order_id} failed: {report.reason or 'the build left no file'}"
        )
    if report.status is not ReportStatus.READY:
        response.status_code = 202
    return report


@router.get("/v1/reports/{order_id}", responses=PROBLEMS(401, 404))
def get_report(order_id: UUID, _: Caller, services: CoreServices) -> Report:
    """One build: its request, its status (queued, building, ready, failed), and its file's
    artifact once ready."""
    return services.reports.get(order_id)


@router.get(
    "/v1/reports/{order_id}/file",
    response_class=Response,
    responses={**PROBLEMS(401, 404, 409), 200: _FILE},
)
def get_report_file(order_id: UUID, _: Caller, services: CoreServices) -> Response:
    """The built file, named by `Content-Disposition`; 409 until the build is ready."""
    body, media_type, name = services.reports.file(order_id)
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
