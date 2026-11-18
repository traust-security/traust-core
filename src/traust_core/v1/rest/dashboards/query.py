"""The dashboard query route: one POST, the access filter in the body."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.dashboard import DashboardQuery, DashboardResults
from traust_core.v1.rest.common.deps import Caller, CoreServices

router = APIRouter(tags=["dashboards"])


@router.post("/v1/dashboards:query")
def query_dashboard(query: DashboardQuery, _: Caller, services: CoreServices) -> DashboardResults:
    """One metrics query over the dashboard facts: a subject, the repository
    filter that trims the answer to a caller's access, allow-listed measures
    and dimensions. One statement; the answer is capped."""
    return services.dashboards.query(query)
