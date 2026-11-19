"""The dashboard preset routes: the named queries SCI's cards reference."""

from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.dashboard import DashboardPreset, DashboardPresetQuery, DashboardResults
from traust_core.v1.rest.common.deps import Caller, CoreServices
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter(tags=["dashboards"])


@router.get("/v1/dashboards/presets", responses=PROBLEMS(401))
def list_dashboard_presets(_: Caller, services: CoreServices) -> tuple[DashboardPreset, ...]:
    """The named, code-defined queries: each resolves to the query body the
    query route takes; the repository filter is the caller's, applied when
    the preset runs."""
    return services.dashboards.presets()


@router.post("/v1/dashboards/presets/{preset_id}:query", responses=PROBLEMS(401, 422))
def query_dashboard_preset(
    preset_id: str, query: DashboardPresetQuery, _: Caller, services: CoreServices
) -> DashboardResults:
    """Run one preset over the caller's grant: the saved query with the
    request's repository filter. An unknown preset id refuses."""
    return services.dashboards.query_preset(preset_id, query)
