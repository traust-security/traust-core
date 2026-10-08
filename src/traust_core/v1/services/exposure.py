from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.exposure import Advisory, ImpactAnalysis
from traust_core.v1.models.operations import JobResult
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.repositories.exposure import ExposureUnitOfWork


class ExposureService:
    def __init__(self, uow: ExposureUnitOfWork) -> None:
        self._uow = uow

    def refresh_feed(self, feed: str) -> FeedStatus:
        raise NotImplementedError("stub: replaces fetch_feeds.py, registry/feeds.py")

    def resolve_advisory(self, identifier: str) -> Advisory | None:
        raise NotImplementedError("stub: replaces fetch_advisory.py, adapters/osv.py")

    def expand_symbols(self, advisory_id: UUID) -> JobResult:
        raise NotImplementedError(
            "stub: replaces resolve_advisory_symbols.py, expand_advisory_entry_points.py"
        )

    def analyze_impact(self, advisory_id: UUID) -> list[ImpactAnalysis]:
        raise NotImplementedError("stub: replaces impact/analyzer.py, run_impact_sweep.py")

    def dependents(self, repository_id: UUID) -> list[UUID]:
        raise NotImplementedError("stub: replaces portfolio/graph.py, build_repo_graph.py")

    def reconcile_cve_provenance(self, finding_id: UUID) -> Advisory | None:
        raise NotImplementedError("stub: replaces reconcile_cve_provenance.py")
