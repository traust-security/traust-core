from __future__ import annotations

from uuid import UUID

from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryIdentifier,
    AdvisoryPackage,
    AffectedDependency,
    Dependency,
    DependencyIngest,
    DependencyProvenance,
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    FeedName,
    ImpactAnalysis,
    ImpactFilter,
    ImpactInput,
    Package,
    ProvenanceCheck,
    Sbom,
    Version,
    VexStatus,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider, FeedStatus, validate_payload
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import record_artifact
from traust_core.v1.services.findings.intake import FindingIntake

FEED_ARTIFACT_KIND = "feed"


class ExposureService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        *,
        feeds: ProviderRegistry[FeedProvider],
        objects: ObjectStore,
    ) -> None:
        self._uow = uow
        self._intake = intake
        self._feeds = feeds
        self._objects = objects

    def refresh_feed(self, feed: FeedName, run_order_id: UUID | None = None) -> FeedStatus:
        """Fetch, validate and snapshot one feed; a failed fetch raises and writes nothing."""
        provider = self._feeds.get(feed)
        result = provider.fetch()
        validate_payload(result.data, provider.filename)
        key = ObjectKey.parse(f"feeds/{feed}/{sha256_hex(result.data)}/{provider.filename}")
        ref = self._objects.put(key, result.data)
        with self._uow as uow:
            artifact = record_artifact(
                uow, Artifact(digest=ref.sha256, kind=FEED_ARTIFACT_KIND, uri=str(ref.key))
            )
            latest = uow.feed_snapshots.latest(feed)
            retried = (
                latest is not None
                and latest.artifact_id == artifact.id
                and latest.run_order_id == run_order_id
            )
            if not retried:
                assert artifact.id is not None
                uow.feed_snapshots.add(
                    FeedSnapshot(
                        run_order_id=run_order_id,
                        artifact_id=artifact.id,
                        feed=feed,
                        retrieved_at=result.acquisition.acquired_at,
                    )
                )
            uow.commit()
        return self.feed_status(feed)

    def ingest_sbom(self, artifact_id: UUID) -> Sbom:
        """CycloneDX / SPDX from standard tools; deduplicated by normalized package-list digest."""
        raise NotImplementedError("stub: replaces portfolio/graph.build_deps, parsers.py")

    def ingest_dependencies(self, repository_ref_id: UUID) -> DependencyIngest:
        raise NotImplementedError("stub: replaces portfolio/graph.build_deps, parsers.py")

    def resolve_symbols(self, advisory_id: UUID) -> UUID:
        """Symbols land as an artifact; returns its artifact id."""
        raise NotImplementedError(
            "stub: replaces resolve_advisory_symbols.py, expand_advisory_entry_points.py"
        )

    def prepare(self, advisory_id: UUID, repository_ref_id: UUID) -> ImpactInput:
        raise NotImplementedError("stub: replaces impact/analyzer evidence collection")

    def record(self, doc: ImpactAnalysisArtifact, provenance: Provenance) -> ImpactAnalysis:
        raise NotImplementedError("stub: replaces impact/analyzer.emit_impact_analysis")

    def affects(self, advisory_id: UUID, package_id: UUID, version: Version) -> bool:
        raise NotImplementedError("stub: replaces dependency-watch/fleet_sweep.fixed_range")

    def fixed_in(self, advisory_id: UUID, package_id: UUID) -> Version | None:
        raise NotImplementedError("stub: replaces adapters/osv.fixed_version")

    def packages_affected(self, advisory_id: UUID) -> list[AdvisoryPackage]:
        raise NotImplementedError("stub: advisory -> package links from feeds")

    def verify_dependency(self, package: Package, version: Version) -> DependencyProvenance:
        raise NotImplementedError("stub: replaces verify_dep_provenance.py")

    def reconcile_provenance(self, finding_id: UUID) -> ProvenanceCheck:
        raise NotImplementedError("stub: replaces reconcile_cve_provenance.py")

    def get_advisory(self, advisory_id: UUID) -> Advisory:
        raise NotImplementedError("stub: exposure read")

    def find_advisory(self, identifier: AdvisoryIdentifier) -> Advisory | None:
        raise NotImplementedError("stub: replaces fetch_advisory.py")

    def advisories_for(self, finding_id: UUID) -> list[Advisory]:
        raise NotImplementedError("stub: replaces enrich_findings_cves.py")

    def affected(self, advisory_id: UUID) -> list[AffectedDependency]:
        raise NotImplementedError("stub: replaces fleet_sweep.py, run_impact_sweep.py")

    def dependencies(self, repository_ref_id: UUID) -> list[Dependency]:
        raise NotImplementedError("stub: replaces portfolio-graph dependency reads")

    def dependents(self, package_id: UUID) -> list[UUID]:
        raise NotImplementedError("stub: replaces portfolio/graph dependents, smoke_deps_multi")

    def impacts(self, filter: ImpactFilter, page: PageRequest) -> Page[ImpactAnalysis]:
        raise NotImplementedError("stub: replaces impact_analysis reads")

    def summary(self, filter: ExposureFilter, group_by: ExposureDimension) -> list[ExposureRollup]:
        raise NotImplementedError("stub: replaces *_exposure queries, exposure_trend")

    def vex_status(self, advisory: AdvisoryIdentifier, product_id: UUID) -> VexStatus | None:
        raise NotImplementedError("stub: replaces fetch_feeds.vex_product_status")

    def feed_status(self, feed: FeedName) -> FeedStatus:
        max_age = self._feeds.get(feed).max_age
        with self._uow as uow:
            latest = uow.feed_snapshots.latest(feed)
        fetched_at = latest.retrieved_at if latest is not None else None
        return FeedStatus(name=feed, fetched_at=fetched_at, max_age=max_age)
