from __future__ import annotations

import logging
from collections import defaultdict
from uuid import UUID

from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryIdentifier,
    AdvisoryPackage,
    AdvisoryRecord,
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
    SbomContents,
    Version,
    VexStatus,
    parse_advisory_identifier,
)
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.models.sbom_formats import parse_sbom
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import (
    AdvisoryLookup,
    FeedProvider,
    FeedStatus,
    validate_payload,
)
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import record_artifact
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.portfolio import PortfolioService

FEED_ARTIFACT_KIND = "feed"
SBOM_ARTIFACT_KIND = "sbom"

log = logging.getLogger(__name__)


class ExposureService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        *,
        feeds: ProviderRegistry[FeedProvider],
        objects: ObjectStore,
        advisories: AdvisoryLookup | None = None,
        portfolio: PortfolioService | None = None,
    ) -> None:
        self._uow = uow
        self._intake = intake
        self._feeds = feeds
        self._objects = objects
        self._advisories = advisories
        self._portfolio = portfolio

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

    def ingest_sbom(self, raw: bytes, repository_ref_id: UUID) -> Sbom:
        """A commit's manifest SBOM (CycloneDX / SPDX JSON from standard tools). The same package
        list again, in either format, is the same SBOM; only its first document is kept."""
        portfolio = self._require_portfolio()
        contents = parse_sbom(raw)
        with self._uow as uow:
            sbom = uow.sboms.find_by_digest(contents.digest) or self._add_sbom(uow, raw, contents)
            uow.commit()
        assert sbom.id is not None
        portfolio.record_manifest_sbom(repository_ref_id, sbom.id)
        log.info(
            "sbom %s for ref %s: %d packages, %d components without a modeled package",
            sbom.id,
            repository_ref_id,
            len(contents.entries),
            contents.skipped,
        )
        return sbom

    def _add_sbom(self, uow: TraustUnitOfWork, raw: bytes, contents: SbomContents) -> Sbom:
        stored = self._objects.put(ObjectKey.parse(f"sboms/{sha256_hex(raw)}.json"), raw)
        artifact = record_artifact(
            uow, Artifact(digest=stored.sha256, kind=SBOM_ARTIFACT_KIND, uri=str(stored.key))
        )
        sbom = uow.sboms.get_or_add(Sbom(digest=contents.digest, artifact_id=artifact.id))
        assert sbom.id is not None
        packages = uow.packages.get_or_add_many(
            [Package(ecosystem=e.ecosystem, name=e.name) for e in contents.entries]
        )
        uow.dependencies.add_many(
            [
                Dependency(sbom_id=sbom.id, package_id=p.id, version=e.version, direct=e.direct)
                for e, p in zip(contents.entries, packages, strict=True)
                if p.id is not None
            ]
        )
        return sbom

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

    def packages_affected(self, advisory_id: UUID) -> list[AdvisoryPackage]:
        with self._uow as uow:
            return uow.advisory_packages.list_for_advisory(advisory_id)

    def verify_dependency(self, package: Package, version: Version) -> DependencyProvenance:
        raise NotImplementedError("stub: replaces verify_dep_provenance.py")

    def reconcile_provenance(self, finding_id: UUID) -> ProvenanceCheck:
        raise NotImplementedError("stub: replaces reconcile_cve_provenance.py")

    def get_advisory(self, advisory_id: UUID) -> Advisory:
        with self._uow as uow:
            return uow.advisories.get(advisory_id)

    def find_advisory(self, identifier: AdvisoryIdentifier) -> AdvisoryRecord | None:
        """The advisory as its source states it now (ranges are never taken from memory);
        its identity, aliases and affected packages are kept on the way through."""
        if self._advisories is None:
            raise ConfigError("find_advisory needs an advisory lookup (the feeds registry's osv)")
        record = self._advisories.record(parse_advisory_identifier(identifier)).data
        if record is None:
            return None
        with self._uow as uow:
            advisory = self._keep_advisory(uow, record)
            uow.commit()
        return record.model_copy(update={"advisory_id": advisory.id})

    def _keep_advisory(self, uow: TraustUnitOfWork, record: AdvisoryRecord) -> Advisory:
        # Aliases join the first one already known, so one vulnerability keeps one canonical row.
        names = [record.identifier, *record.aliases]
        known = [a for a in map(uow.advisories.find_by_identifier, names) if a is not None]
        if known:
            first = known[0]
            canonical = uow.advisories.get(first.alias_of_id) if first.alias_of_id else first
        else:
            canonical = uow.advisories.get_or_add(
                Advisory(identifier=record.identifier, published_at=record.published_at)
            )
        assert canonical.id is not None
        for name in {n for n in names if n != canonical.identifier} - {a.identifier for a in known}:
            published = record.published_at if name == record.identifier else None
            uow.advisories.get_or_add(
                Advisory(alias_of_id=canonical.id, identifier=name, published_at=published)
            )
        for affected in record.affected:
            package = uow.packages.get_or_add(
                Package(ecosystem=affected.ecosystem, name=affected.name)
            )
            assert package.id is not None
            uow.advisory_packages.get_or_add(
                AdvisoryPackage(advisory_id=canonical.id, package_id=package.id)
            )
        return canonical

    def advisories_for(self, finding_id: UUID) -> list[Advisory]:
        raise NotImplementedError("stub: replaces enrich_findings_cves.py")

    def affected(self, advisory_id: UUID) -> list[AffectedDependency]:
        """Commits and images whose SBOM reaches the advisory's packages: directly, through a
        base image, or through an internal library another repository produces."""
        portfolio = self._require_portfolio()
        with self._uow as uow:
            advisory = uow.advisories.get(advisory_id)
            links = uow.advisory_packages.list_for_advisory(advisory.alias_of_id or advisory_id)
            vulnerable = {link.package_id for link in links}
            reached: dict[UUID, Dependency] = {}
            refs: dict[UUID, RepositoryRef] = {}
            started: set[UUID] = set()
            start = set(vulnerable)
            while start:  # one round per hop: a base image, or an internal library
                started |= start
                found = uow.dependencies.list_for_packages(start)
                reached |= {d.id: d for d in found if d.id is not None}
                sboms = {d.sbom_id for d in found}
                built = portfolio.list_refs_by_manifest(sboms)
                refs |= {r.id: r for r in built if r.id is not None}
                carriers = uow.packages.list_with_sboms(
                    sboms
                ) + uow.packages.list_from_repositories({r.repository_id for r in built})
                start = {p.id for p in carriers if p.id is not None} - started
            images = uow.images.list_with_sboms({d.sbom_id for d in reached.values()})
        holders: dict[UUID, list[tuple[UUID | None, UUID | None]]] = defaultdict(list)
        for ref in refs.values():
            assert ref.manifest_sbom_id is not None
            holders[ref.manifest_sbom_id].append((ref.id, None))
        for image in images:
            assert image.sbom_id is not None
            holders[image.sbom_id].append((image.repository_ref_id, image.id))
        return [
            AffectedDependency(
                repository_ref_id=ref_id,
                image_id=image_id,
                dependency=d,
                vulnerable=d.package_id in vulnerable,
            )
            for d in reached.values()
            for ref_id, image_id in holders[d.sbom_id]
        ]

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

    def _require_portfolio(self) -> PortfolioService:
        if self._portfolio is None:
            raise ConfigError("dependency reads and SBOM intake need the portfolio service")
        return self._portfolio

    def feed_status(self, feed: FeedName) -> FeedStatus:
        max_age = self._feeds.get(feed).max_age
        with self._uow as uow:
            latest = uow.feed_snapshots.latest(feed)
        fetched_at = latest.retrieved_at if latest is not None else None
        return FeedStatus(name=feed, fetched_at=fetched_at, max_age=max_age)
