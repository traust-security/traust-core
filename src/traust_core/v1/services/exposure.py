from __future__ import annotations

import difflib
import gzip
import json
import logging
import re
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import JsonValue, TypeAdapter, computed_field

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    ImpactAnalysisArtifact,
    ManifestCoverageArtifact,
)
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.base import Model
from traust_core.v1.models.code_facts import PackageModule
from traust_core.v1.models.common import Page, PageRequest, Provenance, TimeBucket
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryIdentifier,
    AdvisoryMatch,
    AdvisoryPackage,
    AdvisoryRecord,
    AdvisorySweep,
    AffectedDependency,
    AffectedPackage,
    ArtifactSignals,
    ConsumedVersion,
    Dependency,
    DependencyIngest,
    ExploitSignal,
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    ExposureSeriesPoint,
    FeedName,
    FixUptake,
    FixUptakeState,
    Image,
    ImpactAnalysis,
    ImpactEvidence,
    ImpactExport,
    ImpactExportRepo,
    ImpactFilter,
    ImpactInput,
    ImpactPreparationScope,
    ImpactQuery,
    ImpactScopeMember,
    InternalCoupling,
    ItemSignals,
    NoImageSbomError,
    NoManifestSbomError,
    Package,
    PackageAdvisories,
    PackageVersion,
    ProvenanceCheck,
    ProvenanceMatch,
    ProvenanceReconciliation,
    ProvenanceReportRow,
    RefDependency,
    RepositoryReach,
    Sbom,
    SbomContents,
    SweepStatus,
    SweptAdvisory,
    SymbolConfidence,
    SymbolResolution,
    SymbolSource,
    SymbolStatus,
    UnresolvedManifest,
    Version,
    VexStatus,
    VulnerableSymbol,
    is_advisory_identifier,
    package_name,
    parse_advisory_identifier,
    repo_label,
    version_key,
)
from traust_core.v1.models.findings import (
    Category,
    ExposureKey,
    FindingCandidate,
    FindingContext,
    Label,
)
from traust_core.v1.models.fix_commits import changed_functions, fix_commits
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS, RepositoryRef
from traust_core.v1.models.operations import FeedSnapshot
from traust_core.v1.models.sbom_formats import parse_sbom
from traust_core.v1.models.values import CveId, GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    DependencyEvidenceLevel,
    Ecosystem,
    ImpactClassification,
    ImpactManifestScan,
    ImpactSbomScan,
    ImpactSourceImportScan,
    ImpactSymbolUsageScan,
    ImpactTier,
    ScannerSeverity,
)
from traust_core.v1.providers.analysis import ImpactAnalyzer
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.feeds import (
    AdvisoryLookup,
    FeedProvider,
    FeedSource,
    FeedStatus,
    PublishedCve,
    epss_scores,
    kev_entries,
    rh_cve_records,
    validate_payload,
)
from traust_core.v1.providers.package_source import (
    cargo_requires,
    go_direct_requires,
    requirements_names,
)
from traust_core.v1.providers.sources import CheckoutRequest, SourceError, SourceProvider
from traust_core.v1.providers.syft import MANIFESTS, unresolved_manifests
from traust_core.v1.providers.tools import ToolProvider, ToolRequest
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey, ObjectStore
from traust_core.v1.services.artifact_publishing import (
    AssessmentLog,
    record_artifact,
    stored_bytes,
)
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.records import FindingRecords
from traust_core.v1.services.portfolio import Inventory, PortfolioService
from traust_core.v1.services.repo_checkout import RepoCheckoutService

if TYPE_CHECKING:
    from traust_core.v1.services.findings.service import FindingService

FEED_ARTIFACT_KIND = "feed"
EPSS, KEV, RH_CVE = FeedName("epss"), FeedName("kev"), FeedName("rh-cve")
# Title likeness that stamps a CVE on a finding: 53 hand-adjudicated matches at >= 0.55 held no
# false one. A shared CWE promotes probable to confirmed; it never blocks (sibling CWEs are common).
AUTO_CONFIRM, AUTO_PROBABLE = 0.75, 0.55
_TITLE_STOP = frozenset(
    re.findall(
        r"\w+",
        "the a an of to in on for and or with without via is are not no by from at as it its cve",
    )
)
SBOM_ARTIFACT_KIND = "sbom"
IMPACT_ASSESSOR = "impact-analysis"
SUPPLY_CHAIN = "supply-chain"
DEEP_SCAN_CAP = 100  # more commits than this: SBOM evidence now, deep scans staged by an operator
# Sweep order and the --min-severity floor; unrated (no declared severity) ranks below low.
SEVERITY_RANK = {
    ScannerSeverity.CRITICAL: 4,
    ScannerSeverity.HIGH: 3,
    ScannerSeverity.MEDIUM: 2,
    ScannerSeverity.LOW: 1,
    ScannerSeverity.INFORMATIONAL: 0,
    ScannerSeverity.UNRATED: 0,
}
_IMPACT_RANK = {
    ImpactClassification.AFFECTED: 5,
    ImpactClassification.LIKELY_AFFECTED: 4,
    ImpactClassification.INCONCLUSIVE: 3,
    ImpactClassification.NOT_OBSERVED: 2,
    ImpactClassification.VERSION_NOT_IN_RANGE: 1,
    ImpactClassification.NOT_IMPORTED: 0,
}
MAX_FIX_COMMITS = 4  # backports repeat the same change; more commits only add API calls
REACHED_THROUGH = "reached through a base image or an internal library; not listed itself"
SURFACE = "{} surface: manifest-level, no reachability"
UNRESOLVED = "not in the SBOM, but these manifests could not be resolved: {}"
_TICK = timedelta(microseconds=1)
_SURFACES = frozenset({Ecosystem.ACTIONS, Ecosystem.DOCKER, Ecosystem.HELM})
# Ecosystems whose evidence stops at the pin (no reachability tool): the SBOM is the manifest tier.
_MANIFEST_TIER = _SURFACES | {
    Ecosystem.NPM,
    Ecosystem.PYPI,
    Ecosystem.CARGO,
    Ecosystem.MAVEN,
    Ecosystem.RUBY,
    Ecosystem.NUGET,
}

# EPSS asks for attribution when its scores are passed on; KEV is CC0.
EXPLOIT_ATTRIBUTION = "EPSS at https://www.first.org/epss; KEV is CC0-1.0"
_ITEM_LISTS = ("findings", "candidates")
_ITEM_KEYS = ("id", "fingerprint", "osv_id")

log = logging.getLogger(__name__)


class ExploitContext(Model):
    """An enrichment tagger's join: EPSS and KEV on every CVE-bearing item, the repository's
    product reach, and the feed snapshots read. Routes attention; never a severity or a verdict."""

    artifacts: tuple[ArtifactSignals, ...]
    reach: RepositoryReach | None
    feeds: tuple[FeedStatus, ...]
    attribution: str = EXPLOIT_ATTRIBUTION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def items_with_cves(self) -> int:
        return sum(len(a.items) for a in self.artifacts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def kev_hits(self) -> int:
        return sum(i.kev_any for a in self.artifacts for i in a.items)


class ExposureService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        intake: FindingIntake,
        *,
        feeds: ProviderRegistry[FeedProvider],
        objects: ObjectStore,
        feed_sources: ProviderRegistry[FeedSource] | None = None,
        advisories: AdvisoryLookup | None = None,
        portfolio: PortfolioService | None = None,
        clock: Clock | None = None,
        analyzers: Sequence[ImpactAnalyzer] = (),
        sources: SourceProvider | None = None,
        hosts: Mapping[str, str] = DEFAULT_FORGE_HOSTS,
        sbom_tool: ToolProvider[bytes] | None = None,
        findings: FindingService | None = None,
        checkout: RepoCheckoutService | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._findings = FindingRecords(uow)
        self._intake = intake
        self._feeds = feeds
        self._feed_sources = feed_sources or ProviderRegistry[FeedSource]("feed-source")
        self._objects = objects
        self._advisories = advisories
        self._portfolio = portfolio
        self._clock = clock or SystemClock()
        self._analyzers = tuple(analyzers)
        self._sources = sources
        self._hosts = hosts
        self._sbom_tool = sbom_tool
        self._checkout = checkout
        self._finding_service = findings

    def refresh_feeds(
        self, feeds: Sequence[FeedName] | None = None, run_order_id: UUID | None = None
    ) -> list[FeedStatus]:
        """Refresh the named feeds (default: every registered one); one that fails keeps its last
        snapshot and says why in ``last_error``, so the others still refresh."""
        statuses = []
        for feed in feeds if feeds is not None else map(FeedName, self._feeds.names()):
            try:
                statuses.append(self.refresh_feed(feed, run_order_id))
            except (ServiceError, ValidationError) as e:
                log.warning(
                    "feed %s not refreshed; using last snapshot error_type=%s",
                    feed,
                    type(e).__name__,
                )
                statuses.append(self.feed_status(feed).model_copy(update={"last_error": str(e)}))
            except (NotFoundError, IntegrityError, RepositoryError) as e:
                # The last snapshot an incremental feed builds on is unreadable: a person acts.
                log.error("feed %s snapshot unreadable error_type=%s", feed, type(e).__name__)
                statuses.append(self.feed_status(feed).model_copy(update={"last_error": str(e)}))
        return statuses

    def refresh_feed(self, feed: FeedName, run_order_id: UUID | None = None) -> FeedStatus:
        """Fetch, validate and snapshot one feed; a failed fetch raises and writes nothing."""
        provider = self._feeds.get(feed)
        result = provider.fetch(lambda: self.feed_payload(feed))
        validate_payload(result.data, provider.filename)
        key = ObjectKey.parse(f"feeds/{feed}/{sha256_hex(result.data)}/{provider.filename}")
        ref = self._objects.put(key, result.data)
        with self._uow as uow:
            artifact = record_artifact(
                uow, Artifact(digest=ref.sha256, kind=FEED_ARTIFACT_KIND, uri=str(ref.key))
            )
            latest = uow.feed_snapshots.latest(feed)
            retried = (
                run_order_id is not None
                and latest is not None
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

    def ingest_sbom(
        self,
        raw: bytes,
        repository_ref_id: UUID,
        *,
        declared_direct: frozenset[tuple[Ecosystem, str, str | None]] | None = None,
    ) -> Sbom:
        """A commit's manifest SBOM (CycloneDX / SPDX JSON from standard tools). The same package
        list again, in either format, is the same SBOM; only its first document is kept.
        `declared_direct`: (ecosystem, name, version-or-None) the checkout's manifests
        declare, the direct set syft's graph omits for Go, Rust and requirements-file
        Python."""
        portfolio = self._require_portfolio()
        contents = parse_sbom(raw, declared_direct)
        with self._uow as uow:
            sbom = uow.sboms.find_by_digest(contents.digest) or self._add_sbom(uow, raw, contents)
            uow.commit()
        assert sbom.id is not None
        portfolio.record_manifest_sbom(repository_ref_id, sbom.id)
        return sbom

    def ingest_image_sbom(
        self,
        raw: bytes,
        digest: str,
        platform: str | None = None,
        repository_ref_id: UUID | None = None,
    ) -> Image:
        """An image's SBOM, stored as `ingest_sbom` stores a manifest's, on the image's row.
        Image rows are append-only: the same digest again must name the same SBOM, platform and
        commit (`repository_ref_id` only from declared provenance, never inferred)."""
        contents = parse_sbom(raw)
        with self._uow as uow:
            sbom = uow.sboms.find_by_digest(contents.digest) or self._add_sbom(uow, raw, contents)
            wanted = Image(
                digest=digest,
                platform=platform,
                repository_ref_id=repository_ref_id,
                sbom_id=sbom.id,
            )
            image, created = uow.images.get_or_add_with_status(wanted)
            held = (image.sbom_id, image.platform, image.repository_ref_id)
            if held != (sbom.id, platform, repository_ref_id):
                raise ConflictError(
                    f"image {digest} already recorded with sbom {image.sbom_id}, platform "
                    f"{image.platform}, ref {image.repository_ref_id}; image rows are append-only"
                )
            uow.commit()
        if created:
            self._uow.after_commit(
                lambda: log.info(
                    "sbom %s for image %s: %d packages, %d components without a modeled package",
                    sbom.id,
                    image.id,
                    len(contents.entries),
                    contents.skipped,
                )
            )
        return image

    def _add_sbom(self, uow: TraustUnitOfWork, raw: bytes, contents: SbomContents) -> Sbom:
        stored = self._objects.put(
            ObjectKey.parse(f"sboms/{sha256_hex(raw)}.json.gz"), gzip.compress(raw, mtime=0)
        )
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

    def record_manifest_sbom(self, repository_ref_id: UUID) -> Sbom:
        """The commit's manifest SBOM: the one recorded, else the SBOM tool's over the commit's
        manifests, fetched from its forge (the fleet sweep's door; a re-run never fetches)."""
        ref, repository = self._inventory.resolve(repository_ref_id)
        if ref.manifest_sbom_id is not None:
            with self._uow as uow:
                return uow.sboms.get(ref.manifest_sbom_id)
        if self._checkout is None:
            raise ConfigError("record_manifest_sbom needs a checkout provider (Context wires one)")
        self._require_sbom_tool()
        fetched = self._checkout.checkout(
            CheckoutRequest(repo=repository.url, ref=GitSha.parse(ref.sha), keep=MANIFESTS)
        ).data
        try:
            return self.ingest_dependencies(repository_ref_id, fetched.path).sbom
        finally:
            self._checkout.release(fetched)

    def _require_sbom_tool(self) -> ToolProvider[bytes]:
        if self._sbom_tool is None:
            raise ConfigError("ingest_dependencies needs the SBOM tool (Context wires syft)")
        if not (ready := self._sbom_tool.check()).ready:
            raise ConfigError(f"{self._sbom_tool.name}: {ready.detail}")
        return self._sbom_tool

    def ingest_dependencies(self, repository_ref_id: UUID, checkout: Path) -> DependencyIngest:
        """The commit's manifest SBOM, read from its checkout by the SBOM tool (syft) and
        ingested, with a `manifest-coverage` record of what it could not resolve written first,
        so a failure before the SBOM lands is retried whole; the same package list again is the
        same SBOM."""
        sbom_tool = self._require_sbom_tool()
        unresolved = unresolved_manifests(checkout)
        scanned = sbom_tool.acquire(ToolRequest(workspace=checkout))
        tool, version = scanned.acquisition.provider, scanned.acquisition.version
        if version is None:
            raise ServiceError(f"{tool} reported no version; its coverage can't be attributed")
        coverage = ManifestCoverageArtifact.from_document(
            {
                "artifact": "manifest-coverage",
                "tool": {"name": tool, "version": version},
                "unresolved": [m.model_dump(mode="json") for m in unresolved],
            }
        )
        latest = self._latest_coverage(repository_ref_id)
        if latest is None or latest.digest != sha256_hex(coverage.payload):
            with self._uow as uow:
                ref = self._inventory.get_ref(repository_ref_id)
                self._record_document(
                    uow,
                    ref,
                    coverage,
                    AssessmentKind.MANIFEST_SBOM,
                    tool,
                    version,
                    self._clock.now(),
                    reuse=False,
                )
                uow.commit()
        # syft's manifest scan emits no dependency edges for Go (go.mod), Rust
        # (Cargo.lock) or a requirements file's Python (verified: each tree's
        # dependencies graph is empty), so every such package would key indirect. The
        # manifests the archive keeps are the direct truth: go.mod requires (pinned),
        # Cargo.toml's [dependencies] crates and requirements files' packages (named,
        # matched at any version — the manifest states constraints, not pins).
        declared = {
            (Ecosystem.GO, module, version) for module, version in go_direct_requires(checkout)
        }
        declared |= {
            (Ecosystem.CARGO, crate, version) for crate, version in cargo_requires(checkout)
        }
        declared |= {
            (Ecosystem.PYPI, package_name(Ecosystem.PYPI, name), None)
            for name in requirements_names(checkout)
        }
        sbom = self.ingest_sbom(
            scanned.data, repository_ref_id, declared_direct=frozenset(declared)
        )

        return DependencyIngest(
            repository_ref_id=repository_ref_id,
            sbom=sbom,
            tool=tool,
            tool_version=version,
            unresolved=unresolved,
        )

    def unresolved_manifests(self, repository_ref_id: UUID) -> tuple[UnresolvedManifest, ...]:
        """The manifests the SBOM tool could not resolve on the commit, from its latest
        `manifest-coverage` record; none recorded (an SBOM ingested as a document) is none known."""
        latest = self._latest_coverage(repository_ref_id)
        if latest is None:
            return ()
        doc = ManifestCoverageArtifact.parse(stored_bytes(self._objects, latest))
        return tuple(
            UnresolvedManifest.model_validate(m, from_attributes=True) for m in doc.unresolved
        )

    def _latest_coverage(self, repository_ref_id: UUID) -> Artifact | None:
        held = self._log.documents(
            self._log.list_of(AssessmentKind.MANIFEST_SBOM, [repository_ref_id]),
            [ManifestCoverageArtifact.schema],
        )
        return held[0][1] if held else None

    def resolve_symbols(self, advisory_id: UUID) -> SymbolResolution:
        """The functions the advisory's fix touched: what its source publishes (Go's OSV
        imports), else the changed declarations of the fix commits on it and its aliases."""
        advisory = self.get_advisory(advisory_id)
        record = self.find_advisory(AdvisoryIdentifier(advisory.identifier))
        if record is None:
            raise NotFoundError(f"advisory {advisory.identifier}: unknown to its source")
        return _published(record) or self._mined(record)

    def _mined(self, record: AdvisoryRecord) -> SymbolResolution:
        records = [record]
        unread = [f"advisory {name}" for name in record.unreadable_aliases]
        for name in dict.fromkeys(record.upstream):
            try:
                upstream = self._require_lookup().record(name).data
            except ServiceError:
                unread.append(f"advisory {name}")
                continue
            records += [upstream] if upstream else []
        commits, pulls = fix_commits(url for r in records for url in r.references)
        if not commits:
            if unread:
                note = f"unreadable: {', '.join(unread)}; the fix may be on one of them"
                return SymbolResolution(status=SymbolStatus.DEGRADED, note=note)
            note = f"{len(pulls)} pull request reference(s), not followed" if pulls else None
            return SymbolResolution(status=SymbolStatus.NO_FIX_COMMIT, note=note)
        sources = self._require_sources()
        found: dict[str, VulnerableSymbol] = {}
        for commit in commits[:MAX_FIX_COMMITS]:
            try:
                repo = HttpsRepoUrl.parse(f"https://{commit.host}/{commit.repo}", self._hosts)
                files = sources.commit(repo, commit.sha).data.files
            except (ValidationError, SourceError):
                unread.append(commit.url)
                continue
            for symbol in changed_functions(commit.url, [(f.filename, f.patch) for f in files]):
                known = found.get(symbol.symbol)
                if known is None or symbol.confidence == SymbolConfidence.HIGH:
                    found[symbol.symbol] = symbol
        symbols = tuple(sorted(found.values(), key=lambda s: s.symbol))
        return SymbolResolution(
            status=SymbolStatus.DEGRADED
            if unread
            else SymbolStatus.RESOLVED
            if symbols
            else SymbolStatus.NO_SYMBOLS_IN_DIFF,
            symbols=symbols,
            fix_commits=tuple(c.url for c in commits[:MAX_FIX_COMMITS]),
            note=f"unreadable: {', '.join(unread)}"
            if unread
            else None
            if symbols
            else "no changed function: likely a data fix (deny-list, table, version bump)",
        )

    def _require_sources(self) -> SourceProvider:
        if self._sources is None:
            raise ConfigError("fix-commit symbols need a source provider (Context wires the forge)")
        return self._sources

    def prepare(
        self,
        advisory_id: UUID,
        repository_ref_id: UUID,
        checkout: Path | None = None,
        judged: Sequence[str] = (),
    ) -> tuple[ImpactInput, ...]:
        """Prepare each reached ecosystem/package/version, retaining its own ranges and fix."""
        prepared_at = self._clock.now()
        advisory = self.get_advisory(advisory_id)
        record = self.find_advisory(AdvisoryIdentifier(advisory.identifier))
        if record is None or not record.affected:
            raise NotFoundError(f"advisory {advisory.identifier}: its source names no package")
        if record.unreadable_aliases:
            raise ServiceError(
                f"advisory {advisory.identifier}: incomplete alias evidence; "
                f"unreadable: {', '.join(record.unreadable_aliases)}"
            )
        candidates: list[tuple[AffectedPackage, list[AffectedDependency]]] = []
        for package in record.affected:
            with self._uow as uow:
                kept = uow.packages.find(package.ecosystem, package.name)
            rows = (
                [
                    AffectedDependency(
                        repository_ref_id=ref_id,
                        image_id=image_id,
                        dependency=dependency,
                        vulnerable=dependency.package_id == kept.id,
                    )
                    for dependency, ref_id, image_id in self._reach({kept.id})
                    if ref_id == repository_ref_id
                ]
                if kept is not None and kept.id is not None
                else []
            )
            candidates.append((package, rows))
        reached = [(package, rows) for package, rows in candidates if rows]
        prepared = []
        for package, rows in reached or candidates:
            manifest = {r.dependency.version for r in rows if r.vulnerable and r.image_id is None}
            versions = sorted(manifest or {r.dependency.version for r in rows if r.vulnerable})
            for version in versions or [None]:
                selected = [
                    r
                    for r in rows
                    if not r.vulnerable
                    or (bool(manifest) and r.image_id is not None)
                    or r.dependency.version == version
                ]
                prepared.append(
                    self._prepare(record, package, repository_ref_id, selected, checkout, judged)
                )
        members = tuple(item.scope_member for item in prepared)
        with self._uow as uow:
            ref = self._inventory.get_ref(repository_ref_id)
            images = uow.images.list_built_from(repository_ref_id)
        snapshot = {
            "prepared_at": prepared_at.isoformat(),
            "advisory": record.model_dump(mode="json", exclude={"advisory_id"}),
            "manifest_sbom_id": str(ref.manifest_sbom_id),
            "images": sorted((str(image.id), str(image.sbom_id)) for image in images),
            "members": [member.model_dump(mode="json") for member in members],
        }
        scope = ImpactPreparationScope(
            digest=sha256_hex(json.dumps(snapshot, sort_keys=True).encode()),
            members=members,
        )
        return tuple(
            item.model_copy(update={"preparation_scope": scope, "prepared_at": prepared_at})
            for item in prepared
        )

    def _prepare(
        self,
        record: AdvisoryRecord,
        package: AffectedPackage,
        repository_ref_id: UUID,
        rows: list[AffectedDependency],
        checkout: Path | None,
        judged: Sequence[str],
    ) -> ImpactInput:
        portfolio = self._require_portfolio()
        with self._uow as uow:
            subject = self._inventory.subject(repository_ref_id)
            scanned = any(i.sbom_id for i in uow.images.list_built_from(repository_ref_id))
        named = {r.dependency.package_id: package for r in rows if r.vulnerable}
        listed = any(r.image_id is None for r in rows)
        in_manifest = [r.dependency for r in rows if r.vulnerable and r.image_id is None]
        in_images = [r.dependency for r in rows if r.vulnerable and r.image_id is not None]
        in_range, shipped = _in_range(in_manifest, named), _in_range(in_images, named)
        pinned = in_manifest and package.ecosystem in _MANIFEST_TIER
        evidence = ImpactEvidence(
            l1_depends_on=True if listed else None if rows else False,
            l1_version_in_range=in_range,
            manifest_version=in_manifest[0].version if in_manifest else None,
            manifest_scan=None
            if not pinned or in_range is None
            # an undecided range is unobserved, not in range — the tier never asserts
            # a pin it could not check (classification reads IN_RANGE as likely_affected)
            else ImpactManifestScan.MODULE_PINNED_OUT_OF_RANGE
            if in_range is False
            else ImpactManifestScan.MODULE_PINNED_IN_RANGE,
            sbom_scan=None
            if not scanned
            else ImpactSbomScan.MODULE_NOT_IN_SBOM
            if not in_images
            else ImpactSbomScan.SHIPPED_OUT_OF_RANGE
            if shipped is False
            else ImpactSbomScan.SHIPPED_IN_RANGE,
            sbom_shipped_version=in_images[0].version if in_images else None,
            notes="; ".join(
                n
                for n in (
                    REACHED_THROUGH if listed and not in_manifest else None,
                    SURFACE.format(package.ecosystem) if package.ecosystem in _SURFACES else None,
                )
                if n
            )
            or None,
        )
        tiers = [ImpactTier.L1]
        tiers += [ImpactTier.SBOM_CROSS_CHECK] if scanned else []
        tiers += [ImpactTier.MANIFEST_SCAN] if pinned else []
        undecided = (ImpactClassification.INCONCLUSIVE, ImpactClassification.LIKELY_AFFECTED)
        symbols = _with_judged(None, judged)
        if checkout is not None and evidence.classification(package.ecosystem) in undecided:
            # govulncheck carries its own symbol data: Go never mines fix commits.
            scoped = record.model_copy(update={"affected": (package,)})
            found = _published(scoped) or (
                None if package.ecosystem == Ecosystem.GO else self._mined(record)
            )
            symbols = _with_judged(found, judged)
            query = ImpactQuery(
                advisory=scoped,
                package=package,
                symbols=tuple(s.symbol for s in symbols.symbols) if symbols else (),
            )
            evidence, ran = self._analyze(query, checkout, evidence)
            tiers += ran
        return ImpactInput(
            subject=subject,
            findings=FindingContext(),
            prepared_at=self._clock.now(),
            advisory=record,
            package=package,
            dependencies=tuple(rows),
            evidence=evidence,
            products=tuple(p.slug for p in portfolio.list_products_shipping(repository_ref_id)),
            tiers=tuple(tiers),
            symbols=symbols,
        )

    def _analyze(
        self, query: ImpactQuery, checkout: Path, evidence: ImpactEvidence
    ) -> tuple[ImpactEvidence, list[ImpactTier]]:
        """Each analyzer for the ecosystem adds what it observed; one that can't run says so in
        the notes, never as a finding of nothing."""
        ran: list[ImpactTier] = []
        notes = [evidence.notes]
        for analyzer in self._analyzers:
            if query.package.ecosystem not in analyzer.ecosystems:
                continue
            ready = analyzer.check()
            if not ready.ready:
                notes.append(f"{analyzer.name} skipped: {ready.detail}")
                continue
            found = analyzer.evidence(query, ToolRequest(workspace=checkout)).data
            observed = found.model_dump(exclude_none=True, exclude={"notes"})
            evidence = evidence.model_copy(update=observed)
            notes.append(found.notes)
            ran.append(analyzer.tier)
        level = (
            DependencyEvidenceLevel.SYMBOL
            if evidence.govulncheck
            else DependencyEvidenceLevel.SYMBOL_USAGE
            if evidence.symbol_usage_scan == ImpactSymbolUsageScan.SYMBOLS_USED
            else DependencyEvidenceLevel.MANIFEST
            if evidence.manifest_scan
            or evidence.source_import_scan == ImpactSourceImportScan.IMPORTS_FOUND
            else DependencyEvidenceLevel.NONE
        )
        joined = "; ".join(n for n in notes if n) or None
        return evidence.model_copy(update={"evidence_level": level, "notes": joined}), ran

    def record(
        self, repository_ref_id: UUID, doc: ImpactAnalysisArtifact, provenance: Provenance
    ) -> ImpactAnalysis:
        """One commit's impact analysis as an `impact` assessment with its document; an
        `affected` commit also gets its dependency finding, owned and on the SLA clock from now.
        Recording the same document again changes nothing."""
        doc = ImpactAnalysisArtifact.parse(doc.payload)
        if len(doc.repos) != 1:
            raise ValidationError(f"impact analysis covers {len(doc.repos)} commits, not one")
        [entry] = doc.repos
        classification = ImpactClassification(entry.classification)
        ecosystem = getattr(doc.metadata, "ecosystem", None)
        raw_scope = getattr(doc.metadata, "preparation_scope", None)
        scope = None
        if raw_scope is not None:
            if ecosystem is None:
                raise ValidationError("scoped impact analysis requires an ecosystem")
            scope = ImpactPreparationScope.model_validate(raw_scope, from_attributes=True)
            member = ImpactScopeMember(
                ecosystem=Ecosystem(ecosystem),
                module=doc.metadata.module,
                version=Version(entry.version) if entry.version is not None else None,
            )
            if member not in scope.members:
                raise ValidationError(f"impact analysis {member}: not in its preparation scope")
        expected = ImpactEvidence.model_validate(
            entry.evidence, from_attributes=True
        ).classification(Ecosystem(ecosystem) if ecosystem else Ecosystem.GO)
        if classification != expected:
            raise ValidationError(
                f"impact analysis of {entry.repo}: classification {classification} "
                f"contradicts evidence ({expected})"
            )
        record = self.find_advisory(AdvisoryIdentifier(doc.metadata.cve))
        if record is None or record.advisory_id is None:
            raise NotFoundError(f"advisory {doc.metadata.cve}: unknown to its source")
        if scope is not None:
            previous = self._recorded(
                ImpactFilter(advisory_id=record.advisory_id, repository_ref_id=repository_ref_id),
                include_findings=False,
            )
            for row in previous:
                raw_previous = getattr(row.doc.metadata, "preparation_scope", None)
                if raw_previous is None:
                    continue
                kept = ImpactPreparationScope.model_validate(raw_previous, from_attributes=True)
                if kept.digest == scope.digest and frozenset(kept.members) != frozenset(
                    scope.members
                ):
                    raise ValidationError(
                        f"impact preparation scope {scope.digest}: inconsistent member set"
                    )
        with self._uow as uow:
            ref, repository = self._inventory.resolve(repository_ref_id)
            if entry.repo != repo_label(repository.url):
                raise ValidationError(f"impact analysis of {entry.repo}, not {repository.url}")
            assessment, artifact, created = self._record_document(
                uow,
                ref,
                doc,
                AssessmentKind.IMPACT,
                IMPACT_ASSESSOR,
                str(doc.metadata.harness_version),
                provenance.occurred_at,
            )
            canonical = uow.advisories.get(record.advisory_id)
            assert (
                assessment.id is not None and artifact.id is not None and canonical.id is not None
            )
            finding_id = None
            if classification == ImpactClassification.AFFECTED:
                candidate = _exposure_candidate(repository.id, doc, record, canonical)
                finding_id = self._intake.accept(assessment.id, [candidate]).findings[
                    candidate.label
                ]
            uow.commit()
        if created:
            self._uow.after_commit(
                lambda: log.info(
                    "impact of advisory %s on ref %s: %s",
                    canonical.id,
                    repository_ref_id,
                    classification,
                )
            )
        return ImpactAnalysis(
            assessment_id=assessment.id,
            artifact_id=artifact.id,
            repository_ref_id=repository_ref_id,
            advisory_id=canonical.id,
            classification=classification,
            finding_id=finding_id,
        )

    def _record_document(
        self,
        uow: TraustUnitOfWork,
        ref: RepositoryRef,
        doc: ArtifactDocument,
        kind: AssessmentKind,
        assessor: str,
        assessor_version: str,
        occurred_at: datetime,
        *,
        reuse: bool = True,
    ) -> tuple[Assessment, Artifact, bool]:
        """`doc` as the artifact of a `kind` assessment on the commit; with `reuse`, the same
        bytes again are the assessment already recorded."""
        assert ref.id is not None
        digest = sha256_hex(doc.payload)
        schema = doc.schema
        if reuse and (recorded := self._log.find_recorded([ref.id], kind, schema, digest)):
            assessment, artifact = recorded[0]
            return assessment, artifact, False
        assessment = self._log.open(
            Assessment(
                repository_ref_id=ref.id,
                kind=kind,
                status=ASSESSMENT_COMPLETED,
                assessor=assessor,
                assessor_version=assessor_version,
                occurred_at=occurred_at,
            )
        )
        stored = self._objects.put(
            ObjectKey.parse(f"artifacts/{schema}/{digest}.json"), doc.payload
        )
        artifact = record_artifact(
            uow,
            Artifact(
                assessment_id=assessment.id, digest=stored.sha256, kind=schema, uri=str(stored.key)
            ),
        )
        return assessment, artifact, True

    def packages_affected(self, advisory_id: UUID) -> list[AdvisoryPackage]:
        with self._uow as uow:
            return uow.advisory_packages.list_for_advisory(advisory_id)

    def sweep(
        self,
        min_severity: ScannerSeverity = ScannerSeverity.CRITICAL,
        scan_cap: int = DEEP_SCAN_CAP,
        ecosystems: Collection[Ecosystem] = (),
    ) -> AdvisorySweep:
        """Which known advisories touch the recorded SBOMs at all: every package version they
        hold, asked of the advisory source, each advisory kept with its packages. Unanswered
        versions make the sweep degraded, never clean; nothing answered makes it failed."""
        lookup = self._require_lookup()
        if not (ready := lookup.check()).ready:
            return AdvisorySweep(status=SweepStatus.FAILED, package_versions=0, detail=ready.detail)
        covered = set(ecosystems or lookup.ecosystems) & lookup.ecosystems
        with self._uow as uow:
            versions = uow.dependencies.list_versions()
            packages = {p.id: p for p in uow.packages.list_by_ids({pid for pid, _ in versions})}
        held = [PackageVersion(package=packages[pid], version=Version(v)) for pid, v in versions]
        queries = [q for q in held if q.package.ecosystem in covered]
        skipped = len(held) - len(queries)
        if skipped:
            log.info("sweep: %d package versions in ecosystems not swept", skipped)
        if not queries:
            return AdvisorySweep(
                status=SweepStatus.FAILED,
                package_versions=0,
                skipped=skipped,
                detail="no recorded SBOM holds a package the advisory source covers",
            )
        hits = lookup.affecting(queries).data
        unanswered = tuple(
            str(q) for q, found in zip(queries, hits.ids, strict=True) if found is None
        )
        if len(unanswered) == len(queries):
            return AdvisorySweep(
                status=SweepStatus.FAILED,
                package_versions=len(queries),
                skipped=skipped,
                unanswered=unanswered,
                issues=hits.issues,
                detail="the advisory source answered no package version",
            )
        hit: dict[str, set[PackageVersion]] = defaultdict(set)
        for query, found in zip(queries, hits.ids, strict=True):
            for raw in found or ():
                hit[raw].add(query)
        records, missing, rejected = self._sweep_records(lookup, sorted(hit))
        best: dict[UUID, tuple[AdvisoryRecord, set[PackageVersion]]] = {}
        for record in records:
            assert record.advisory_id is not None
            touched = set().union(*(hit[n] for n in (record.identifier, *record.aliases)))
            kept = best.get(record.advisory_id)
            if kept is None:
                best[record.advisory_id] = (record, touched)
            else:
                top, other = sorted((kept[0], record), key=lambda r: -SEVERITY_RANK[r.severity])
                best[record.advisory_id] = (top.merge(other), kept[1] | touched)
        rows = [
            self._swept(record, touched, scan_cap)
            for record, touched in best.values()
            if SEVERITY_RANK[record.severity] >= SEVERITY_RANK[min_severity]
        ]
        rows.sort(key=lambda r: (not r.malicious, -SEVERITY_RANK[r.severity], -r.commits))
        degraded = unanswered or missing
        return AdvisorySweep(
            status=SweepStatus.DEGRADED if degraded else SweepStatus.COMPLETE,
            package_versions=len(queries),
            skipped=skipped,
            unanswered=unanswered,
            issues=hits.issues,
            details_missing=missing,
            rejected=tuple(rejected),
            advisories=tuple(rows),
        )

    def package_advisories(
        self, ecosystem: Ecosystem, name: str, version: Version
    ) -> PackageAdvisories:
        """The advisories affecting one package version, from the advisory source (OSV by
        package and version); an unanswered query raises, never reads as no advisories."""
        lookup = self._require_lookup()
        if ecosystem not in lookup.ecosystems:
            raise ValidationError(f"{lookup.name} can't answer {ecosystem} packages by name")
        query = PackageVersion(
            package=Package(ecosystem=ecosystem, name=package_name(ecosystem, name)),
            version=version,
        )
        hits = lookup.affecting([query]).data
        if (found := hits.ids[0]) is None:
            raise ServiceError(f"{lookup.name} did not answer {query}: {hits.issues}")
        records, missing, rejected = self._sweep_records(lookup, sorted(set(found)))
        return PackageAdvisories(
            package=str(query),
            advisories=tuple(records),
            rejected=tuple(rejected),
            details_missing=missing,
        )

    def _sweep_records(
        self, lookup: AdvisoryLookup, ids: Sequence[str]
    ) -> tuple[list[AdvisoryRecord], int, list[str]]:
        records, missing, rejected = [], 0, []
        for raw in ids:
            try:
                identifier = parse_advisory_identifier(raw)
            except ValidationError:
                rejected.append(raw)
                continue
            try:
                record = lookup.record(identifier).data
            except (ServiceError, ValidationError) as e:
                log.warning("advisory %s not fetched error_type=%s", identifier, type(e).__name__)
                record = None
            if record is None:
                missing += 1
                continue
            with self._uow as uow:
                advisory = self._keep_advisory(uow, record)
                uow.commit()
            records.append(record.model_copy(update={"advisory_id": advisory.id}))
        return records, missing, rejected

    def _swept(
        self, record: AdvisoryRecord, held: set[PackageVersion], scan_cap: int
    ) -> SweptAdvisory:
        assert record.advisory_id is not None
        versions = {(q.package.id, q.version) for q in held}
        commits = {  # the commits pinning a version the source named: what a deep scan clones
            a.repository_ref_id
            for a in self.affected(record.advisory_id)
            if a.repository_ref_id is not None
            and (a.dependency.package_id, a.dependency.version) in versions
        }
        return SweptAdvisory(
            advisory_id=record.advisory_id,
            identifier=record.identifier,
            display_id=record.display_id,
            malicious=record.malicious,
            severity=record.severity,
            summary=record.summary,
            packages=tuple(sorted({f"{q.package.ecosystem}/{q.package.name}" for q in held})),
            commits=len(commits),
            scan=len(commits) <= scan_cap,
            fix_available=_fix_stated(record, held),
        )

    def _require_lookup(self) -> AdvisoryLookup:
        if self._advisories is None:
            raise ConfigError("advisory reads need an advisory lookup (the feeds registry's osv)")
        return self._advisories

    def reconcile_provenance(self, finding_id: UUID) -> ProvenanceCheck:
        """Link an unnamed finding to its best later CVE, using its first report date."""
        findings = self._require_findings()
        reported = findings.occurrences(finding_ids=[finding_id])
        if not reported:
            raise NotFoundError(f"finding {finding_id}: never reported, so no first report")
        view = findings.get(finding_id)
        runs = self._log.list_by_ids({o.assessment_id for o in reported})
        first = min(a.occurred_at for a in runs).astimezone(UTC).date()
        url = self._inventory.get_repository(view.finding.repository_id).url
        component = url.rstrip("/").rsplit("/", 1)[-1].lower()
        matches = sorted(
            (
                found
                for cve in rh_cve_records(self._required_payload(RH_CVE))
                if (found := _provenance(cve, component, first, view.finding.title, view.cwes))
            ),
            key=lambda m: (m.match != AdvisoryMatch.CONFIRMED, -m.score, m.identifier),
        )
        check = self._provenance_check(finding_id, matches)
        with self._uow as uow:
            check = self._link_provenance(check)
            uow.commit()
        return check

    def reconcile_all_provenance(
        self, *, min_score: float = AUTO_PROBABLE, apply: bool = False
    ) -> ProvenanceReconciliation:
        """Match every code audit against later CVEs; only explicit apply records finding links."""
        if not 0 <= min_score <= 1:
            raise ValidationError("provenance min_score must be between 0 and 1")
        findings = self._require_findings()
        cves = rh_cve_records(self._required_payload(RH_CVE))
        by_component: dict[str, list[PublishedCve]] = defaultdict(list)
        for cve in sorted(cves, key=lambda c: c.identifier):
            if cve.component:
                by_component[cve.component.lower()].append(cve)
        runs = [
            run
            for kind in sorted({AssessmentKind.SECURE_CODE, AssessmentKind.SECURE_CODE_CANONICAL})
            for run in self._log.list_of(kind)
        ]
        refs = {
            ref.id: ref
            for ref in self._inventory.list_refs_by_ids({run.repository_ref_id for run in runs})
        }
        components = {
            repository_id: self._inventory.get_repository(repository_id)
            .url.rstrip("/")
            .rsplit("/", 1)[-1]
            .removesuffix(".git")
            .lower()
            for repository_id in {ref.repository_id for ref in refs.values()}
        }
        rows: list[ProvenanceReportRow] = []
        for run in sorted(runs, key=lambda a: (a.occurred_at, a.id)):
            assert run.id is not None
            ref = refs[run.repository_ref_id]
            component = components[ref.repository_id]
            audit_date = run.occurred_at.astimezone(UTC).date()
            candidates = findings.list_by_ids(
                {o.finding_id for o in findings.occurrences(assessment_id=run.id)}
            )
            for cve in by_component.get(component, ()):
                best: ProvenanceReportRow | None = None
                for view in sorted(candidates, key=lambda v: str(v.finding.id)):
                    match = _provenance(
                        cve, component, audit_date, view.finding.title, view.cwes, min_score
                    )
                    if match is not None and (best is None or match.score > best.score):
                        assert view.finding.id is not None
                        best = ProvenanceReportRow(
                            **dict(match),
                            assessment_id=run.id,
                            repository_ref_id=run.repository_ref_id,
                            repository_id=ref.repository_id,
                            component=component,
                            audit_date=audit_date,
                            finding_id=view.finding.id,
                            finding_title=view.finding.title,
                        )
                if best is not None:
                    rows.append(best)
        matches_by_finding: dict[UUID, list[ProvenanceMatch]] = defaultdict(list)
        for row in rows:
            matches_by_finding[row.finding_id].append(
                ProvenanceMatch.model_validate(
                    {name: getattr(row, name) for name in ProvenanceMatch.model_fields}
                )
            )
        checks = {
            finding_id: self._provenance_check(finding_id, matches)
            for finding_id, matches in matches_by_finding.items()
        }
        pairs = {(row.finding_id, row.identifier) for row in rows}
        known = {
            (ref.finding_id, ref.ref) for ref in self._findings.external_refs(list(checks), "cve")
        }
        planned = pairs - known
        written = linked = 0
        if apply:
            with self._uow as uow:
                for check in checks.values():
                    linked += int(self._link_provenance(check).linked)
                for finding_id, identifier in sorted(planned):
                    written += int(self._findings.link_external(finding_id, "cve", identifier))
                uow.commit()
        return ProvenanceReconciliation(
            apply=apply,
            min_score=min_score,
            cves=len(cves),
            reports=len(runs),
            matches=tuple(
                row.model_copy(update={"conflict": checks[row.finding_id].conflict}) for row in rows
            ),
            links_planned=len(planned),
            links_written=written,
            findings_linked=linked,
        )

    def _provenance_check(
        self, finding_id: UUID, matches: Sequence[ProvenanceMatch]
    ) -> ProvenanceCheck:
        named = [a.identifier for a in self.advisories_for(finding_id)]
        conflict = bool(matches and named and not set(named) & {m.identifier for m in matches})
        if conflict:
            log.warning("finding %s names an unmatched advisory identifier", finding_id)
        return ProvenanceCheck(
            finding_id=finding_id,
            recorded=AdvisoryIdentifier(named[0]) if named else None,
            matches=tuple(
                sorted(
                    matches,
                    key=lambda m: (m.match != AdvisoryMatch.CONFIRMED, -m.score, m.identifier),
                )
            ),
            conflict=conflict,
        )

    def _link_provenance(self, check: ProvenanceCheck) -> ProvenanceCheck:
        if check.recorded is not None or not check.matches:
            return check
        best = check.matches[0]
        with self._uow as uow:
            advisory = uow.advisories.find_by_identifier(best.identifier) or uow.advisories.add(
                Advisory(
                    identifier=best.identifier,
                    published_at=datetime.combine(best.published, time(), UTC),
                )
            )
            assert advisory.id is not None
            self._findings.link_advisory(check.finding_id, advisory.id, best.match)
        self._uow.after_commit(
            lambda: log.info(
                "finding %s linked to advisory %s (%s)",
                check.finding_id,
                advisory.id,
                best.match,
            )
        )
        return check.model_copy(update={"recorded": best.identifier, "linked": True})

    def get_advisory(self, advisory_id: UUID) -> Advisory:
        with self._uow as uow:
            return uow.advisories.get(advisory_id)

    def _with_alias_packages(self, record: AdvisoryRecord) -> AdvisoryRecord:
        # OSV's CVE records name no package; their GHSA / GO- / PYSEC-aliases state the same
        # vulnerability per ecosystem. Without this, which id is asked first decides the analysis.
        # Only ids the impact schema admits are asked: the rest (BIT-, distro ids) name packages
        # in ecosystems core doesn't model.
        lookup = self._require_lookup()
        named = [
            alias
            for name in record.aliases
            if is_advisory_identifier(name)
            and (alias := lookup.record(name).data)
            and alias.identifier.upper() == name.upper()
            and alias.affected
            and not alias.withdrawn
        ]
        # Two aliases may state one package with different spans: keep every span, so a version
        # only one of them covers is still in range.
        packages: dict[tuple[Ecosystem, str], AffectedPackage] = {}
        for p in (p for alias in named for p in alias.affected):
            kept = packages.get((p.ecosystem, p.name))
            packages[(p.ecosystem, p.name)] = p if kept is None else _joined(kept, p)
        return record.model_copy(
            update={
                "affected": tuple(packages.values()),
                "sources": tuple(alias.source for alias in named),
            }
        )

    def find_advisory(self, identifier: AdvisoryIdentifier) -> AdvisoryRecord | None:
        """Read every known alias from its source, preserving their package ranges and fixes."""
        lookup = self._require_lookup()
        record = lookup.record(parse_advisory_identifier(identifier)).data
        if record is None:
            return None
        with self._uow as uow:
            known: dict[str, Advisory | None] = {
                name: uow.advisories.find_by_identifier(name)
                for name in (record.identifier, *record.aliases)
            }
            first = next((advisory for advisory in known.values() if advisory is not None), None)
            canonical = (
                uow.advisories.get(first.alias_of_id)
                if first is not None and first.alias_of_id is not None
                else first
            )
            names = set()
            if canonical is not None:
                assert canonical.id is not None
                aliases = uow.advisories.list_aliases(canonical.id)
                known.update((alias.identifier, alias) for alias in aliases)
                known[canonical.identifier] = canonical
                names = {canonical.identifier, *(alias.identifier for alias in aliases)}
        pending = names | set(record.aliases)
        seen = {str(identifier), record.identifier}
        unreadable = set(record.unreadable_aliases)
        while pending - seen:
            name = min(pending - seen)
            seen.add(name)
            try:
                alias = lookup.record(parse_advisory_identifier(name)).data
            except ServiceError:
                unreadable.add(AdvisoryIdentifier(name))
                log.warning("advisory alias %s unreadable; alias evidence is incomplete", name)
                continue
            except ValidationError:
                continue  # a distro or Bitnami id names packages core doesn't model
            if alias is None:
                continue
            pending.update(alias.aliases)
            seen.add(alias.identifier)
            top, other = sorted((record, alias), key=lambda r: -SEVERITY_RANK[r.severity])
            record = top.merge(other)
        with self._uow as uow:
            advisory = self._keep_advisory(uow, record, known)
            uow.commit()
        return record.model_copy(
            update={"advisory_id": advisory.id, "unreadable_aliases": tuple(sorted(unreadable))}
        )

    def _keep_advisory(
        self,
        uow: TraustUnitOfWork,
        record: AdvisoryRecord,
        previously_read: Mapping[str, Advisory | None] | None = None,
    ) -> Advisory:
        # Aliases join the first one already known, so one vulnerability keeps one canonical row.
        names = [record.identifier, *record.aliases]
        by_name = dict(previously_read or {})
        for name in names:
            if name not in by_name:
                by_name[name] = uow.advisories.find_by_identifier(name)
        known = [a for a in (by_name[name] for name in names) if a is not None]
        if known:
            first = known[0]
            canonical = first
            if first.alias_of_id is not None:
                canonical = next(
                    (a for a in by_name.values() if a is not None and a.id == first.alias_of_id),
                    None,
                ) or uow.advisories.get(first.alias_of_id)
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
        """The advisory a finding is about, canonical first, then every alias (CVE, GHSA, OSV
        ids of the one vulnerability); none when the finding names no advisory."""
        with self._uow as uow:
            finding = self._findings.get(finding_id)
            if finding.advisory_id is None:
                return []
            named = uow.advisories.get(finding.advisory_id)
            canonical = uow.advisories.get(named.alias_of_id) if named.alias_of_id else named
            assert canonical.id is not None
            return [canonical, *uow.advisories.list_aliases(canonical.id)]

    def consumes_fix(
        self, repository_ref_id: UUID, ecosystem: Ecosystem, name: str, fixed: Version
    ) -> FixUptake:
        """The package's versions in the commit's manifest SBOM and the images built from it,
        each at or above `fixed`; a version that can't be ordered decides nothing. Not listed while
        a manifest of its ecosystem went unresolved is `not_observed`, never `module_absent`."""
        with self._uow as uow:
            ref = self._inventory.get_ref(repository_ref_id)
            held = [(None, ref.manifest_sbom_id)] if ref.manifest_sbom_id else []
            held += [(i.id, i.sbom_id) for i in uow.images.list_built_from(repository_ref_id)]
            package = uow.packages.find(ecosystem, package_name(ecosystem, name))
            rows = [
                (image_id, d)
                for image_id, sbom_id in held
                if sbom_id and package
                for d in uow.dependencies.list_for_sbom(sbom_id)
                if d.package_id == package.id
            ]
        unread = not rows and any(
            m.ecosystem == ecosystem for m in self.unresolved_manifests(repository_ref_id)
        )
        if not any(sbom_id for _, sbom_id in held) or unread:
            return FixUptake(state=FixUptakeState.NOT_OBSERVED)
        fix = version_key(fixed, ecosystem)
        checked = tuple(
            ConsumedVersion(
                image_id=image_id,
                version=Version(d.version),
                consumed=None if fix is None or have is None else have >= fix,
            )
            for image_id, d in rows
            for have in [version_key(d.version, ecosystem)]
        )
        verdicts = {c.consumed for c in checked} - {None}
        state = (
            FixUptakeState.MODULE_ABSENT
            if not checked
            else FixUptakeState.CONSUMED
            if verdicts == {True}
            else FixUptakeState.PENDING
        )
        return FixUptake(state=state, checked=checked)

    def affected(self, advisory_id: UUID) -> list[AffectedDependency]:
        """Commits and images whose SBOM reaches the advisory's packages: directly, through a
        base image, or through an internal library another repository produces."""
        self._require_portfolio()
        with self._uow as uow:
            advisory = uow.advisories.get(advisory_id)
            links = uow.advisory_packages.list_for_advisory(advisory.alias_of_id or advisory_id)
        vulnerable = {link.package_id for link in links}
        return [
            AffectedDependency(
                repository_ref_id=ref_id,
                image_id=image_id,
                dependency=d,
                vulnerable=d.package_id in vulnerable,
            )
            for d, ref_id, image_id in self._reach(vulnerable)
        ]

    def _reach(
        self, start: set[UUID], version: str | None = None
    ) -> list[tuple[Dependency, UUID | None, UUID | None]]:
        """(dependency, ref, image) for every SBOM row holding the packages (at `version`, when
        given) or what carries them; one round per hop: a base image, or an internal library."""
        portfolio = self._require_portfolio()
        with self._uow as uow:
            reached: dict[UUID, Dependency] = {}
            refs: dict[UUID, RepositoryRef] = {}
            started: set[UUID] = set()
            while start:
                found = [
                    d
                    for d in uow.dependencies.list_for_packages(start)
                    if version is None or started or d.version == version
                ]
                started |= start
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
            (d, ref_id, image_id)
            for d in reached.values()
            for ref_id, image_id in holders[d.sbom_id]
        ]

    def dependencies(self, repository_ref_id: UUID) -> list[RefDependency]:
        """The packages in the commit's manifest SBOM, by ecosystem, name and version. A commit
        with none ingested raises: unknown is never read as no dependencies."""
        with self._uow as uow:
            ref = self._inventory.get_ref(repository_ref_id)
            if ref.manifest_sbom_id is None:
                raise NoManifestSbomError(repository_ref_id)
            return _sbom_packages(uow, ref.manifest_sbom_id)

    def manifest_packages(self, refs: Collection[RepositoryRef]) -> dict[UUID, list[Package]]:
        """The distinct packages in each commit's manifest SBOM, by ref id, read in bounded
        batches. A commit with none ingested raises, as `dependencies` does."""
        sboms: dict[UUID, UUID] = {}
        for ref in refs:
            if ref.manifest_sbom_id is None:
                raise NoManifestSbomError(ref.id)  # type: ignore[arg-type]
            sboms[ref.id] = ref.manifest_sbom_id  # type: ignore[index]
        with self._uow as uow:
            pairs = uow.dependencies.package_ids_for_sboms(set(sboms.values()))
            packages = {p.id: p for p in uow.packages.list_by_ids({p for _, p in pairs})}
        held: defaultdict[UUID, list[Package]] = defaultdict(list)
        for sbom_id, package_id in pairs:
            held[sbom_id].append(packages[package_id])
        return {ref_id: held[sbom_id] for ref_id, sbom_id in sboms.items()}

    def image_dependencies(self, digest: str) -> list[RefDependency]:
        """The packages in the image's SBOM (OS packages included), ordered as `dependencies`.
        An image unknown or without an SBOM raises: unknown is never read as no packages."""
        with self._uow as uow:
            image = uow.images.find_by_digest(digest)
            if image is None or image.sbom_id is None:
                raise NoImageSbomError(digest)
            return _sbom_packages(uow, image.sbom_id)

    def find_package(self, ecosystem: Ecosystem, name: str) -> Package | None:
        """The package stored under the name (compared as the ecosystem normalises it)."""
        with self._uow as uow:
            return uow.packages.find(ecosystem, package_name(ecosystem, name))

    def record_package_sources(
        self, repository_ref_id: UUID, modules: Sequence[PackageModule]
    ) -> list[Package]:
        """Persist producing repositories from measured package manifests, refusing conflicts."""
        repository_id = self._inventory.get_ref(repository_ref_id).repository_id
        recorded = []
        with self._uow as uow:
            for module in modules:
                ecosystem = Ecosystem(module.ecosystem)
                name = package_name(ecosystem, module.name)
                package = uow.packages.get_or_add(Package(ecosystem=ecosystem, name=name))
                if package.source_repository_id not in (None, repository_id):
                    raise ConflictError(
                        f"package {ecosystem}/{name} is already produced by "
                        f"repository {package.source_repository_id}, not {repository_id}"
                    )
                if package.source_repository_id is None:
                    package = uow.packages.update(
                        package.model_copy(update={"source_repository_id": repository_id})
                    )
                recorded.append(package)
            uow.commit()
        return recorded

    def internal_coupling(self, repository_ids: Collection[UUID]) -> list[InternalCoupling]:
        """Portfolio-produced packages ranked by distinct consuming repositories, excluding self."""
        with self._uow as uow:
            packages = uow.packages.list_from_repositories(repository_ids)
        by_repository: defaultdict[UUID, list[Package]] = defaultdict(list)
        for package in packages:
            assert package.source_repository_id is not None
            by_repository[package.source_repository_id].append(package)
        found = []
        for repository_id, produced in by_repository.items():
            ref_ids = {
                ref_id
                for package in produced
                if package.id is not None
                for ref_id in self.dependents(package.id)
            }
            refs = self._inventory.list_refs_by_ids(ref_ids)
            consumers = [r for r in refs if r.repository_id != repository_id]
            found.append(
                InternalCoupling(
                    repository_id=repository_id,
                    packages=tuple(sorted(produced, key=lambda p: (p.ecosystem, p.name))),
                    consumer_repository_ids=tuple(sorted({r.repository_id for r in consumers})),
                    consumer_repository_ref_ids=tuple(sorted({r.id for r in consumers if r.id})),
                )
            )
        return sorted(found, key=lambda row: (-len(row.consumer_repository_ids), row.repository_id))

    def dependents(self, package_id: UUID, version: str | None = None) -> list[UUID]:
        """The commits whose SBOMs hold the package (at `version`, when given): directly,
        through a base image, or through an internal library (`affected`'s walk)."""
        with self._uow as uow:
            uow.packages.get(package_id)
        reached = self._reach({package_id}, version)
        return sorted({ref_id for _, ref_id, _ in reached if ref_id is not None})

    def image_dependents(
        self, package_id: UUID, version: str | None = None
    ) -> list[AffectedDependency]:
        """The images whose SBOMs ship the package (at `version`, when given), each with the row
        that reaches it: the package itself, or a base image or internal library carrying it."""
        with self._uow as uow:
            uow.packages.get(package_id)
        return [
            AffectedDependency(
                repository_ref_id=ref_id,
                image_id=image_id,
                dependency=d,
                vulnerable=d.package_id == package_id,
            )
            for d, ref_id, image_id in self._reach({package_id}, version)
            if image_id is not None
        ]

    def ships_module(
        self, ecosystem: Ecosystem, name: str, version: str | None = None
    ) -> list[AffectedDependency]:
        """Images shipping the named module/package, directly or through a recorded base image."""
        package = self.find_package(ecosystem, name)
        if package is None or package.id is None:
            raise NotFoundError(f"no recorded package {ecosystem}/{name}")
        return self.image_dependents(package.id, version)

    def impacts(self, filter: ImpactFilter, page: PageRequest) -> Page[ImpactAnalysis]:
        """Recorded impact analyses, newest first; aliases of the advisory count as it."""
        after = page.position()
        rows = sorted(self._recorded(filter), key=lambda r: r.at, reverse=True)
        kept = [r for r in rows if after is None or r.at < after][: page.limit + 1]
        at = {r.analysis.assessment_id: r.at for r in kept}
        return Page.of([r.analysis for r in kept], page.limit, key=lambda a: at[a.assessment_id])

    def export_impacts(self, identifier: AdvisoryIdentifier | UUID) -> ImpactExport:
        """Export kept evidence for one advisory, without refreshing its source."""
        with self._uow as uow:
            known = (
                uow.advisories.get(identifier)
                if isinstance(identifier, UUID)
                else uow.advisories.find_by_identifier(parse_advisory_identifier(identifier))
            )
            if known is None:
                raise NotFoundError(f"advisory {identifier}: no recorded advisory")
            canonical = uow.advisories.get(known.alias_of_id) if known.alias_of_id else known
        assert canonical.id is not None
        rows = sorted(
            _latest(self._recorded(ImpactFilter(advisory_id=canonical.id)), None),
            key=lambda row: row.at,
            reverse=True,
        )
        exported = []
        documents = TypeAdapter(dict[str, JsonValue])
        repo_documents = TypeAdapter(list[dict[str, JsonValue]])
        for row in rows:
            [entry] = row.doc.repos
            metadata = row.doc.metadata
            document = documents.validate_json(row.doc.payload)
            [native] = repo_documents.validate_python(document["repos"])
            ref, repository = self._inventory.resolve(row.analysis.repository_ref_id)
            exported.append(
                ImpactExportRepo(
                    **row.analysis.model_dump(),
                    repo=entry.repo,
                    repository_url=repository.url,
                    sha=ref.sha,
                    ecosystem=Ecosystem(metadata.ecosystem) if metadata.ecosystem else None,
                    module=metadata.module,
                    version=entry.version,
                    evidence=ImpactEvidence.model_validate(native["evidence"]),
                    document=document,
                )
            )
        return ImpactExport(
            advisory_id=canonical.id,
            advisory=AdvisoryIdentifier(canonical.identifier),
            generated_at=self._clock.now(),
            commits=len({row.repository_ref_id for row in exported}),
            analyses=len(exported),
            classifications={
                verdict: sum(row.classification == verdict for row in exported)
                for verdict in ImpactClassification
            },
            repos=tuple(exported),
        )

    def summary(self, filter: ExposureFilter, group_by: ExposureDimension) -> list[ExposureRollup]:
        """Latest complete evidence, counted once per commit/advisory at its worst verdict."""
        latest = _latest(self._recorded(ImpactFilter(advisory_id=filter.advisory_id)), filter.as_of)
        latest = [r for r in latest if filter.ecosystem in (None, r.doc.metadata.ecosystem)]
        groups: defaultdict[str | None, list[_Recorded]] = defaultdict(list)
        if group_by == ExposureDimension.CLASSIFICATION:
            latest = _worst(latest)
        for row in latest:
            for key in self._exposure_keys(row, group_by):
                groups[key].append(row)
        return sorted(
            (
                ExposureRollup.of([row.analysis.classification for row in _worst(found)], key=key)
                for key, found in groups.items()
            ),
            key=lambda r: (-r.commits, r.key is None, r.key or ""),
        )

    def timeline(self, filter: ExposureFilter, bucket: TimeBucket) -> list[ExposureSeriesPoint]:
        """`summary`'s counts standing at each bucket's end, from the first analysis to `as_of`
        (else the last analysis); `analysed` counts the analyses recorded within the bucket."""
        all_rows = [
            r
            for r in self._recorded(ImpactFilter(advisory_id=filter.advisory_id))
            if _by(r, filter.as_of)
        ]
        rows = [r for r in all_rows if filter.ecosystem in (None, r.doc.metadata.ecosystem)]
        if not rows:
            return []
        end = filter.as_of or max(r.at[0] for r in all_rows)
        points = []
        window = bucket.window_of(min(r.at[0] for r in rows))
        while window.start <= end:
            standing = _worst(
                [
                    r
                    for r in _latest(all_rows, min(window.end - _TICK, end))
                    if filter.ecosystem in (None, r.doc.metadata.ecosystem)
                ]
            )
            points.append(
                ExposureSeriesPoint.of(
                    [r.analysis.classification for r in standing],
                    bucket=window.start,
                    analysed=sum(window.start <= r.at[0] < window.end for r in rows),
                )
            )
            window = bucket.window_of(window.end)
        return points

    def _exposure_keys(self, row: _Recorded, group_by: ExposureDimension) -> list[str | None]:
        meta = row.doc.metadata
        if group_by == ExposureDimension.PRODUCT:
            shipping = self._require_portfolio().list_products_shipping(
                row.analysis.repository_ref_id
            )
            return [p.slug for p in shipping] or [None]
        if group_by == ExposureDimension.REPOSITORY:
            return [self._inventory.resolve(row.analysis.repository_ref_id)[1].url]
        return [
            {
                ExposureDimension.ADVISORY: row.identifier,
                ExposureDimension.PACKAGE: f"{meta.ecosystem}/{meta.module}",
                ExposureDimension.ECOSYSTEM: meta.ecosystem,
                ExposureDimension.CLASSIFICATION: row.analysis.classification,
            }[group_by]
        ]

    def _recorded(self, filter: ImpactFilter, *, include_findings: bool = True) -> list[_Recorded]:
        refs = None if filter.repository_ref_id is None else [filter.repository_ref_id]
        held = [
            (
                assessment,
                artifact,
                ImpactAnalysisArtifact.parse(stored_bytes(self._objects, artifact)),
            )
            for assessment, artifact in self._log.documents(
                self._log.list_of(AssessmentKind.IMPACT, refs), [ImpactAnalysisArtifact.schema]
            )
        ]
        with self._uow as uow:
            named = None if filter.advisory_id is None else uow.advisories.get(filter.advisory_id)
            wanted = None if named is None else named.alias_of_id or named.id
            canonical = {}
            for cve in {doc.metadata.cve for _, _, doc in held}:
                known = uow.advisories.find_by_identifier(cve)
                if known is None:
                    raise IntegrityError(f"an impact analysis names {cve}, never kept")
                canonical[cve] = (
                    uow.advisories.get(known.alias_of_id) if known.alias_of_id else known
                )
        rows = []
        for assessment, artifact, doc in held:
            advisory = canonical[doc.metadata.cve]
            classification = ImpactClassification(doc.repos[0].classification)
            if wanted not in (None, advisory.id) or filter.classification not in (
                None,
                classification,
            ):
                continue
            assert assessment.id is not None and artifact.id is not None
            assert assessment.repository_ref_id is not None and advisory.id is not None
            filed = (
                self._require_findings().occurrences(assessment_id=assessment.id)
                if include_findings and classification == ImpactClassification.AFFECTED
                else []
            )
            analysis = ImpactAnalysis(
                assessment_id=assessment.id,
                artifact_id=artifact.id,
                repository_ref_id=assessment.repository_ref_id,
                advisory_id=advisory.id,
                classification=classification,
                finding_id=filed[0].finding_id if filed else None,
            )
            rows.append(
                _Recorded(
                    (assessment.occurred_at, assessment.id), advisory.identifier, doc, analysis
                )
            )
        return rows

    def vex_status(self, advisory: AdvisoryIdentifier, product_id: UUID) -> VexStatus | None:
        """NEED(provider: per-advisory CSAF VEX documents; inventory: vendor product ids)."""
        raise ConfigError(
            "vex_status: NEED(provider: a per-advisory CSAF VEX document source; inventory: a "
            f"product's vendor product ids) - neither is modelled, so {advisory} for product "
            f"{product_id} can't be answered"
        )

    def _require_findings(self) -> FindingService:
        if self._finding_service is None:
            raise ConfigError("finding reads need the finding service (Context wires it)")
        return self._finding_service

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

    def feed_statuses(self) -> list[FeedStatus]:
        return [self.feed_status(FeedName(f)) for f in self._feeds.names()]

    def feed_payload(self, feed: FeedName, as_of: datetime | None = None) -> bytes | None:
        """The latest snapshot retrieved by `as_of`; None when none had been fetched."""
        with self._uow as uow:
            latest = uow.feed_snapshots.latest(feed, as_of)
            artifact = None if latest is None else self._log.get_artifact(latest.artifact_id)
        return None if artifact is None else stored_bytes(self._objects, artifact)

    def exploit_signals(self, identifiers: Sequence[AdvisoryIdentifier]) -> list[ExploitSignal]:
        """EPSS and KEV for each identifier, from the latest snapshot of each feed."""
        epss = epss_scores(self._required_payload(EPSS))
        kev = kev_entries(self._required_payload(KEV))
        return self._signals(identifiers, epss, kev)

    def recorded_exploit_signals(
        self, identifiers: Sequence[AdvisoryIdentifier], as_of: datetime
    ) -> list[ExploitSignal]:
        """Available recorded feed evidence by `as_of`; missing snapshots supply no evidence."""
        if not identifiers:
            return []
        epss = self.feed_payload(EPSS, as_of)
        kev = self.feed_payload(KEV, as_of)
        return self._signals(
            identifiers,
            {} if epss is None else epss_scores(epss),
            {} if kev is None else kev_entries(kev),
        )

    @staticmethod
    def _signals(
        identifiers: Sequence[AdvisoryIdentifier],
        epss: Mapping[str, tuple[float, float]],
        kev: Mapping[str, tuple[date | None, bool]],
    ) -> list[ExploitSignal]:
        signals = []
        for identifier in dict.fromkeys(identifiers):
            score, percentile = epss.get(identifier, (None, None))
            added, ransomware = kev.get(identifier, (None, None))
            signals.append(
                ExploitSignal(
                    identifier=identifier,
                    epss=score,
                    epss_percentile=percentile,
                    kev_added=added,
                    kev_ransomware=ransomware,
                )
            )
        return signals

    def exploit_context(
        self,
        artifacts: Mapping[str, bytes],
        repository: HttpsRepoUrl | None = None,
        deployed: Collection[HttpsRepoUrl] | None = None,
    ) -> ExploitContext:
        """EPSS and KEV for the CVEs each artifact's items name, and the repository's reach;
        `deployed` is a lab cluster's workload inventory, when one was taken."""
        found = {label: _cve_items(label, raw) for label, raw in artifacts.items()}
        cves = sorted({c for _, items in found.values() for _, cs in items for c in cs})
        signals = {s.identifier: s for s in self.exploit_signals(cves)}
        return ExploitContext(
            artifacts=tuple(
                ArtifactSignals(
                    source=label,
                    list_key=key,
                    items_scanned=len(items),
                    items=tuple(
                        ItemSignals(item=item, signals=tuple(signals[c] for c in cs))
                        for item, cs in items
                        if cs
                    ),
                )
                for label, (key, items) in found.items()
            ),
            reach=None if repository is None else self._repository_reach(repository, deployed),
            feeds=(self.feed_status(EPSS), self.feed_status(KEV)),
        )

    def _repository_reach(
        self, url: HttpsRepoUrl, deployed: Collection[HttpsRepoUrl] | None
    ) -> RepositoryReach:
        portfolio = self._require_portfolio()
        repo = portfolio.find_repository(url)
        reach = RepositoryReach(
            repository=str(url),
            registered=repo is not None,
            deployed=None if deployed is None else url in deployed,
        )
        if repo is None or repo.id is None:
            return reach
        return reach.model_copy(
            update={
                "products": tuple(sorted(p.name for p in portfolio.list_products_of(repo.id))),
                "owner_teams": tuple(sorted(t.name for t in portfolio.list_owners(repo.id))),
            }
        )

    def source_document(self, source: str, identifier: str) -> bytes:
        """A registered feed source's document for one identifier, as it serves it now; nothing
        is kept (`find_advisory` is the OSV record analysis works from)."""
        if source not in self._feed_sources.names():
            raise NotFoundError(
                f"feed source {source}: not registered "
                f"({', '.join(self._feed_sources.names()) or 'none registered'})"
            )
        return self._feed_sources.get(source).document(identifier).data

    def _required_payload(self, feed: FeedName) -> bytes:
        payload = self.feed_payload(feed)
        if payload is None:
            raise NotFoundError(f"feed {feed}: never fetched; refresh it first")
        return payload


_Items = list[tuple[str | None, list[AdvisoryIdentifier]]]


def _cve_items(label: str, raw: bytes) -> tuple[str | None, _Items]:
    """The artifact's item list key and, per item, its id and the CVEs named anywhere in it."""
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ValidationError(f"{label}: not a JSON document: {e}") from e
    if not isinstance(doc, dict):
        raise ValidationError(f"{label}: expected a JSON object")
    key = next((k for k in _ITEM_LISTS if isinstance(doc.get(k), list)), None)
    return key, [
        (
            next((str(i[k]) for k in _ITEM_KEYS if isinstance(i, dict) and i.get(k)), None),
            [AdvisoryIdentifier(str(c)) for c in CveId.find_all(json.dumps(i))],
        )
        for i in (doc[key] if key else [])
    ]


def _by(row: _Recorded, until: datetime | None) -> bool:
    return until is None or row.at[0] <= until


def _latest(rows: Sequence[_Recorded], until: datetime | None) -> list[_Recorded]:
    """Latest complete preparation snapshot, retaining each declared package/version member."""
    member_rows: dict[
        tuple[UUID, UUID, str], dict[tuple[str | None, str, str | None], _Recorded]
    ] = {}
    expected: dict[tuple[UUID, UUID, str], frozenset[tuple[str | None, str, str | None]]] = {}
    for row in rows:
        if not _by(row, until):
            continue
        member = (row.doc.metadata.ecosystem, row.doc.metadata.module, row.doc.repos[0].version)
        raw_scope = getattr(row.doc.metadata, "preparation_scope", None)
        if raw_scope is None:
            digest = f"legacy:{row.analysis.assessment_id}"
            declared = frozenset({member})
        else:
            scope = ImpactPreparationScope.model_validate(raw_scope, from_attributes=True)
            digest = scope.digest
            declared = frozenset((m.ecosystem.value, m.module, m.version) for m in scope.members)
        key = (row.analysis.repository_ref_id, row.analysis.advisory_id, digest)
        if expected.setdefault(key, declared) != declared:
            raise IntegrityError(f"impact preparation scope {digest}: inconsistent member set")
        if member not in declared:
            raise IntegrityError(f"impact preparation scope {digest}: undeclared packet {member}")
        latest = member_rows.setdefault(key, {})
        if member not in latest or latest[member].at < row.at:
            latest[member] = row
    snapshots: dict[tuple[UUID, UUID], tuple[tuple[datetime, UUID], list[_Recorded]]] = {}
    for key, members in member_rows.items():
        if frozenset(members) != expected[key]:
            continue
        complete = list(members.values())
        at = max(row.at for row in complete)
        commit = (key[0], key[1])
        if commit not in snapshots or snapshots[commit][0] < at:
            snapshots[commit] = (at, complete)
    return [row for _, complete in snapshots.values() for row in complete]


def _worst(rows: Sequence[_Recorded]) -> list[_Recorded]:
    worst: dict[tuple[UUID, UUID], _Recorded] = {}
    for row in rows:
        key = (row.analysis.repository_ref_id, row.analysis.advisory_id)
        previous = worst.get(key)
        if previous is None or (_IMPACT_RANK[row.analysis.classification], row.at) > (
            _IMPACT_RANK[previous.analysis.classification],
            previous.at,
        ):
            worst[key] = row
    return list(worst.values())


@dataclass(frozen=True)
class _Recorded:
    at: tuple[datetime, UUID]
    identifier: str
    doc: ImpactAnalysisArtifact
    analysis: ImpactAnalysis


def _provenance(
    cve: PublishedCve,
    component: str,
    first: date,
    title: str,
    cwes: Sequence[str],
    min_score: float = AUTO_PROBABLE,
) -> ProvenanceMatch | None:
    """The CVE as a first-discovery match of the finding, or None when it can't be one."""
    # Only a CVE published after our first report can be our find; earlier ones we read.
    if (cve.component or "").lower() != component or cve.published <= first:
        return None
    score = _title_score(cve.title, title)
    if score < max(AUTO_PROBABLE, min_score):
        return None
    confirmed = score >= AUTO_CONFIRM or bool(set(cve.cwes) & set(cwes))
    return ProvenanceMatch(
        identifier=cve.identifier,
        title=cve.title,
        published=cve.published,
        lead_days=(cve.published - first).days,
        score=score,
        match=AdvisoryMatch.CONFIRMED if confirmed else AdvisoryMatch.PROBABLE,
        severity=cve.severity,
    )


def _title_score(a: str, b: str) -> float:
    """max(token Jaccard, sequence ratio): Jaccard survives reordering, the ratio rescues near
    identical strings that tokenize apart (`no_auth` / `noauth`)."""
    ta, tb = (
        {w for w in re.findall(r"[a-z0-9_]+", t.lower()) if len(w) > 2 and w not in _TITLE_STOP}
        for t in (a, b)
    )
    jaccard = len(ta & tb) / len(ta | tb) if ta and tb else 0.0
    return max(jaccard, difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio())


def _fix_stated(record: AdvisoryRecord, held: set[PackageVersion]) -> bool:
    return any(
        span.fixed
        for q in held
        if (named := record.package(Ecosystem(q.package.ecosystem), q.package.name)) is not None
        for span in named.spans
    )


def _sbom_packages(uow: TraustUnitOfWork, sbom_id: UUID) -> list[RefDependency]:
    rows = uow.dependencies.list_for_sbom(sbom_id)
    packages = {p.id: p for p in uow.packages.list_by_ids({d.package_id for d in rows})}
    listed = [RefDependency(dependency=d, package=packages[d.package_id]) for d in rows]
    return sorted(listed, key=lambda r: (r.package.ecosystem, r.package.name, r.dependency.version))


def _joined(a: AffectedPackage, b: AffectedPackage) -> AffectedPackage:
    """One package as two aliases state it: every span, listed version, import and symbol."""
    return a.model_copy(
        update={
            field: tuple(dict.fromkeys((*getattr(a, field), *getattr(b, field))))
            for field in ("spans", "versions", "imports", "symbols")
        }
    )


def _in_range(
    dependencies: list[Dependency], named: Mapping[UUID, AffectedPackage | None]
) -> bool | None:
    """True when any listed version is affected; None when none is, but one can't be decided."""
    verdicts = {
        package.affects(Version(d.version)) if (package := named.get(d.package_id)) else None
        for d in dependencies
    }
    return True if True in verdicts else None if None in verdicts or not verdicts else False


def _exposure_candidate(
    repository_id: UUID, doc: ImpactAnalysisArtifact, record: AdvisoryRecord, canonical: Advisory
) -> FindingCandidate:
    """The dependency finding an affected commit gets: severity as the advisory declares it."""
    meta, [entry] = doc.metadata, doc.repos
    observed = ((k, getattr(entry.evidence, k)) for k in dir(entry.evidence))
    evidence = "\n".join(f"- {k}: {v}" for k, v in observed if v not in (None, ()))
    return FindingCandidate(
        label=Label(f"{canonical.identifier}:{meta.ecosystem}:{meta.module}"),
        repository_id=repository_id,
        title=f"{canonical.identifier} in {meta.module}"
        + (f": {record.summary}" if record.summary else ""),
        description=(
            f"{meta.module} {entry.version or ''} is in {meta.vulnerable_range}, fixed in "
            f"{meta.fixed_version or 'no release yet'}.\n\nEvidence:\n{evidence}"
        ),
        category=Category(SUPPLY_CHAIN),
        reported_severity=record.severity,
        exposure=ExposureKey(
            advisory_id=canonical.id,
            advisory=canonical.identifier,
            ecosystem=meta.ecosystem,
            package=meta.module,
        ),
    )


def _published(record: AdvisoryRecord) -> SymbolResolution | None:
    symbols = tuple(
        VulnerableSymbol(
            symbol=symbol,
            source=SymbolSource.PUBLISHED,
            confidence=SymbolConfidence.HIGH,
            reference=record.source,
        )
        for package in record.affected
        for symbol in package.symbols
    )
    return (
        SymbolResolution(
            status=SymbolStatus.DEGRADED if record.unreadable_aliases else SymbolStatus.RESOLVED,
            symbols=symbols,
            note=f"unreadable aliases: {', '.join(record.unreadable_aliases)}"
            if record.unreadable_aliases
            else None,
        )
        if symbols
        else None
    )


def _with_judged(found: SymbolResolution | None, judged: Sequence[str]) -> SymbolResolution | None:
    # Judged symbols join what was published or mined; they never replace it.
    known = {s.symbol for s in found.symbols} if found else set()
    extra = tuple(
        VulnerableSymbol(
            symbol=name,
            source=SymbolSource.JUDGED,
            confidence=SymbolConfidence.MEDIUM,
            reference="judged from the fix diff",
        )
        for name in dict.fromkeys(judged)
        if name and name not in known
    )
    if not extra:
        return found
    if found is None:
        return SymbolResolution(status=SymbolStatus.RESOLVED, symbols=extra)
    return found.model_copy(
        update={
            "status": SymbolStatus.DEGRADED
            if found.status == SymbolStatus.DEGRADED
            else SymbolStatus.RESOLVED,
            "symbols": (*found.symbols, *extra),
        }
    )
