from __future__ import annotations

import difflib
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    RepositoryError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import ImpactAnalysisArtifact
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Artifact,
    Assessment,
    AssessmentKind,
)
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.dependencies import (
    EXPOSED,
    Advisory,
    AdvisoryIdentifier,
    AdvisoryMatch,
    AdvisoryPackage,
    AdvisoryRecord,
    AdvisorySweep,
    AffectedDependency,
    AffectedPackage,
    ConsumedVersion,
    Dependency,
    DependencyIngest,
    ExploitSignal,
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    FeedName,
    FixUptake,
    FixUptakeState,
    Image,
    ImpactAnalysis,
    ImpactEvidence,
    ImpactFilter,
    ImpactInput,
    ImpactQuery,
    NoImageSbomError,
    NoManifestSbomError,
    Package,
    PackageVersion,
    ProvenanceCheck,
    ProvenanceMatch,
    RefDependency,
    Sbom,
    SbomContents,
    SweepStatus,
    SweptAdvisory,
    SymbolConfidence,
    SymbolResolution,
    SymbolSource,
    SymbolStatus,
    Version,
    VexStatus,
    VulnerableSymbol,
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
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    DependencyEvidenceLevel,
    Ecosystem,
    FindingOrigin,
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
    FeedStatus,
    PublishedCve,
    epss_scores,
    kev_entries,
    rh_cve_records,
    validate_payload,
)
from traust_core.v1.providers.sources import SourceError, SourceProvider
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
MAX_FIX_COMMITS = 4  # backports repeat the same change; more commits only add API calls
REACHED_THROUGH = "reached through a base image or an internal library; not listed itself"
SURFACE = "{} surface: manifest-level, no reachability"
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
        clock: Clock | None = None,
        analyzers: Sequence[ImpactAnalyzer] = (),
        sources: SourceProvider | None = None,
        hosts: Mapping[str, str] = DEFAULT_FORGE_HOSTS,
        sbom_tool: ToolProvider[bytes] | None = None,
        findings: FindingService | None = None,
    ) -> None:
        self._uow = uow
        self._inventory = Inventory(uow)
        self._log = AssessmentLog(uow)
        self._findings = FindingRecords(uow)
        self._intake = intake
        self._feeds = feeds
        self._objects = objects
        self._advisories = advisories
        self._portfolio = portfolio
        self._clock = clock or SystemClock()
        self._analyzers = tuple(analyzers)
        self._sources = sources
        self._hosts = hosts
        self._sbom_tool = sbom_tool
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
                log.warning("feed %s not refreshed, keeping its last snapshot: %s", feed, e)
                statuses.append(self.feed_status(feed).model_copy(update={"last_error": str(e)}))
            except (NotFoundError, IntegrityError, RepositoryError) as e:
                # The last snapshot an incremental feed builds on is unreadable: a person acts.
                log.error("feed %s not refreshed, its last snapshot is unreadable: %s", feed, e)
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
            image = uow.images.get_or_add(wanted)
            held = (image.sbom_id, image.platform, image.repository_ref_id)
            if held != (sbom.id, platform, repository_ref_id):
                raise ConflictError(
                    f"image {digest} already recorded with sbom {image.sbom_id}, platform "
                    f"{image.platform}, ref {image.repository_ref_id}; image rows are append-only"
                )
            uow.commit()
        log.info(
            "sbom %s for image %s: %d packages, %d components without a modeled package",
            sbom.id,
            digest,
            len(contents.entries),
            contents.skipped,
        )
        return image

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

    def ingest_dependencies(self, repository_ref_id: UUID, checkout: Path) -> DependencyIngest:
        """The commit's manifest SBOM, read from its checkout by the SBOM tool (syft) and
        ingested; the same package list again is the same SBOM."""
        if self._sbom_tool is None:
            raise ConfigError("ingest_dependencies needs the SBOM tool (Context wires syft)")
        if not (ready := self._sbom_tool.check()).ready:
            raise ConfigError(f"{self._sbom_tool.name}: {ready.detail}")
        scanned = self._sbom_tool.acquire(ToolRequest(workspace=checkout))
        sbom = self.ingest_sbom(scanned.data, repository_ref_id)
        return DependencyIngest(
            repository_ref_id=repository_ref_id,
            sbom=sbom,
            tool=scanned.acquisition.provider,
            tool_version=scanned.acquisition.version,
        )

    def resolve_symbols(self, advisory_id: UUID) -> SymbolResolution:
        """The functions the advisory's fix touched: what its source publishes (Go's OSV
        imports), else the changed declarations of the fix commits on it and its aliases."""
        advisory = self.get_advisory(advisory_id)
        record = self.find_advisory(AdvisoryIdentifier(advisory.identifier))
        if record is None:
            raise NotFoundError(f"advisory {advisory.identifier}: unknown to its source")
        return _published(record) or self._mined(record)

    def _mined(self, record: AdvisoryRecord) -> SymbolResolution:
        assert self._advisories is not None
        records, unreadable = [record], 0
        for name in dict.fromkeys((*record.aliases, *record.upstream)):
            try:
                alias = self._advisories.record(name).data
            except ServiceError:
                unreadable += 1
                continue
            records += [alias] if alias else []
        commits, pulls = fix_commits(url for r in records for url in r.references)
        if not commits:
            if unreadable:
                note = f"{unreadable} alias record(s) unreadable; the fix may be on one of them"
                return SymbolResolution(status=SymbolStatus.DEGRADED, note=note)
            note = f"{len(pulls)} pull request reference(s), not followed" if pulls else None
            return SymbolResolution(status=SymbolStatus.NO_FIX_COMMIT, note=note)
        sources = self._require_sources()
        found: dict[str, VulnerableSymbol] = {}
        unread: list[str] = []
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
            status=SymbolStatus.RESOLVED
            if symbols
            else SymbolStatus.DEGRADED
            if unread
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
    ) -> ImpactInput:
        """One commit against one advisory: the advisory as its source states it now, what the
        commit's manifest and the images built from it hold of it, and the evidence that gives.
        Given the commit's checkout, the analysis tiers for the package's ecosystem run too,
        unless its SBOMs already rule it out."""
        advisory = self.get_advisory(advisory_id)
        record = self.find_advisory(AdvisoryIdentifier(advisory.identifier))
        if record is None or not record.affected:
            raise NotFoundError(f"advisory {advisory.identifier}: its source names no package")
        rows = [r for r in self.affected(advisory_id) if r.repository_ref_id == repository_ref_id]
        portfolio = self._require_portfolio()
        with self._uow as uow:
            subject = self._inventory.subject(repository_ref_id)
            scanned = any(i.sbom_id for i in uow.images.list_built_from(repository_ref_id))
            named = {
                d.package_id: record.package(Ecosystem(p.ecosystem), p.name)
                for d in {r.dependency for r in rows if r.vulnerable}
                for p in [uow.packages.get(d.package_id)]
            }
        package = next((p for p in named.values() if p is not None), record.affected[0])
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
            if not pinned
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
        if checkout is not None and evidence.classification() in undecided:
            # govulncheck carries its own symbol data: Go never mines fix commits.
            found = _published(record) or (
                None if package.ecosystem == Ecosystem.GO else self._mined(record)
            )
            symbols = _with_judged(found, judged)
            query = ImpactQuery(
                advisory=record,
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
        if len(doc.repos) != 1:
            raise ValidationError(f"impact analysis covers {len(doc.repos)} commits, not one")
        [entry] = doc.repos
        record = self.find_advisory(AdvisoryIdentifier(doc.metadata.cve))
        if record is None or record.advisory_id is None:
            raise NotFoundError(f"advisory {doc.metadata.cve}: unknown to its source")
        with self._uow as uow:
            ref, repository = self._inventory.resolve(repository_ref_id)
            if entry.repo != repo_label(repository.url):
                raise ValidationError(f"impact analysis of {entry.repo}, not {repository.url}")
            assessment, artifact = self._impact_assessment(uow, ref, doc, provenance)
            canonical = uow.advisories.get(record.advisory_id)
            uow.commit()
        assert assessment.id is not None and artifact.id is not None and canonical.id is not None
        classification = ImpactClassification(entry.classification)
        finding_id = None
        if classification == ImpactClassification.AFFECTED:
            candidate = _exposure_candidate(repository.id, doc, record, canonical)
            finding_id = self._intake.accept(assessment.id, [candidate]).findings[candidate.label]
        log.info(
            "impact of %s on ref %s: %s", canonical.identifier, repository_ref_id, classification
        )
        return ImpactAnalysis(
            assessment_id=assessment.id,
            artifact_id=artifact.id,
            repository_ref_id=repository_ref_id,
            advisory_id=canonical.id,
            classification=classification,
            finding_id=finding_id,
        )

    def _impact_assessment(
        self,
        uow: TraustUnitOfWork,
        ref: RepositoryRef,
        doc: ImpactAnalysisArtifact,
        provenance: Provenance,
    ) -> tuple[Assessment, Artifact]:
        assert ref.id is not None
        digest = sha256_hex(doc.payload)
        kind = ImpactAnalysisArtifact.schema
        if recorded := self._log.find_recorded([ref.id], AssessmentKind.IMPACT, kind, digest):
            return recorded[0]
        assessment = self._log.open(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.IMPACT,
                status=ASSESSMENT_COMPLETED,
                assessor=IMPACT_ASSESSOR,
                assessor_version=str(doc.metadata.harness_version),
                occurred_at=provenance.occurred_at,
            )
        )
        stored = self._objects.put(ObjectKey.parse(f"artifacts/{kind}/{digest}.json"), doc.payload)
        artifact = record_artifact(
            uow,
            Artifact(
                assessment_id=assessment.id, digest=stored.sha256, kind=kind, uri=str(stored.key)
            ),
        )
        return assessment, artifact

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
        best: dict[str, tuple[AdvisoryRecord, set[PackageVersion]]] = {}
        for record in records:
            touched = hit[record.identifier]
            kept = best.get(record.display_id)
            if kept is None:
                best[record.display_id] = (record, touched)
            else:
                top = max(kept[0], record, key=lambda r: SEVERITY_RANK[r.severity])
                best[record.display_id] = (top, kept[1] | touched)
        rows = [
            self._swept(record, touched, scan_cap)
            for record, touched in best.values()
            if SEVERITY_RANK[record.severity] >= SEVERITY_RANK[min_severity]
            and (record.malicious or _fix_stated(record, touched))
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
                log.warning("advisory %s: not fetched (%s)", raw, e)
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
        )

    def _require_lookup(self) -> AdvisoryLookup:
        if self._advisories is None:
            raise ConfigError("advisory reads need an advisory lookup (the feeds registry's osv)")
        return self._advisories

    def reconcile_provenance(self, finding_id: UUID) -> ProvenanceCheck:
        """Which published CVE the finding became (rh-cve feed): its repository's component,
        published after the finding's first report, a like title. A finding naming no advisory
        gets the best match; one naming an advisory no match is comes back a conflict."""
        findings = self._require_findings()
        view = findings.get(finding_id)
        reported = findings.occurrences(finding_ids=[finding_id])
        if not reported:
            raise NotFoundError(f"finding {finding_id}: never reported, so no first report")
        runs = self._log.list_by_ids({o.assessment_id for o in reported})
        first = min(a.occurred_at for a in runs).date()
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
        named = [a.identifier for a in self.advisories_for(finding_id)]
        check = ProvenanceCheck(
            finding_id=finding_id,
            recorded=AdvisoryIdentifier(named[0]) if named else None,
            matches=tuple(matches),
        )
        if not matches:
            return check
        if named:
            conflict = not set(named) & {m.identifier for m in matches}
            if conflict:
                log.warning("finding %s names %s, not a matched CVE", finding_id, named[0])
            return check.model_copy(update={"conflict": conflict})
        best = matches[0]
        with self._uow as uow:
            advisory = uow.advisories.find_by_identifier(best.identifier) or uow.advisories.add(
                Advisory(
                    identifier=best.identifier,
                    published_at=datetime.combine(best.published, time(), UTC),
                )
            )
            assert advisory.id is not None
            self._findings.link_advisory(finding_id, advisory.id, best.match)
            uow.commit()
        log.info("finding %s became %s (%s)", finding_id, best.identifier, best.match)
        return check.model_copy(update={"recorded": best.identifier, "linked": True})

    def get_advisory(self, advisory_id: UUID) -> Advisory:
        with self._uow as uow:
            return uow.advisories.get(advisory_id)

    def find_advisory(self, identifier: AdvisoryIdentifier) -> AdvisoryRecord | None:
        """The advisory as its source states it now (ranges are never taken from memory);
        its identity, aliases and affected packages are kept on the way through."""
        record = self._require_lookup().record(parse_advisory_identifier(identifier)).data
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
        each at or above `fixed`; a version that can't be ordered decides nothing."""
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
        if not any(sbom_id for _, sbom_id in held):
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

    def _reach(self, start: set[UUID]) -> list[tuple[Dependency, UUID | None, UUID | None]]:
        """(dependency, ref, image) for every SBOM row holding the packages or what carries
        them; one round per hop: a base image, or an internal library."""
        portfolio = self._require_portfolio()
        with self._uow as uow:
            reached: dict[UUID, Dependency] = {}
            refs: dict[UUID, RepositoryRef] = {}
            started: set[UUID] = set()
            while start:
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

    def image_dependencies(self, digest: str) -> list[RefDependency]:
        """The packages in the image's SBOM (OS packages included), ordered as `dependencies`.
        An image unknown or without an SBOM raises: unknown is never read as no packages."""
        with self._uow as uow:
            image = uow.images.find_by_digest(digest)
            if image is None or image.sbom_id is None:
                raise NoImageSbomError(digest)
            return _sbom_packages(uow, image.sbom_id)

    def dependents(self, package_id: UUID) -> list[UUID]:
        """The commits whose SBOMs hold the package: directly, through a base image, or through
        an internal library (the blast radius `affected` walks, for one package)."""
        with self._uow as uow:
            uow.packages.get(package_id)
        return sorted({ref_id for _, ref_id, _ in self._reach({package_id}) if ref_id is not None})

    def impacts(self, filter: ImpactFilter, page: PageRequest) -> Page[ImpactAnalysis]:
        """Recorded impact analyses, newest first; aliases of the advisory count as it."""
        after = page.position()
        rows = sorted(self._recorded(filter), key=lambda r: r.at, reverse=True)
        kept = [r for r in rows if after is None or r.at < after][: page.limit + 1]
        at = {r.analysis.assessment_id: r.at for r in kept}
        return Page.of([r.analysis for r in kept], page.limit, key=lambda a: at[a.assessment_id])

    def summary(self, filter: ExposureFilter, group_by: ExposureDimension) -> list[ExposureRollup]:
        """The latest impact analysis of each commit for each advisory, counted per group,
        largest first. A commit counts in each product that ships it."""
        latest: dict[tuple[UUID, UUID], _Recorded] = {}
        for row in self._recorded(ImpactFilter(advisory_id=filter.advisory_id)):
            key = (row.analysis.repository_ref_id, row.analysis.advisory_id)
            if filter.ecosystem in (None, row.doc.metadata.ecosystem) and (
                key not in latest or latest[key].at < row.at
            ):
                latest[key] = row
        groups: defaultdict[str | None, list[ImpactClassification]] = defaultdict(list)
        for row in latest.values():
            for key in self._exposure_keys(row, group_by):
                groups[key].append(row.analysis.classification)
        return sorted(
            (
                ExposureRollup(
                    key=key,
                    commits=len(found),
                    exposed=sum(c in EXPOSED for c in found),
                    affected=found.count(ImpactClassification.AFFECTED),
                    by_classification=Counter(found),
                )
                for key, found in groups.items()
            ),
            key=lambda r: (-r.commits, r.key is None, r.key or ""),
        )

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

    def _recorded(self, filter: ImpactFilter) -> list[_Recorded]:
        refs = None if filter.repository_ref_id is None else [filter.repository_ref_id]
        held = self._log.documents(
            self._log.list_of(AssessmentKind.IMPACT, refs), [ImpactAnalysisArtifact.schema]
        )
        wanted = None
        with self._uow as uow:
            if filter.advisory_id is not None:
                named = uow.advisories.get(filter.advisory_id)
                wanted = named.alias_of_id or named.id
            canonical: dict[str, Advisory] = {}
            rows = []
            for assessment, artifact in held:
                doc = ImpactAnalysisArtifact.parse(stored_bytes(self._objects, artifact))
                [entry] = doc.repos
                cve = doc.metadata.cve
                if cve not in canonical:
                    known = uow.advisories.find_by_identifier(cve)
                    if known is None:
                        raise IntegrityError(f"impact {assessment.id} names {cve}, never kept")
                    canonical[cve] = (
                        uow.advisories.get(known.alias_of_id) if known.alias_of_id else known
                    )
                advisory = canonical[cve]
                classification = ImpactClassification(entry.classification)
                if (wanted not in (None, advisory.id)) or filter.classification not in (
                    None,
                    classification,
                ):
                    continue
                assert assessment.id is not None and artifact.id is not None
                assert assessment.repository_ref_id is not None and advisory.id is not None
                rows.append(
                    _Recorded(
                        at=(assessment.occurred_at, assessment.id),
                        identifier=advisory.identifier,
                        doc=doc,
                        analysis=ImpactAnalysis(
                            assessment_id=assessment.id,
                            artifact_id=artifact.id,
                            repository_ref_id=assessment.repository_ref_id,
                            advisory_id=advisory.id,
                            classification=classification,
                        ),
                    )
                )
        affected = [
            r.analysis.assessment_id
            for r in rows
            if r.analysis.classification == ImpactClassification.AFFECTED
        ]
        filed = {
            o.assessment_id: o.finding_id
            for a in affected
            for o in self._require_findings().occurrences(assessment_id=a)
        }
        return [
            replace(r, analysis=r.analysis.model_copy(update={"finding_id": filed[a]}))
            if (a := r.analysis.assessment_id) in filed
            else r
            for r in rows
        ]

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

    def feed_payload(self, feed: FeedName) -> bytes | None:
        """The latest snapshot's bytes; None when the feed was never fetched."""
        with self._uow as uow:
            latest = uow.feed_snapshots.latest(feed)
            artifact = None if latest is None else self._log.get_artifact(latest.artifact_id)
        return None if artifact is None else stored_bytes(self._objects, artifact)

    def exploit_signals(self, identifiers: Sequence[AdvisoryIdentifier]) -> list[ExploitSignal]:
        """EPSS and KEV for each identifier, from the latest snapshot of each feed."""
        epss = epss_scores(self._required_payload(EPSS))
        kev = kev_entries(self._required_payload(KEV))
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

    def _required_payload(self, feed: FeedName) -> bytes:
        payload = self.feed_payload(feed)
        if payload is None:
            raise NotFoundError(f"feed {feed}: never fetched; refresh it first")
        return payload


@dataclass(frozen=True)
class _Recorded:
    at: tuple[datetime, UUID]
    identifier: str
    doc: ImpactAnalysisArtifact
    analysis: ImpactAnalysis


def _provenance(
    cve: PublishedCve, component: str, first: date, title: str, cwes: Sequence[str]
) -> ProvenanceMatch | None:
    """The CVE as a first-discovery match of the finding, or None when it can't be one."""
    # Only a CVE published after our first report can be our find; earlier ones we read.
    if (cve.component or "").lower() != component or cve.published <= first:
        return None
    score = _title_score(cve.title, title)
    if score < AUTO_PROBABLE:
        return None
    confirmed = score >= AUTO_CONFIRM or bool(set(cve.cwes) & set(cwes))
    return ProvenanceMatch(
        identifier=cve.identifier,
        title=cve.title,
        published=cve.published,
        lead_days=(cve.published - first).days,
        score=round(score, 3),
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
        origin=FindingOrigin(IMPACT_ASSESSOR),
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
    return SymbolResolution(status=SymbolStatus.RESOLVED, symbols=symbols) if symbols else None


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
        update={"status": SymbolStatus.RESOLVED, "symbols": (*found.symbols, *extra)}
    )
