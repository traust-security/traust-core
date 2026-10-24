from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, TypeVar

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from traust_core.v1 import contracts
from traust_core.v1.context.config import Config
from traust_core.v1.context.designations import load_designations
from traust_core.v1.context.feeds import load_advisory_lookup, load_feeds
from traust_core.v1.context.observation import command_source, comment_sources
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import (
    ARTIFACT_FOR_KIND,
    AdrRegistryArtifact,
    BenchmarkTargetArtifact,
    CloudConfigAuditArtifact,
    CodeFactsArtifact,
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
    CorpusRegistryArtifact,
    DocVarianceArtifact,
    FleetFixArtifact,
    PqcFactsArtifact,
    PqcReadinessArtifact,
    PrivProfileArtifact,
    RemediationArtifact,
    ReportArtifact,
    RepoStateArtifact,
    RunManifestArtifact,
    ThreatModelArtifact,
    TriageArtifact,
    VerificationArtifact,
)
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.collaboration import AdrSource, DocSource
from traust_core.v1.providers.crypto import CryptoProbe
from traust_core.v1.providers.crypto_cluster import ClusterCryptoProbe
from traust_core.v1.providers.crypto_image import ImageCryptoProbe
from traust_core.v1.providers.detection_quality import CanaryMaterializer, RulePackSource
from traust_core.v1.providers.feeds import AdvisoryLookup, FeedProvider
from traust_core.v1.providers.fleet_fix import FleetFixApplier, GoldenRunner
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
from traust_core.v1.providers.identity import (
    CommandDirectory,
    CredentialStore,
    LocalIssuer,
    OidcLogin,
    TokenIdentityProvider,
)
from traust_core.v1.providers.impact import GovulncheckAnalyzer, SourceScanAnalyzer
from traust_core.v1.providers.model_catalog import ModelCatalog
from traust_core.v1.providers.pqc import PqcScanner
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.providers.syft import SyftSbom
from traust_core.v1.providers.symbols import SymbolIndex
from traust_core.v1.providers.tools import ToolInspector, ToolProvider
from traust_core.v1.repositories import (
    LocalObjectStore,
    ObjectStore,
    UnitOfWork,
    apply_schema,
    create_database_engine,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.analysis_results import AnalysisResultsRepository
from traust_core.v1.repositories.sql import Dialect
from traust_core.v1.repositories.tables import TableFactory
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.attestation import AttestationService, StatementPolicy
from traust_core.v1.services.code_facts import CodeFactsService
from traust_core.v1.services.compliance import ComplianceService
from traust_core.v1.services.detection_quality import DetectionQualityService
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import (
    FindingDecisions,
    FindingIntake,
    FindingPrecedents,
    FindingReview,
    FindingService,
    IdentityPolicy,
    RatingPolicy,
    ReviewPolicy,
    TaxonomyPolicy,
)
from traust_core.v1.services.findings.citations import VerdictCitations
from traust_core.v1.services.findings.restatement import RestatementPolicy
from traust_core.v1.services.identity import IdentityService
from traust_core.v1.services.insight import (
    ComplianceDashboardView,
    CoverageView,
    ExecutiveSummaryView,
    ExposureView,
    FindingsRollupView,
    FindingsTrendView,
    InsightService,
    LocView,
    PqcView,
    ProgramView,
    ReviewCardView,
    ThreatRegisterView,
    TriageView,
)
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint
from traust_core.v1.services.onboarding import OnboardingService
from traust_core.v1.services.operations import (
    FreshnessQuery,
    Materializer,
    OpsService,
    SpendService,
)
from traust_core.v1.services.portfolio import (
    PortfolioPolicy,
    PortfolioService,
    PortfolioSync,
    RepoStateQuery,
)
from traust_core.v1.services.pqc import PqcService
from traust_core.v1.services.provider_catalog import ProviderCatalog
from traust_core.v1.services.remediation import (
    ForkPolicy,
    RemediationService,
    VerificationService,
)

U = TypeVar("U", bound=UnitOfWork)


# NEED(direction): the REST API is a thin adapter over Services, and the SDK becomes a
# framework (prepare -> run skill -> record) on top of that REST API, not thin wrappers.
@dataclass(frozen=True)
class Services:
    assessment: AssessmentService
    portfolio: PortfolioService
    findings: FindingService
    attestation: AttestationService
    exposure: ExposureService
    ops: OpsService
    spend: SpendService
    catalog: ProviderCatalog
    freshness: FreshnessQuery
    ledger: LedgerService | None
    identity: IdentityService | None
    code_facts: CodeFactsService
    sync: PortfolioSync
    onboarding: OnboardingService
    compliance: ComplianceService
    detection_quality: DetectionQualityService
    remediation: RemediationService
    insight: InsightService
    pqc: PqcService
    verification: VerificationService


@dataclass(frozen=True)
class _Observation:
    """What the observation door yields: the write path and the composite read."""

    service: PortfolioService
    query: RepoStateQuery


class Context:
    def __init__(
        self,
        config: Config,
        *,
        clock: Clock | None = None,
        object_store: ObjectStore | None = None,
        process: ProcessRunner | None = None,
    ) -> None:
        self.config = config
        self.clock: Clock = clock or SystemClock()
        self._object_store = object_store
        self._process = process
        self.tools: ProviderRegistry[ToolProvider[Any]] = ProviderRegistry("tool")
        self.sources: ProviderRegistry[SourceProvider] = ProviderRegistry("source")
        self.feeds: ProviderRegistry[FeedProvider] = ProviderRegistry("feed")
        self.advisories: AdvisoryLookup | None = None
        self.pqc_scanner: PqcScanner | None = None  # traust-engine registers pqc-scan
        self.fleet_fix_applier: FleetFixApplier | None = None  # traust-engine registers it
        self.fleet_fix_goldens: GoldenRunner | None = None  # traust-engine registers it
        # traust-engine registers these (compliance and detection-quality doors raise without)
        self.adr_source: AdrSource | None = None
        self.doc_source: DocSource | None = None
        self.rule_packs: RulePackSource | None = None
        self.canaries: CanaryMaterializer | None = None
        self.assets: ProviderRegistry[Materializer] = ProviderRegistry("asset")
        self.tool_inspector: ToolInspector | None = None  # traust-engine registers its toolchain
        self.tool_floors: dict[str, str] = {}  # pack policy: minimum tool versions
        self.model_catalog: ModelCatalog | None = None  # NEED(model-registry)

    @classmethod
    def from_file(cls, path: Path) -> Context:
        return cls(Config.from_file(path))

    @cached_property
    def object_store(self) -> ObjectStore:
        return self._object_store or LocalObjectStore(self.config.artifacts_path())

    @cached_property
    def process(self) -> ProcessRunner:
        if self._process is not None:
            return self._process
        cfg = self.config.process
        return ProcessRunner(
            cfg.allowed_binaries, keep_env=cfg.keep_env, timeout_seconds=cfg.timeout_seconds
        )

    @cached_property
    def git(self) -> GitCheckout:
        return GitCheckout(self.process)

    @cached_property
    def symbols(self) -> SymbolIndex:
        return SymbolIndex(self.process, self.clock)

    @cached_property
    def http(self) -> HttpFetcher:
        policy = RetryPolicy(**self.config.http.model_dump())
        return HttpFetcher("traust-core", policy, clock=self.clock)

    @cached_property
    def identity(self) -> IdentityService | None:
        """Caller verification from the `identity:` section; the local issuer is always known."""
        cfg = self.config.identity
        if cfg is None:
            return None
        provider = TokenIdentityProvider(
            cfg.issuers,
            local_jwks=self.local_jwks,
            trust_local=cfg.trust_local,
            identity_claim=cfg.identity_claim,
            machine_claim=cfg.machine_claim,
        )
        directory = None
        if command := cfg.directory_command:
            if not (shutil.which(command[0]) or Path(command[0]).is_file()):
                raise ConfigError(f"identity.directory_command: program not found: {command[0]}")
            runner = ProcessRunner(
                [Path(command[0]).name], timeout_seconds=cfg.directory_timeout_seconds
            )
            directory = CommandDirectory(command, runner)
        return IdentityService(provider, directory, cfg.admins)

    @property
    def local_jwks(self) -> Path:
        return self.local_issuer.jwks

    @cached_property
    def local_issuer(self) -> LocalIssuer:
        return LocalIssuer(self.config.home, self.clock)

    @cached_property
    def credentials(self) -> CredentialStore:
        return CredentialStore(self.config.home)

    @cached_property
    def login(self) -> OidcLogin | None:
        """Getting a token from the deployment's identity provider (`identity.login`)."""
        cfg = self.config.identity.login if self.config.identity else None
        if cfg is None:
            return None
        return OidcLogin(cfg.issuer, cfg.client_id, self.http, self.clock, scope=cfg.scope)

    def register_feeds(self, registry: Path) -> None:
        """Register a provider for each cached feed, and the advisory lookup, from the
        feeds registry YAML."""
        for feed in load_feeds(registry, http=self.http, clock=self.clock):
            self.feeds.register(feed.name, lambda feed=feed: feed)
        self.advisories = load_advisory_lookup(registry, http=self.http, clock=self.clock)

    @cached_property
    def database(self) -> Engine:
        local = self.config.database.url is None
        if local:
            self.config.home.mkdir(parents=True, exist_ok=True)
        engine = create_database_engine(self.config.record_store_url())
        if local and not sa.inspect(engine).get_table_names():
            apply_schema(engine, contracts.database_ddl(Dialect.of(engine)))
        return engine

    @cached_property
    def dialect(self) -> Dialect:
        return Dialect.of(self.database)

    @cached_property
    def tables(self) -> TableFactory:
        """Contract tables for the configured database: schemas on Postgres, prefixes on SQLite."""
        return TableFactory.for_dialect(self.dialect)

    def unit_of_work(self, factory: Callable[[Engine], U]) -> U:
        """e.g. unit_of_work(SqlTraustUnitOfWork): every repository, one transaction."""
        return factory(self.database)

    def artifact_publisher(self, specs: PublishSpecs) -> ArtifactPublisher:
        return ArtifactPublisher(specs, self.object_store, SqlTraustUnitOfWork(self.database))

    def services(self) -> Services:
        return self._wire(SqlTraustUnitOfWork(self.database), PortfolioPolicy())

    def _wire(self, uow: SqlTraustUnitOfWork, policy: PortfolioPolicy) -> Services:
        hosts = self.config.forge_hosts
        intake = FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy())
        ledger = None if self.config.ledger is None else LedgerService(uow, self.config.ledger)
        identity = self.config.identity
        precedents = FindingPrecedents(uow)
        rating = RatingPolicy(self.config.rating)
        review = ReviewPolicy(self.config.valve_salt())
        decisions = FindingDecisions(
            uow,
            ledger,
            Lint({TriageArtifact: [VerdictCitations()]}),
            precedents,
            clock=self.clock,
            objects=self.object_store,
            review=review,
            restatement=RestatementPolicy(identity.restatement_approvers if identity else 0),
        )
        findings = FindingService(
            uow,
            intake,
            decisions,
            FindingReview(uow, review),
            precedents,
            rating,
            self.object_store,
        )
        assessment = AssessmentService(
            uow,
            intake,
            clock=self.clock,
            hosts=hosts,
            tools=self.tools,
            decisions=decisions,
            publisher=ArtifactPublisher(
                PublishSpecs(
                    PublishSpec(CloudConfigAuditArtifact),
                    PublishSpec(ReportArtifact),
                    PublishSpec(ThreatModelArtifact),
                    PublishSpec(PrivProfileArtifact),
                ),
                self.object_store,
                uow,
            ),
            findings=findings,
            git=self.git,
            symbols=self.symbols,
        )
        sources = command_source(hosts, clock=self.clock)
        portfolio = PortfolioService(
            uow,
            policy,
            assessment=assessment,
            sources=sources,
            clock=self.clock,
            hosts=hosts,
            publisher=ArtifactPublisher(
                PublishSpecs(PublishSpec(CorpusRegistryArtifact), PublishSpec(RepoStateArtifact)),
                self.object_store,
                uow,
            ),
        )
        exposure = ExposureService(
            uow,
            intake,
            feeds=self.feeds,
            objects=self.object_store,
            advisories=self.advisories,
            portfolio=portfolio,
            clock=self.clock,
            analyzers=(
                GovulncheckAnalyzer(self.process, self.clock),
                SourceScanAnalyzer(self.clock),
            ),
            sources=command_source(hosts, clock=self.clock),
            hosts=hosts,
            sbom_tool=SyftSbom(self.process, self.clock),
            findings=findings,
        )
        sync = PortfolioSync(portfolio, sources, clock=self.clock)
        spend = SpendService(uow, self.clock, self.config.budgets, self.model_catalog)
        catalog = ProviderCatalog(
            self.tools,
            self.feeds,
            inspector=self.tool_inspector,
            models=self.model_catalog,
            floors=self.tool_floors,
        )
        ops = OpsService(
            uow,
            self.clock,
            ArtifactPublisher(
                PublishSpecs(PublishSpec(RunManifestArtifact)), self.object_store, uow
            ),
        )
        compliance = ComplianceService(
            uow,
            portfolio=portfolio,
            findings=findings,
            publisher=ArtifactPublisher(
                PublishSpecs(
                    PublishSpec(ComplianceScopeArtifact),
                    PublishSpec(ComplianceMappingArtifact),
                    PublishSpec(ComplianceAssessmentArtifact),
                    PublishSpec(AdrRegistryArtifact),
                    PublishSpec(DocVarianceArtifact),
                ),
                self.object_store,
                uow,
            ),
            objects=self.object_store,
            clock=self.clock,
            hosts=hosts,
            adr_source=self.adr_source,
            docs=self.doc_source,
            # NEED(contracts): org parameters are Config (D8) but the config schema has no
            # section yet; until it lands, `param:` checks verdict not_assessed (undeclared).
        )
        code_facts = CodeFactsService(
            assessment,
            ArtifactPublisher(PublishSpecs(PublishSpec(CodeFactsArtifact)), self.object_store, uow),
            (CryptoProbe(self.clock), self.symbols),
            exposure,
            image=ImageCryptoProbe(self.process, self.clock),
            cluster=ClusterCryptoProbe(self.process, self.clock),
            clock=self.clock,
        )
        pqc = PqcService(
            uow,
            code_facts,
            portfolio,
            ArtifactPublisher(
                PublishSpecs(PublishSpec(PqcFactsArtifact), PublishSpec(PqcReadinessArtifact)),
                self.object_store,
                uow,
            ),
            scanner=self.pqc_scanner,
            clock=self.clock,
        )
        remediation = RemediationService(
            uow,
            findings,
            assessment=assessment,
            clock=self.clock,
            forks=ForkPolicy(self.config.remediation, hosts),
            publisher=ArtifactPublisher(
                PublishSpecs(PublishSpec(RemediationArtifact), PublishSpec(FleetFixArtifact)),
                self.object_store,
                uow,
            ),
            portfolio=portfolio,
            exposure=exposure,
            ops=ops,
            applier=self.fleet_fix_applier,
            goldens=self.fleet_fix_goldens,
        )
        return Services(
            compliance=compliance,
            assessment=assessment,
            portfolio=portfolio,
            findings=findings,
            attestation=AttestationService(
                uow,
                findings.decisions,
                findings.review,
                comment_sources(hosts, clock=self.clock),
                StatementPolicy(),
            ),
            exposure=exposure,
            ops=ops,
            spend=spend,
            catalog=catalog,
            freshness=FreshnessQuery(catalog, exposure, self.clock),
            ledger=ledger,
            identity=self.identity,
            code_facts=code_facts,
            sync=sync,
            onboarding=OnboardingService(portfolio, sync, ops, clock=self.clock),
            detection_quality=DetectionQualityService(
                uow,
                findings,
                ArtifactPublisher(
                    PublishSpecs(
                        PublishSpec(BenchmarkTargetArtifact),
                        PublishSpec(ReportArtifact),
                        PublishSpec(ComplianceAssessmentArtifact),
                    ),
                    self.object_store,
                    uow,
                ),
                clock=self.clock,
                rule_packs=self.rule_packs,
                canaries=self.canaries,
            ),
            pqc=pqc,
            remediation=remediation,
            verification=VerificationService(
                uow,
                findings,
                remediation,
                exposure,
                assessment=assessment,
                clock=self.clock,
                publisher=ArtifactPublisher(
                    PublishSpecs(PublishSpec(VerificationArtifact)), self.object_store, uow
                ),
            ),
            insight=InsightService(
                (
                    FindingsRollupView(findings, portfolio),
                    FindingsTrendView(findings, portfolio, self.clock),
                    ProgramView(spend, ops, self.assets.names),
                    CoverageView(assessment, portfolio, self.clock),
                    ExposureView(exposure),
                    PqcView(pqc),
                    ComplianceDashboardView(compliance),
                    ThreatRegisterView(assessment, compliance, portfolio, rating, self.clock),
                    LocView(code_facts, portfolio),
                    ExecutiveSummaryView(findings, portfolio, assessment, code_facts, exposure),
                    ReviewCardView(findings, portfolio),
                    TriageView(
                        ArtifactPublisher(
                            PublishSpecs(PublishSpec(TriageArtifact)), self.object_store, uow
                        )
                    ),
                ),
                self.clock,
            ),
        )

    def analysis_results(self) -> AnalysisResultsRepository:
        return AnalysisResultsRepository(self.object_store, ARTIFACT_FOR_KIND)

    @contextmanager
    def repository_observation(
        self,
        *,
        designations: Path | None = None,
    ) -> Iterator[_Observation]:
        """Observe repositories: forge facts in, derived routing state out.

        Each observation commits as its own transaction; forge facts are kept as repo-state
        assessments and on the repository row.
        """
        policy = PortfolioPolicy()
        services = self._wire(SqlTraustUnitOfWork(self.database), policy)
        yield _Observation(
            service=services.portfolio,
            query=RepoStateQuery(
                services.portfolio,
                services.assessment,
                services.findings,
                policy,
                designations=load_designations(designations) if designations is not None else (),
                clock=self.clock,
                hosts=self.config.forge_hosts,
            ),
        )
