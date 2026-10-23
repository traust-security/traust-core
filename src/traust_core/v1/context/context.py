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
from traust_core.v1.context.feeds import load_advisory_lookup, load_file_feeds
from traust_core.v1.context.observation import command_source, comment_sources
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import (
    ARTIFACT_FOR_KIND,
    CodeFactsArtifact,
    CorpusRegistryArtifact,
    RunManifestArtifact,
    TriageArtifact,
)
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.feeds import AdvisoryLookup, FeedProvider
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
from traust_core.v1.providers.identity import (
    CommandDirectory,
    CredentialStore,
    LocalIssuer,
    OidcLogin,
    TokenIdentityProvider,
)
from traust_core.v1.providers.impact import GovulncheckAnalyzer, SourceScanAnalyzer
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.providers.tools import ToolProvider
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
from traust_core.v1.services.ledger import LedgerService
from traust_core.v1.services.lint import Lint
from traust_core.v1.services.operations import Materializer, OpsService, SpendService
from traust_core.v1.services.portfolio import (
    PortfolioPolicy,
    PortfolioService,
    RepoStateQuery,
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
    ledger: LedgerService | None
    identity: IdentityService | None
    code_facts: CodeFactsService


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
        self.assets: ProviderRegistry[Materializer] = ProviderRegistry("asset")

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
        """Register a provider for each single-file feed, and the advisory lookup, from the
        feeds registry YAML."""
        for feed in load_file_feeds(registry, http=self.http, clock=self.clock):
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
        assessment = AssessmentService(uow, intake, clock=self.clock, hosts=hosts)
        ledger = None if self.config.ledger is None else LedgerService(uow, self.config.ledger)
        identity = self.config.identity
        precedents = FindingPrecedents(uow)
        review = ReviewPolicy(self.config.valve_salt())
        findings = FindingService(
            uow,
            intake,
            FindingDecisions(
                uow,
                ledger,
                Lint({TriageArtifact: [VerdictCitations()]}),
                precedents,
                clock=self.clock,
                objects=self.object_store,
                review=review,
                restatement=RestatementPolicy(identity.restatement_approvers if identity else 0),
            ),
            FindingReview(uow, review),
            precedents,
            RatingPolicy(self.config.rating),
            self.object_store,
        )
        portfolio = PortfolioService(
            uow,
            policy,
            assessment=assessment,
            sources=command_source(hosts, clock=self.clock),
            clock=self.clock,
            hosts=hosts,
            publisher=ArtifactPublisher(
                PublishSpecs(PublishSpec(CorpusRegistryArtifact)), self.object_store, uow
            ),
        )
        return Services(
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
            exposure=ExposureService(
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
            ),
            ops=OpsService(
                uow,
                self.clock,
                ArtifactPublisher(
                    PublishSpecs(PublishSpec(RunManifestArtifact)), self.object_store, uow
                ),
            ),
            spend=SpendService(uow, self.clock, self.config.budgets),
            ledger=ledger,
            identity=self.identity,
            code_facts=CodeFactsService(
                assessment,
                ArtifactPublisher(
                    PublishSpecs(PublishSpec(CodeFactsArtifact)), self.object_store, uow
                ),
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

        Reads inventory, assessments and open counts from the contract tables
        over one session unit of work; forge facts live for the session (NEED marker
        in services/portfolio.py).
        """
        policy = PortfolioPolicy()
        with SqlTraustUnitOfWork(self.database) as uow:
            services = self._wire(uow, policy)
            query = RepoStateQuery(
                services.portfolio,
                services.assessment,
                services.findings,
                policy,
                designations=load_designations(designations) if designations is not None else (),
                clock=self.clock,
                hosts=self.config.forge_hosts,
            )
            yield _Observation(service=services.portfolio, query=query)
