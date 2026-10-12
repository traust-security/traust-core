from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import cached_property
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from traust_core.v1.context.config import Config
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.artifacts import ARTIFACT_FOR_KIND
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.providers.forge import CommandSourceProvider
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import SourceProvider
from traust_core.v1.providers.tools import ToolProvider
from traust_core.v1.repositories import (
    LocalObjectStore,
    ObjectStore,
    UnitOfWork,
    create_database_engine,
)
from traust_core.v1.repositories.analysis_results import (
    AnalysisResultsRepository,
    FileAuditMetadataRepository,
)
from traust_core.v1.repositories.assessment import SqlAssessmentUnitOfWork
from traust_core.v1.repositories.designations import (
    FileDesignationRepository,
    InMemoryDesignationRepository,
)
from traust_core.v1.repositories.findings import SqlFindingUnitOfWork
from traust_core.v1.repositories.portfolio import (
    InMemoryInventoryUnitOfWork,
    SqlInventoryUnitOfWork,
    SqlPortfolioUnitOfWork,
)
from traust_core.v1.repositories.portfolio import (
    metadata as portfolio_metadata,
)
from traust_core.v1.repositories.sql import schema_drift
from traust_core.v1.repositories.storage import SqlStorageUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpecs,
    StorageIndex,
)
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.operations import Materializer
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

U = TypeVar("U", bound=UnitOfWork)


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
        self.feeds: ProviderRegistry[FeedProvider[Any]] = ProviderRegistry("feed")
        self.assets: ProviderRegistry[Materializer] = ProviderRegistry("asset")

    @classmethod
    def from_file(cls, path: Path) -> Context:
        return cls(Config.from_file(path))

    @cached_property
    def object_store(self) -> ObjectStore:
        return self._object_store or LocalObjectStore(self.config.artifacts.path)

    @cached_property
    def process(self) -> ProcessRunner:
        if self._process is not None:
            return self._process
        cfg = self.config.process
        return ProcessRunner(
            cfg.allowed_binaries, keep_env=cfg.keep_env, timeout_seconds=cfg.timeout_seconds
        )

    @cached_property
    def database(self) -> Engine:
        return create_database_engine(self.config.database.engine_url())

    def unit_of_work(self, factory: Callable[[Engine], U]) -> U:
        return factory(self.database)

    def artifact_publisher(self, specs: PublishSpecs) -> ArtifactPublisher:
        index = None
        if self.config.database.url is not None:
            engine = self.database
            index = StorageIndex(lambda: SqlStorageUnitOfWork(engine), self.clock)
        return ArtifactPublisher(
            specs, AnalysisResultsRepository(self.object_store, ARTIFACT_FOR_KIND), index
        )

    def analysis_results(self) -> AnalysisResultsRepository:
        return AnalysisResultsRepository(self.object_store, ARTIFACT_FOR_KIND)

    @contextmanager
    def repository_observation(
        self,
        findings_db: Path,
        *,
        inventory_db: Path | None = None,
        designations: Path | None = None,
    ) -> Iterator[PortfolioService]:
        url = self.config.database.engine_url()
        inputs = [findings_db, *([inventory_db] if inventory_db else [])]
        if (
            url.get_backend_name() == "sqlite"
            and url.database
            and Path(url.database).resolve() in {path.resolve() for path in inputs}
        ):
            raise ConfigError("Core database must be separate from read-only input projections")
        state_db = self.database
        problems = schema_drift(state_db, portfolio_metadata)
        if problems:
            raise ConfigError(
                "Portfolio storage is not initialized or needs migration: " + "; ".join(problems)
            )
        projection = _readonly_projection(findings_db)
        inventory_engine = (
            _readonly_projection(inventory_db) if inventory_db and inventory_db.is_file() else None
        )
        try:
            inventory = (
                SqlInventoryUnitOfWork(inventory_engine)
                if inventory_engine is not None
                else InMemoryInventoryUnitOfWork()
            )
            assessment = AssessmentService(
                SqlAssessmentUnitOfWork(projection),
                reports=FileAuditMetadataRepository(),
                inventory=inventory,
                clock=self.clock,
                hosts=self.config.forge_hosts,
            )
            yield PortfolioService(
                SqlPortfolioUnitOfWork(state_db),
                PortfolioPolicy(),
                assessment=assessment,
                findings=SqlFindingUnitOfWork(projection),
                sources=CommandSourceProvider(self.process, self.clock, self.config.forge_hosts),
                clock=self.clock,
                hosts=self.config.forge_hosts,
                designations=FileDesignationRepository(designations)
                if designations
                else InMemoryDesignationRepository(),
            )
        finally:
            projection.dispose()
            if inventory_engine is not None:
                inventory_engine.dispose()
            state_db.dispose()


def _readonly_projection(path: Path) -> Engine:
    return create_database_engine(
        sa.URL.create(
            "sqlite",
            database=f"file:{quote(str(path.resolve()), safe='/')}",
            query={"mode": "ro", "uri": "true"},
        )
    )
