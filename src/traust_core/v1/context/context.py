from __future__ import annotations

from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any, TypeVar

from sqlalchemy.engine import Engine

from traust_core.v1.clients import ProcessRunner
from traust_core.v1.context.config import Config
from traust_core.v1.domain.clock import Clock, SystemClock
from traust_core.v1.interfaces import (
    FeedProvider,
    Materializer,
    ProviderRegistry,
    SourceProvider,
    ToolProvider,
)
from traust_core.v1.repositories import (
    LocalObjectStore,
    ObjectStore,
    UnitOfWork,
    create_database_engine,
)
from traust_core.v1.repositories.analysis_results import AnalysisResultsRepository
from traust_core.v1.repositories.storage import SqlStorageUnitOfWork
from traust_core.v1.security.artifacts import ARTIFACT_FOR_KIND
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpecs,
    StorageIndex,
)

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
