from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, Protocol, TypeVar

from traust_core.v1.artifacts import Artifact
from traust_core.v1.domain.analysis_results import ResultKind, Subject
from traust_core.v1.domain.clock import Clock
from traust_core.v1.domain.errors import ConfigError, DocumentError, Issue, TraustError
from traust_core.v1.domain.model import Dto
from traust_core.v1.domain.storage import BindingContext
from traust_core.v1.repositories.analysis_results import AnalysisResultsRepository, artifact_kind
from traust_core.v1.repositories.object_store import ObjectRef
from traust_core.v1.repositories.storage import StorageUnitOfWork
from traust_core.v1.services.storage import record_artifact

A = TypeVar("A", bound=Artifact)


class InputFormat(Protocol):
    def to_json(self, artifact: str, raw: bytes) -> bytes: ...


class JsonInput:
    def to_json(self, artifact: str, raw: bytes) -> bytes:
        if not raw.strip():
            raise DocumentError(artifact, [Issue("$", "empty input")])
        return raw


@dataclass(frozen=True, slots=True)
class Companion(Generic[A]):
    kind: ResultKind
    render: Callable[[A], bytes]


@dataclass(frozen=True, slots=True)
class PublishSpec(Generic[A]):
    artifact: type[A]
    companions: tuple[Companion[A], ...] = ()
    input: InputFormat = field(default_factory=JsonInput)

    @property
    def name(self) -> str:
        return self.artifact.name


class PublishSpecs:
    def __init__(self, *specs: PublishSpec[Any]) -> None:
        self._specs: dict[str, PublishSpec[Any]] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: PublishSpec[Any]) -> None:
        if spec.name in self._specs:
            raise ConfigError(f"artifact spec {spec.name!r} registered twice")
        self._specs[spec.name] = spec

    def get(self, name: str) -> PublishSpec[Any]:
        try:
            return self._specs[name]
        except KeyError:
            raise ConfigError(
                f"unknown artifact {name!r}; known: {', '.join(sorted(self._specs))}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._specs)


class ArtifactIndex(Protocol):
    def record(self, artifact: Artifact, subject: Subject, ref: ObjectRef, run_id: str) -> str: ...


class StorageIndex:
    def __init__(self, storage: Callable[[], StorageUnitOfWork], clock: Clock) -> None:
        self._storage = storage
        self._clock = clock

    def record(self, artifact: Artifact, subject: Subject, ref: ObjectRef, run_id: str) -> str:
        context = BindingContext(subject_id=subject.key, run_id=run_id, role=artifact.role)
        result = record_artifact(
            self._storage(), artifact.schema, artifact.payload, self._clock, context, [str(ref.key)]
        )
        return result.binding_id


class PublishResult(Dto):
    artifact: str
    written: tuple[str, ...]
    binding_id: str | None = None
    index_error: str | None = None

    @property
    def degraded(self) -> bool:
        return self.index_error is not None


class ArtifactPublisher:
    def __init__(
        self,
        specs: PublishSpecs,
        results: AnalysisResultsRepository,
        index: ArtifactIndex | None = None,
    ) -> None:
        self._specs = specs
        self._results = results
        self._index = index

    def publish(self, name: str, subject: Subject, raw: bytes, run_id: str) -> PublishResult:
        spec = self._specs.get(name)
        artifact = spec.artifact.parse(spec.input.to_json(name, raw))
        return self.publish_artifact(artifact, subject, run_id)

    def publish_artifact(self, artifact: Artifact, subject: Subject, run_id: str) -> PublishResult:
        spec = self._specs.get(artifact.name)
        primary = self._results.put(subject, artifact_kind(spec.artifact), artifact.payload)
        written = [
            primary,
            *(self._results.put(subject, c.kind, c.render(artifact)) for c in spec.companions),
        ]
        result = PublishResult(artifact=spec.name, written=tuple(str(r.key) for r in written))
        if self._index is None:
            return result
        try:
            binding = self._index.record(artifact, subject, primary, run_id)
        except TraustError as e:
            return result.model_copy(update={"index_error": str(e)})
        return result.model_copy(update={"binding_id": binding})
