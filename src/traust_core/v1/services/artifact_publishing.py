from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Generic, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import ConfigError, DocumentError, IntegrityError, Issue
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.base import Dto
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectStore
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork

A = TypeVar("A", bound=ArtifactDocument)


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
        for known in self._specs.values():
            if (
                known.artifact.schema == spec.artifact.schema
                and known.artifact.schema_type() is not spec.artifact.schema_type()
            ):
                raise ConfigError(
                    f"aliases of schema {spec.artifact.schema!r} need a common artifact type"
                )
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

    def artifact_type(self, schema: str) -> type[ArtifactDocument]:
        types = {
            s.artifact.schema_type() for s in self._specs.values() if s.artifact.schema == schema
        }
        if len(types) != 1:
            raise ConfigError(
                f"artifact schema {schema!r}: expected one registered type, got {len(types)}"
            )
        return types.pop()


def record_artifact(uow: AssessmentsUnitOfWork, artifact: Artifact) -> Artifact:
    """One writer for artifact metadata; the aggregate's caller commits."""
    known = uow.artifacts.get_or_add(artifact)
    if known.kind != artifact.kind:
        raise IntegrityError(f"artifact {known.id}: digest already recorded as {known.kind}")
    return known


class PublishResult(Dto):
    artifact: str
    written: tuple[str, ...]
    artifact_id: UUID


class ArtifactPublisher:
    def __init__(
        self,
        specs: PublishSpecs,
        objects: ObjectStore,
        uow: AssessmentsUnitOfWork,
    ) -> None:
        self._specs = specs
        self._objects = objects
        self._uow = uow

    def publish(self, name: str, raw: bytes) -> PublishResult:
        spec = self._specs.get(name)
        artifact = spec.artifact.parse(spec.input.to_json(name, raw))
        return self.publish_artifact(artifact)

    def publish_artifact(self, artifact: ArtifactDocument) -> PublishResult:
        spec = self._specs.get(artifact.name)
        artifact = spec.artifact.parse(artifact.payload)
        companions = [(c.kind, c.render(artifact)) for c in spec.companions]
        prefix = f"artifacts/{artifact.schema}"
        primary = self._objects.put(
            ObjectKey.parse(f"{prefix}/{sha256_hex(artifact.payload)}.json"), artifact.payload
        )
        written = [primary]
        for kind, data in companions:
            written.append(
                self._objects.put(
                    ObjectKey.parse(f"{prefix}/{sha256_hex(data)}-{kind.value}"), data
                )
            )
        with self._uow as uow:
            row = record_artifact(
                uow, Artifact(digest=primary.sha256, kind=artifact.schema, uri=str(primary.key))
            )
            uow.commit()
        assert row.id is not None
        return PublishResult(
            artifact=spec.name, written=tuple(str(r.key) for r in written), artifact_id=row.id
        )

    def get(self, artifact_id: UUID) -> ArtifactDocument:
        with self._uow as uow:
            row = uow.artifacts.get(artifact_id)
        artifact = self._specs.artifact_type(row.kind)
        ref = self._objects.stat(ObjectKey.parse(row.uri))
        return artifact.parse(self._objects.get(replace(ref, sha256=row.digest)))

    def verify(self, artifact_id: UUID) -> DigestCheck:
        raise NotImplementedError("stub: replaces verify_report_digests.py, ledger report digests")

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]:
        with self._uow as uow:
            return uow.artifacts.list_for_assessment(assessment_id, kind=kind)


class DigestCheck(Dto): ...


class Redacted(Dto): ...


class RedactionPolicy:
    def redact(self, payload: bytes) -> Redacted:
        raise NotImplementedError("stub: replaces _util/redact.py")
