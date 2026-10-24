from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Generic, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import ConfigError, ConflictError, DocumentError, IntegrityError, Issue
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectStore
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork

A = TypeVar("A", bound=ArtifactDocument)
_BATCH = 500  # ids per IN list


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


def stored_bytes(objects: ObjectStore, row: Artifact) -> bytes:
    """An artifact row's bytes, checked against the digest it was recorded with."""
    ref = objects.stat(ObjectKey.parse(row.uri))
    return objects.get(replace(ref, sha256=row.digest))


class AssessmentLog:
    """Assessments and their recorded documents on the caller's uow (needs only the uow)."""

    def __init__(self, uow: AssessmentsUnitOfWork) -> None:
        self._uow = uow

    def get(self, assessment_id: UUID) -> Assessment:
        with self._uow as uow:
            return uow.assessments.get(assessment_id)

    def find_at(self, assessment_id: UUID, occurred_at: datetime) -> Assessment | None:
        with self._uow as uow:
            return uow.assessments.find_at(assessment_id, occurred_at)

    def get_artifact(self, artifact_id: UUID) -> Artifact:
        with self._uow as uow:
            return uow.artifacts.get(artifact_id)

    def list_artifacts_by_ids(self, artifact_ids: Collection[UUID]) -> list[Artifact]:
        ids = tuple(artifact_ids)
        with self._uow as uow:
            return [
                artifact
                for start in range(0, len(ids), _BATCH)
                for artifact in uow.artifacts.list_by_ids(ids[start : start + _BATCH])
            ]

    def list_by_ids(self, assessment_ids: Collection[UUID]) -> list[Assessment]:
        with self._uow as uow:
            return uow.assessments.list_by_ids(assessment_ids)

    def list_of(
        self, kind: str | None, repository_ref_ids: Sequence[UUID] | None = None
    ) -> list[Assessment]:
        """The assessments of `kind` (any when None) on the refs, or on every ref when None."""
        with self._uow as uow:
            if repository_ref_ids is not None:
                return [
                    a
                    for i in range(0, len(repository_ref_ids), _BATCH)
                    for a in uow.assessments.list_for_refs(repository_ref_ids[i : i + _BATCH], kind)
                ]
            found: list[Assessment] = []
            after = None
            while page := uow.assessments.search(kind=kind, limit=_BATCH, after=after):
                found += page
                after = (page[-1].occurred_at, page[-1].id)
            return found

    def documents(
        self, assessments: Iterable[Assessment], kinds: Collection[str] | None
    ) -> list[tuple[Assessment, Artifact]]:
        """The documents of `kinds` the assessments hold, newest assessment first."""
        ordered = sorted(
            (a for a in assessments if a.id is not None),
            key=lambda a: (a.occurred_at, a.created_at or a.occurred_at),
            reverse=True,
        )
        ids = [a.id for a in ordered]
        held: dict[UUID | None, list[Artifact]] = {}
        with self._uow as uow:
            for i in range(0, len(ids), _BATCH):
                for row in uow.artifacts.list_for_assessments(ids[i : i + _BATCH], kinds):  # type: ignore[arg-type]
                    held.setdefault(row.assessment_id, []).append(row)
        return [(a, row) for a in ordered for row in held.get(a.id, ())]

    def find_recorded(
        self,
        repository_ref_ids: Iterable[UUID],
        kind: str,
        document: str,
        digest: str,
        *,
        baseline_id: UUID | None = None,
    ) -> list[tuple[Assessment, Artifact]]:
        """The `kind` assessments on the refs (ref order, oldest first) holding these bytes."""
        found: list[tuple[Assessment, Artifact]] = []
        with self._uow as uow:
            for ref_id in repository_ref_ids:
                runs = {
                    a.id: a
                    for a in uow.assessments.list_for_refs([ref_id], kind)
                    if baseline_id is None or a.baseline_assessment_id == baseline_id
                }
                held = {
                    r.assessment_id: r
                    for r in (uow.artifacts.list_for_assessments(runs, [document]) if runs else [])  # type: ignore[arg-type]
                    if r.digest == digest
                }
                found += [(a, held[i]) for i, a in runs.items() if i in held]
        return found

    def attach(self, assessment_id: UUID, artifact_id: UUID, digest: str) -> Artifact:
        """Record the published artifact on the assessment; IntegrityError unless it is `digest`."""
        with self._uow as uow:
            published = uow.artifacts.get(artifact_id)
            if published.digest != digest:
                raise IntegrityError(
                    f"artifact {artifact_id}: doc digest {digest} != published {published.digest}"
                )
            return record_artifact(
                uow,
                Artifact(
                    assessment_id=assessment_id,
                    digest=published.digest,
                    kind=published.kind,
                    uri=published.uri,
                ),
            )

    def open(self, assessment: Assessment) -> Assessment:
        """A new assessment with no document yet, committed with the caller's work."""
        with self._uow as uow:
            added = uow.assessments.add(assessment)
            uow.commit()
        return added

    def add(
        self, assessment: Assessment, artifact_id: UUID, digest: str
    ) -> tuple[Assessment, Artifact]:
        """A new assessment holding the published artifact, committed with the caller's work."""
        with self._uow as uow:
            assessment = self.open(assessment)
            assert assessment.id is not None
            artifact = self.attach(assessment.id, artifact_id, digest)
            uow.commit()
        return assessment, artifact


@dataclass(frozen=True, slots=True)
class Imported(Generic[A]):
    artifact_id: UUID
    document: A


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
        return self._publish(artifact, None)

    def publish_ref(self, artifact: ArtifactDocument) -> ArtifactRef:
        """Publish the document and return the reference provenance carries."""
        published = self._publish(artifact, None)
        return ArtifactRef(
            id=published.artifact_id, name=artifact.name, digest=sha256_hex(artifact.payload)
        )

    def publish_successor(self, artifact: ArtifactDocument, prior: UUID | None) -> PublishResult:
        """Publish the next version of an imported document read at `prior` (None = none yet).

        ConflictError if another writer published after `prior`; IntegrityError if the
        recorded row is not then the newest (a digest match returned an older version).
        """
        return self._publish(artifact, _Successor(prior))

    def _publish(self, artifact: ArtifactDocument, successor: _Successor | None) -> PublishResult:
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
            if successor is not None:
                successor.require_latest(uow, artifact.schema)
            row = record_artifact(
                uow, Artifact(digest=primary.sha256, kind=artifact.schema, uri=str(primary.key))
            )
            if successor is not None:
                successor.require_newest(uow, artifact.schema, row)
            uow.commit()
        assert row.id is not None
        return PublishResult(
            artifact=spec.name, written=tuple(str(r.key) for r in written), artifact_id=row.id
        )

    def metadata(self, artifact_id: UUID) -> Artifact:
        return AssessmentLog(self._uow).get_artifact(artifact_id)

    def get(self, artifact_id: UUID) -> ArtifactDocument:
        row = self.metadata(artifact_id)
        return self._read(row, self._specs.artifact_type(row.kind))

    def payload(self, artifact_id: UUID) -> bytes:
        """The recorded bytes, including companions without an artifact schema."""
        return stored_bytes(self._objects, self.metadata(artifact_id))

    def read(self, artifact_id: UUID, artifact: type[A]) -> A:
        """The stored document as `artifact`; IntegrityError if it is another kind."""
        doc = self.get(artifact_id)
        if not isinstance(doc, artifact):
            raise IntegrityError(f"artifact {artifact_id} is not a {artifact.schema} document")
        return doc

    def latest(self, artifact: type[A]) -> A | None:
        """The newest imported document of this type (configuration documents)."""
        latest = self.latest_imported(artifact)
        return None if latest is None else latest.document

    def latest_imported(self, artifact: type[A]) -> Imported[A] | None:
        """The newest imported document with its id, the `prior` for publish_successor."""
        with self._uow as uow:
            row = uow.artifacts.latest_imported(artifact.schema)
        if row is None:
            return None
        assert row.id is not None
        return Imported(row.id, self._read(row, artifact))

    def find(self, digest: str) -> Artifact | None:
        """The published row of these bytes, None when they were never published."""
        with self._uow as uow:
            return uow.artifacts.find(None, digest)

    def history(self, artifact: type[A], limit: int) -> list[Artifact]:
        """The imported rows of this type, newest first."""
        with self._uow as uow:
            return uow.artifacts.list_imported(artifact.schema, limit=limit)

    def _read(self, row: Artifact, artifact: type[A]) -> A:
        return artifact.parse(stored_bytes(self._objects, row))

    def verify(self, artifact_id: UUID) -> DigestCheck:
        raise NotImplementedError("stub: replaces verify_report_digests.py, ledger report digests")

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]:
        with self._uow as uow:
            return uow.artifacts.list_for_assessment(assessment_id, kind=kind)


@dataclass(frozen=True, slots=True)
class _Successor:
    prior: UUID | None

    def require_latest(self, uow: AssessmentsUnitOfWork, kind: str) -> None:
        latest = uow.artifacts.latest_imported(kind)
        if (None if latest is None else latest.id) != self.prior:
            raise ConflictError(f"{kind}: another writer published since {self.prior}")

    def require_newest(self, uow: AssessmentsUnitOfWork, kind: str, row: Artifact) -> None:
        latest = uow.artifacts.latest_imported(kind)
        if latest is None or latest.id != row.id:
            raise IntegrityError(f"{kind}: published {row.id} is not the newest version")


class DigestCheck(Dto): ...


class Redacted(Dto): ...


class RedactionPolicy:
    def redact(self, payload: bytes) -> Redacted:
        raise NotImplementedError("stub: replaces _util/redact.py")
