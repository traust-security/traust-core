from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Generic, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    DocumentError,
    IntegrityError,
    Issue,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import ArtifactDocument
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import ArtifactRef, TimeWindow
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
        if repository_ref_ids is None:
            return self._scan(kind)
        with self._uow as uow:
            return [
                a
                for i in range(0, len(repository_ref_ids), _BATCH)
                for a in uow.assessments.list_for_refs(repository_ref_ids[i : i + _BATCH], kind)
            ]

    def list_within(self, window: TimeWindow, kind: str | None = None) -> list[Assessment]:
        """The assessments of `kind` (any when None) that occurred in the window, newest first."""
        return self._scan(kind, window.start, window.end)

    def _scan(
        self, kind: str | None, since: datetime | None = None, until: datetime | None = None
    ) -> list[Assessment]:
        found: list[Assessment] = []
        after = None
        with self._uow as uow:
            while page := uow.assessments.search(
                kind=kind, since=since, until=until, limit=_BATCH, after=after
            ):
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

    def latest(self, artifact: type[A], as_of: datetime | None = None) -> A | None:
        """The newest imported document of this type (configuration documents), or the newest
        published by `as_of`."""
        latest = self.latest_imported(artifact, as_of)
        return None if latest is None else latest.document

    def latest_imported(
        self, artifact: type[A], as_of: datetime | None = None
    ) -> Imported[A] | None:
        """The newest imported document with its id, the `prior` for publish_successor."""
        with self._uow as uow:
            row = uow.artifacts.latest_imported(artifact.schema, as_of)
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
        """The stored bytes re-hashed against the digest recorded when they were published;
        bytes gone from the store read as `actual=None`, never as verified."""
        with self._uow as uow:
            row = uow.artifacts.get(artifact_id)
        try:
            actual: str | None = self._objects.stat(ObjectKey.parse(row.uri)).sha256
        except NotFoundError:
            actual = None
        return DigestCheck(artifact_id=artifact_id, uri=row.uri, recorded=row.digest, actual=actual)

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]:
        with self._uow as uow:
            return uow.artifacts.list_for_assessment(assessment_id, kind=kind)

    def documents(
        self, assessments: Iterable[Assessment], artifact: type[A]
    ) -> list[tuple[Assessment, A]]:
        """The `artifact` documents the assessments hold, newest assessment first."""
        return [
            (a, self._read(row, artifact))
            for a, row in AssessmentLog(self._uow).documents(assessments, [artifact.schema])
        ]


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


class DigestCheck(Dto):
    """An artifact's stored bytes against its recorded digest."""

    artifact_id: UUID
    uri: str
    recorded: str
    actual: str | None

    @property
    def verified(self) -> bool:
        return self.actual == self.recorded


class RedactionHit(Dto):
    """One secret found: its class and its first characters, never the secret itself."""

    category: str
    match_prefix: str

    @property
    def high_confidence(self) -> bool:
        return self.category in _HIGH_CONFIDENCE


class Redacted(Dto):
    payload: bytes
    hits: tuple[RedactionHit, ...] = ()


_KEEP = 5
_MARK = "...REDACTED"
# (category, pattern, only group 1 is the secret)
_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{12,}"), False),
    ("github-token", re.compile(r"gh[posru]_[a-zA-Z0-9]{30,}"), False),
    ("github-pat", re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"), False),
    ("gitlab-token", re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"), False),
    ("slack-token", re.compile(r"xox[bpsa]-[a-zA-Z0-9\-]{10,}"), False),
    ("llm-api-key", re.compile(r"sk-[a-zA-Z0-9]{20,}"), False),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), False),
    ("bearer-token", re.compile(r"Bearer\s+([a-zA-Z0-9._\-]{20,})"), True),
    ("jwt", re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"), False),
    *(
        (
            f"{name}-assignment",
            re.compile(rf"{key}\s*[:=]\s*\\?['\"]([^'\"\\]{{8,}})\\?['\"]", re.IGNORECASE),
            True,
        )
        for name, key in (
            ("password", "(?:password|passwd)"),
            ("secret", "secret"),
            ("token", "token"),
            ("apikey", "api[_-]?key"),
        )
    ),
    ("url-credentials", re.compile(r"://[A-Za-z0-9._%+-]+:([^@/\s'\"]{6,})@"), True),
    ("us-ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), False),
    ("azure-client-secret", re.compile(r"\b[a-zA-Z0-9~_.\-]{3}8Q~[a-zA-Z0-9~_.\-]{30,}\b"), False),
    ("gcp-sa-key", re.compile(r'"private_key_id"\s*:\s*"([a-f0-9]{40})"'), True),
)
# Vendor token formats are near-certainly real; the heuristic classes (assignments, SSN, card,
# URL credentials) turn up in quoted audit evidence (a 400-report dry run: 0 vs 14 hits).
_HIGH_CONFIDENCE = frozenset(
    {
        "aws-access-key",
        "github-token",
        "github-pat",
        "gitlab-token",
        "slack-token",
        "google-api-key",
        "jwt",
        "pem-private-key",
        "azure-client-secret",
        "gcp-sa-key",
    }
)
_PEM = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)", re.DOTALL
)
_PAN_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


class RedactionPolicy:
    """Write-time secret scrubbing for every published document: each secret keeps its first
    five characters, so evidence stays traceable without being usable."""

    def redact(self, payload: bytes) -> Redacted:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValidationError(f"redaction reads UTF-8 text: {e}") from None
        hits: list[RedactionHit] = []

        def found(category: str, value: str) -> str:
            hits.append(RedactionHit(category=category, match_prefix=value[:_KEEP]))
            return value[:_KEEP] + _MARK

        for category, rx, grouped in _PATTERNS:

            def sub(m: re.Match[str], category: str = category, grouped: bool = grouped) -> str:
                whole = m.group(0)
                if _MARK in whole:
                    return whole
                if grouped and m.lastindex:
                    return whole.replace(m.group(1), found(category, m.group(1)))
                return found(category, whole)

            text = rx.sub(sub, text)

        def pem(m: re.Match[str]) -> str:
            hits.append(RedactionHit(category="pem-private-key", match_prefix="-----"))
            return f"{m.group(1)}\n[PRIVATE KEY MATERIAL REDACTED]\n{m.group(3)}"

        text = _PEM.sub(pem, text)

        def pan(m: re.Match[str]) -> str:
            digits = re.sub(r"[ -]", "", m.group(0))
            ok = 13 <= len(digits) <= 19 and _luhn_ok(digits)
            return found("payment-card", digits) if ok else m.group(0)

        text = _PAN_CANDIDATE.sub(pan, text)
        return Redacted(payload=text.encode("utf-8"), hits=tuple(hits))
