from __future__ import annotations

import logging
import re
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from time import perf_counter
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
from traust_core.v1.models.artifacts import ARTIFACT_FOR_SCHEMA, ArtifactDocument
from traust_core.v1.models.assessment import Artifact, Assessment
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import ArtifactRef, RecordBudget, TimeWindow
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.redaction import (
    PAYMENT_CARD_PATTERN,
    PEM_PATTERN,
    SecretDetector,
    luhn_ok,
)
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef, ObjectStore
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork

A = TypeVar("A", bound=ArtifactDocument)
_BATCH = 500  # ids per IN list
log = logging.getLogger(__name__)


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


def record_artifact(uow: AssessmentsUnitOfWork, artifact: Artifact) -> Artifact:
    """One writer for artifact metadata; the aggregate's caller commits."""
    if artifact.assessment_id is None:
        return _record_imported_with_status(uow, artifact)[0]
    known = uow.artifacts.get_or_add(artifact)
    if known.kind != artifact.kind:
        raise IntegrityError(f"artifact {known.id}: digest already recorded as {known.kind}")
    return known


def _record_artifact_with_status(
    uow: AssessmentsUnitOfWork, artifact: Artifact
) -> tuple[Artifact, bool]:
    known, created = uow.artifacts.get_or_add_with_status(artifact)
    if known.kind != artifact.kind:
        raise IntegrityError(f"artifact {known.id}: digest already recorded as {known.kind}")
    return known, created


def _record_imported_with_status(
    uow: AssessmentsUnitOfWork, artifact: Artifact, successor: _Successor | None = None
) -> tuple[Artifact, bool]:
    """Serialize a kind's prior check and time-gated insert; the caller commits."""
    with uow.write():
        uow.artifacts.lock_imported(artifact.kind)
        latest = uow.artifacts.latest_imported(artifact.kind)
        if successor is not None:
            successor.require_latest(artifact.kind, latest)
        row, created = _record_artifact_with_status(uow, artifact)
        if successor is not None:
            successor.require_newest(artifact.kind, row, latest, created)
        return row, created


def stored_bytes(objects: ObjectStore, row: Artifact) -> bytes:
    """An artifact row's bytes, checked against the digest it was recorded with."""
    ref = objects.stat(ObjectKey.parse(row.uri))
    return objects.get(replace(ref, sha256=row.digest))


class AssessmentLog:
    """Assessments and their recorded documents on the caller's uow (needs only the uow)."""

    def __init__(self, uow: AssessmentsUnitOfWork) -> None:
        self._uow = uow

    def after_commit(self, event: Callable[[], None]) -> None:
        self._uow.after_commit(event)

    def get(self, assessment_id: UUID) -> Assessment:
        with self._uow as uow:
            return uow.assessments.get(assessment_id)

    def lock(self, assessment_id: UUID) -> Assessment:
        """Lock an original assessment inside the caller's write transaction."""
        with self._uow as uow:
            return uow.assessments.get_for_update(assessment_id)

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

    def list_by_ids(
        self, assessment_ids: Collection[UUID], *, read_budget: RecordBudget | None = None
    ) -> list[Assessment]:
        with self._uow as uow:
            return uow.assessments.list_by_ids(assessment_ids, read_budget=read_budget)

    def list_at(self, timestamps: Mapping[UUID, datetime]) -> list[Assessment]:
        items = tuple(timestamps.items())
        with self._uow as uow:
            return [
                row
                for start in range(0, len(items), _BATCH)
                for row in uow.assessments.list_at(dict(items[start : start + _BATCH]))
            ]

    def list_of(
        self,
        kind: str | None,
        repository_ref_ids: Sequence[UUID] | None = None,
        *,
        assessor_version: str | None = None,
        read_budget: RecordBudget | None = None,
    ) -> list[Assessment]:
        """The assessments of `kind` (any when None) on the refs, or on every ref when None."""
        if repository_ref_ids is None:
            return self._scan(kind, assessor_version=assessor_version, read_budget=read_budget)
        with self._uow as uow:
            return [
                a
                for i in range(0, len(repository_ref_ids), _BATCH)
                for a in uow.assessments.list_for_refs(
                    repository_ref_ids[i : i + _BATCH],
                    kind,
                    assessor_version=assessor_version,
                    read_budget=read_budget,
                )
            ]

    def list_within(
        self,
        window: TimeWindow,
        kind: str | None = None,
        *,
        read_budget: RecordBudget | None = None,
    ) -> list[Assessment]:
        """The assessments of `kind` (any when None) that occurred in the window, newest first."""
        return self._scan(kind, window.start, window.end, read_budget=read_budget)

    def _scan(
        self,
        kind: str | None,
        since: datetime | None = None,
        until: datetime | None = None,
        *,
        assessor_version: str | None = None,
        read_budget: RecordBudget | None = None,
    ) -> list[Assessment]:
        found: list[Assessment] = []
        after = None
        with self._uow as uow:
            while page := uow.assessments.search(
                kind=kind,
                assessor_version=assessor_version,
                since=since,
                until=until,
                limit=min(_BATCH, read_budget.remaining + 1) if read_budget else _BATCH,
                after=after,
            ):
                if read_budget is not None:
                    read_budget.consume(len(page))
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

    def attach(
        self,
        assessment_id: UUID,
        artifact_id: UUID,
        digest: str,
        run_order_id: UUID | None = None,
    ) -> Artifact:
        """Record the published artifact on the assessment, by the order whose run recorded it;
        IntegrityError unless it is `digest`."""
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
                    run_order_id=run_order_id,
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


@dataclass(frozen=True, slots=True)
class StagedArtifact(Generic[A]):
    artifact: A
    objects: tuple[ObjectRef, ...]
    started: float
    _publisher: ArtifactPublisher = field(repr=False)


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
        self._redaction = RedactionPolicy()

    def publish(self, name: str, raw: bytes) -> PublishResult:
        spec = self._specs.get(name)
        artifact = spec.artifact.parse(spec.input.to_json(name, raw))
        return self.publish_artifact(artifact)

    def publish_artifact(self, artifact: ArtifactDocument) -> PublishResult:
        return self.publish_artifact_with_status(artifact)[0]

    def publish_artifact_with_status(
        self, artifact: ArtifactDocument
    ) -> tuple[PublishResult, bool]:
        """Publish and report whether this call inserted a new artifact row."""
        return self._publish(artifact, None)

    def publish_ref(self, artifact: ArtifactDocument) -> ArtifactRef:
        """Publish the document and return the reference provenance carries."""
        published = self.publish_artifact(artifact)
        return ArtifactRef(
            id=published.artifact_id, name=artifact.name, digest=sha256_hex(artifact.payload)
        )

    def publish_successor(self, artifact: ArtifactDocument, prior: UUID | None) -> PublishResult:
        """Append after exactly `prior`; stale priors conflict and old-digest reverts refuse.
        Retrying the current digest with the current prior returns its original row."""
        return self._publish(artifact, _Successor(prior))[0]

    def _publish(
        self, artifact: ArtifactDocument, successor: _Successor | None
    ) -> tuple[PublishResult, bool]:
        return self._publish_staged(self.stage(artifact), successor)

    def stage(self, artifact: A) -> StagedArtifact[A]:
        """Validate and upload bytes without opening a metadata transaction."""
        started = perf_counter()
        spec = self._specs.get(artifact.name)
        artifact = spec.artifact.parse(artifact.payload)
        self._check_secrets(spec.name, "$", artifact.text_fragments())
        companions = [(c.kind, c.render(artifact)) for c in spec.companions]
        for kind, data in companions:
            path = f"companions/{kind.value}"
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                raise DocumentError(
                    spec.name, [Issue(path, "companion must be UTF-8 text")]
                ) from None
            self._check_secrets(spec.name, path, (text,))
        prefix = f"artifacts/{artifact.schema}"
        written = [
            self._objects.put(
                ObjectKey.parse(f"{prefix}/{sha256_hex(artifact.payload)}.json"), artifact.payload
            )
        ]
        for kind, data in companions:
            written.append(
                self._objects.put(
                    ObjectKey.parse(f"{prefix}/{sha256_hex(data)}-{kind.value}"), data
                )
            )
        return StagedArtifact(artifact, tuple(written), started, self)

    def publish_staged(self, staged: StagedArtifact[A]) -> PublishResult:
        """Publish staged metadata; the caller may attach it in the same transaction."""
        return self._publish_staged(staged, None)[0]

    def _publish_staged(
        self, staged: StagedArtifact[A], successor: _Successor | None
    ) -> tuple[PublishResult, bool]:
        if staged._publisher is not self:
            raise ValidationError("staged artifact belongs to a different publisher")
        artifact = staged.artifact
        primary = staged.objects[0]
        with self._uow as uow:
            row, created = _record_imported_with_status(
                uow,
                Artifact(digest=primary.sha256, kind=artifact.schema, uri=str(primary.key)),
                successor,
            )
            uow.commit()
        assert row.id is not None
        if created:
            event = (
                row.id,
                artifact.schema,
                primary.sha256,
                len(staged.objects) - 1,
                (perf_counter() - staged.started) * 1000,
            )
            self._uow.after_commit(
                lambda: log.info(
                    "artifact published id=%s kind=%s digest=%s companions=%d duration_ms=%.1f",
                    *event,
                )
            )
        return (
            PublishResult(
                artifact=artifact.name,
                written=tuple(str(ref.key) for ref in staged.objects),
                artifact_id=row.id,
            ),
            created,
        )

    def _check_secrets(self, name: str, path: str, texts: Iterable[str]) -> None:
        categories = sorted(
            {h.category for text in texts for h in self._redaction.scan(text) if h.high_confidence}
        )
        if categories:
            raise DocumentError(
                name,
                [Issue(path, f"unredacted high-confidence secret ({c})") for c in categories],
            )

    def metadata(self, artifact_id: UUID) -> Artifact:
        return AssessmentLog(self._uow).get_artifact(artifact_id)

    def get(self, artifact_id: UUID) -> ArtifactDocument:
        row = self.metadata(artifact_id)
        try:
            artifact = ARTIFACT_FOR_SCHEMA[row.kind]
        except KeyError:
            raise ConfigError(f"unknown artifact schema {row.kind!r}") from None
        return self._read(row, artifact)

    def payload(self, artifact_id: UUID) -> bytes:
        """The recorded bytes, including companions without an artifact schema."""
        return stored_bytes(self._objects, self.metadata(artifact_id))

    def read(
        self, artifact_id: UUID, artifact: type[A], *, read_budget: RecordBudget | None = None
    ) -> A:
        """The stored document as `artifact`; IntegrityError if it is another kind."""
        if read_budget is not None:
            read_budget.consume(1)
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

    def latest_for_assessment(self, assessment_id: UUID, artifact: type[A]) -> A | None:
        """The assessment's newest stored document of this type; None when it holds none."""
        with self._uow as uow:
            row = uow.artifacts.latest_for_assessment(assessment_id, artifact.schema)
        return None if row is None else self._read(row, artifact)

    def list_for_assessment(
        self,
        assessment_id: UUID,
        *,
        kind: str | None = None,
        read_budget: RecordBudget | None = None,
    ) -> list[Artifact]:
        with self._uow as uow:
            return uow.artifacts.list_for_assessment(
                assessment_id, kind=kind, read_budget=read_budget
            )

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

    def require_latest(self, kind: str, latest: Artifact | None) -> None:
        if (None if latest is None else latest.id) != self.prior:
            raise ConflictError(f"{kind}: another writer published since {self.prior}")

    def require_newest(
        self, kind: str, row: Artifact, latest: Artifact | None, created: bool
    ) -> None:
        if not created and (latest is None or latest.id != row.id):
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
_PEM = PEM_PATTERN
_PEM_REDACTED = "[PRIVATE KEY MATERIAL REDACTED]"
# The run of newlines (raw or JSON-escaped to any depth) padding a PEM body.
_PEM_PAD = re.compile(r"(?:\\+[rn]|\r?\n)+")
_PEM_PAD_END = re.compile(r"(?:\\+[rn]|\r?\n)+$")
_PAN_CANDIDATE = PAYMENT_CARD_PATTERN


class RedactionPolicy:
    """Write-time secret scrubbing for every published document: each secret keeps its first
    five characters, so evidence stays traceable without being usable."""

    def redact(self, payload: bytes) -> Redacted:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValidationError(f"redaction reads UTF-8 text: {e}") from None
        hits: list[RedactionHit] = []
        return Redacted(payload=_scrub(text, hits, replace=True).encode("utf-8"), hits=tuple(hits))

    def scan(self, text: str) -> tuple[RedactionHit, ...]:
        """The secrets in `text`, found without redacting: every pattern reads the original."""
        hits: list[RedactionHit] = []
        _scrub(text, hits, replace=False)
        return tuple(hits)


def _scrub(text: str, hits: list[RedactionHit], *, replace: bool) -> str:
    def found(category: str, value: str) -> str:
        hits.append(RedactionHit(category=category, match_prefix=value[:_KEEP]))
        return value[:_KEEP] + _MARK

    for rule in SecretDetector.publication_rules():
        category, rx, grouped = rule.category, rule.pattern, bool(rule.group)

        def sub(m: re.Match[str], category: str = category, grouped: bool = grouped) -> str:
            whole = m.group(0)
            if _MARK in whole:
                return whole
            if grouped and m.lastindex:
                masked = whole.replace(m.group(1), found(category, m.group(1)))
            else:
                masked = found(category, whole)
            return masked if replace else whole

        text = rx.sub(sub, text)

    def pem(m: re.Match[str]) -> str:
        if re.sub(r"\\+[rn]", "\n", m.group(2)).strip() == _PEM_REDACTED:
            return m.group(0)
        hits.append(RedactionHit(category="pem-private-key", match_prefix="-----"))
        if not replace:
            return m.group(0)
        body = m.group(2)
        lead = _PEM_PAD.match(body)
        tail = _PEM_PAD_END.search(body)
        if tail is not None and lead is not None and tail.start() < lead.end():
            tail = None  # an all-padding body: the run is already spent on the lead
        pad = (lead.group(0) if lead else "") + _PEM_REDACTED + (tail.group(0) if tail else "")
        return f"{m.group(1)}{pad}{m.group(3)}"

    text = _PEM.sub(pem, text)

    def pan(m: re.Match[str]) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19 and luhn_ok(digits)):
            return m.group(0)
        masked = found("payment-card", digits)
        return masked if replace else m.group(0)

    return _PAN_CANDIDATE.sub(pan, text)
