"""The assessment and artifact doors (`AssessmentLog`, `stored_bytes`, `ArtifactPublisher.read`,
`publish_ref`, `find`, `history`) over the contract tables (SQLite + Postgres), on the caller's
open unit of work."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest

from tests.v1.example.artifact_publishing import example_specs
from tests.v1.fixtures import TRIAGE
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.errors import IntegrityError, NotFoundError
from traust_core.v1.models.artifacts import SecurityAuditArtifact, TriageArtifact
from traust_core.v1.models.assessment import Artifact, Assessment, AssessmentKind
from traust_core.v1.models.common import ArtifactRef
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    AssessmentLog,
    stored_bytes,
)

MISSING = uuid4()
AUDIT, SCAN = "security-audit", "scan"


@dataclass(frozen=True)
class World:
    main: RepositoryRef
    feature: RepositoryRef
    old: Assessment  # audit on main, day 1, holds AUDIT "d-old"
    new: Assessment  # audit on main, day 3, holds AUDIT "d-new" and SCAN "d-scan"
    bare: Assessment  # audit on main, day 2, holds nothing
    triage: Assessment  # triage on feature, measured against `old`, holds "triage" "d-tri"
    other: Assessment  # triage on feature, against `new`, holds "triage" "d-tri"
    rows: dict[str, Artifact]


@pytest.fixture
def world(seed: Seed) -> World:
    main = seed.repository_ref(name="main")
    feature = seed.repository_ref(repository=None, name="feature")

    def at(ref: RepositoryRef, kind: str, days: int, **kw: Any) -> Assessment:
        return seed.assessment(ref=ref, kind=kind, occurred_at=T0 + timedelta(days=days), **kw)

    old, new, bare = at(main, "audit", 1), at(main, "audit", 3), at(main, "audit", 2)
    triage = at(feature, "triage", 4, baseline_assessment_id=old.id)
    other = at(feature, "triage", 5, baseline_assessment_id=new.id)
    rows = {
        "old": seed.artifact(old, kind=AUDIT, digest="d-old"),
        "new": seed.artifact(new, kind=AUDIT, digest="d-new"),
        "scan": seed.artifact(new, kind=SCAN, digest="d-scan"),
        "triage": seed.artifact(triage, kind="triage", digest="d-tri"),
        "other": seed.artifact(other, kind="triage", digest="d-tri"),
    }
    return World(main, feature, old, new, bare, triage, other, rows)


Call = Callable[[AssessmentLog, World], Any]

FOUND: list[tuple[str, Call, Callable[[World], Any]]] = [
    ("get", lambda log, w: log.get(w.new.id), lambda w: w.new),
    ("get_artifact", lambda log, w: log.get_artifact(w.rows["scan"].id), lambda w: w.rows["scan"]),
    (
        "list_by_ids",
        lambda log, w: {a.id for a in log.list_by_ids({w.old.id, w.triage.id})},
        lambda w: {w.old.id, w.triage.id},
    ),
    ("list_by_ids of none", lambda log, w: log.list_by_ids(set()), lambda w: []),
    (
        "list_of one kind on refs, oldest first",
        lambda log, w: log.list_of("audit", [w.main.id, w.feature.id]),
        lambda w: [w.old, w.bare, w.new],
    ),
    (
        "list_of any kind on a ref",
        lambda log, w: log.list_of(None, [w.feature.id]),
        lambda w: [w.triage, w.other],
    ),
    (
        "list_of one kind on every ref, newest first",
        lambda log, w: log.list_of("triage"),
        lambda w: [w.other, w.triage],
    ),
    ("list_of no refs", lambda log, w: log.list_of("audit", []), lambda w: []),
    (
        "documents newest assessment first, empty assessments skipped",
        lambda log, w: [
            (a.id, r.digest in {"d-new", "d-scan"})
            for a, r in log.documents([w.old, w.bare, w.new], [AUDIT, SCAN])
        ],
        lambda w: [(w.new.id, True), (w.new.id, True), (w.old.id, False)],
    ),
    (
        "documents of one kind",
        lambda log, w: [r.digest for _, r in log.documents([w.old, w.new], [AUDIT])],
        lambda w: ["d-new", "d-old"],
    ),
    ("documents of no assessments", lambda log, w: log.documents([], [AUDIT]), lambda w: []),
    (
        "find_recorded by kind, document and digest",
        lambda log, w: log.find_recorded([w.main.id], "audit", AUDIT, "d-new"),
        lambda w: [(w.new, w.rows["new"])],
    ),
    (
        "find_recorded in ref order",
        lambda log, w: [
            a for a, _ in log.find_recorded([w.feature.id], "triage", "triage", "d-tri")
        ],
        lambda w: [w.triage, w.other],
    ),
    (
        "find_recorded against a baseline",
        lambda log, w: log.find_recorded(
            [w.feature.id], "triage", "triage", "d-tri", baseline_id=w.new.id
        ),
        lambda w: [(w.other, w.rows["other"])],
    ),
    (
        "find_recorded another document kind",
        lambda log, w: log.find_recorded([w.main.id], "audit", SCAN, "d-new"),
        lambda w: [],
    ),
    (
        "find_recorded another assessment kind",
        lambda log, w: log.find_recorded([w.main.id], "triage", AUDIT, "d-new"),
        lambda w: [],
    ),
    (
        "find_recorded unknown bytes",
        lambda log, w: log.find_recorded([w.main.id, w.feature.id], "audit", AUDIT, "d-none"),
        lambda w: [],
    ),
]


@pytest.mark.parametrize(("case", "call", "expected"), FOUND, ids=[c[0] for c in FOUND])
def test_assessment_log_reads(uow: SqlTraustUnitOfWork, world: World, case, call, expected) -> None:
    assert call(AssessmentLog(uow), world) == expected(world)


@pytest.mark.parametrize(
    ("case", "call"),
    [
        ("get", lambda log: log.get(MISSING)),
        ("get_artifact", lambda log: log.get_artifact(MISSING)),
    ],
    ids=["get", "get_artifact"],
)
def test_assessment_log_refuses_an_unknown_id(uow: SqlTraustUnitOfWork, case, call) -> None:
    with pytest.raises(NotFoundError):
        call(AssessmentLog(uow))


def publisher(uow: SqlTraustUnitOfWork) -> tuple[ArtifactPublisher, InMemoryObjectStore]:
    store = InMemoryObjectStore()
    return ArtifactPublisher(example_specs(), store, uow), store


def triage(title: str = "SQL injection in handler") -> TriageArtifact:
    doc = json.loads(TRIAGE)
    doc["findings"] = [
        {
            "id": "f001",
            "title": title,
            "verdict": "true_positive",
            "severity": "high",
            "file": "pkg/api/handler.go",
            "line": 42,
        }
    ]
    return TriageArtifact.from_document(doc)


@pytest.mark.parametrize("digest", ["published", "other"], ids=["matching", "mismatched"])
def test_attach_records_the_published_row_only_for_its_own_bytes(
    uow: SqlTraustUnitOfWork, seed: Seed, digest: str
) -> None:
    doc, log = triage(), AssessmentLog(uow)
    published = publisher(uow)[0].publish_artifact(doc)
    row = log.get_artifact(published.artifact_id)
    assessment = seed.assessment()
    claim = sha256_hex(doc.payload) if digest == "published" else "f" * 64
    if digest == "other":
        with pytest.raises(IntegrityError, match="doc digest"):
            log.attach(assessment.id, published.artifact_id, claim)  # type: ignore[arg-type]
        return
    attached = log.attach(assessment.id, published.artifact_id, claim)  # type: ignore[arg-type]
    assert (attached.assessment_id, attached.digest, attached.kind, attached.uri) == (
        assessment.id,
        row.digest,
        row.kind,
        row.uri,
    )
    assert log.attach(assessment.id, published.artifact_id, claim) == attached  # type: ignore[arg-type]


def test_add_records_a_new_assessment_holding_the_artifact(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    doc, log = triage(), AssessmentLog(uow)
    published = publisher(uow)[0].publish_artifact(doc)
    new = seed.new_assessment(kind=AssessmentKind.TRIAGE)
    assessment, artifact = log.add(new, published.artifact_id, sha256_hex(doc.payload))
    assert assessment.id is not None and artifact.assessment_id == assessment.id
    assert log.find_recorded(
        [new.repository_ref_id], "triage", TriageArtifact.schema, sha256_hex(doc.payload)
    ) == [(assessment, artifact)]


def test_publisher_reads_a_document_as_its_type_and_refuses_another(
    uow: SqlTraustUnitOfWork,
) -> None:
    service, _ = publisher(uow)
    doc = triage()
    ref = service.publish_ref(doc)
    assert ref == ArtifactRef(id=ref.id, name=doc.name, digest=sha256_hex(doc.payload))
    assert service.read(ref.id, TriageArtifact).payload == doc.payload
    with pytest.raises(IntegrityError, match=f"is not a {SecurityAuditArtifact.schema} document"):
        service.read(ref.id, SecurityAuditArtifact)


def test_publisher_finds_published_bytes_and_lists_the_history_newest_first(
    uow: SqlTraustUnitOfWork,
) -> None:
    service, _ = publisher(uow)
    first = service.publish_ref(triage("first"))
    apart()
    second = service.publish_ref(triage("second"))
    found = service.find(first.digest)
    assert found is not None and found.id == first.id
    assert service.find("0" * 64) is None
    assert [r.id for r in service.history(TriageArtifact, 10)] == [second.id, first.id]
    assert [r.id for r in service.history(TriageArtifact, 1)] == [second.id]


def test_stored_bytes_are_checked_against_the_recorded_digest(uow: SqlTraustUnitOfWork) -> None:
    service, store = publisher(uow)
    doc = triage()
    row = AssessmentLog(uow).get_artifact(service.publish_ref(doc).id)
    assert stored_bytes(store, row) == doc.payload
    with pytest.raises(IntegrityError):
        stored_bytes(store, row.model_copy(update={"digest": "0" * 64}))


def test_log_documents_without_a_kind_filter_include_every_companion(
    uow: SqlTraustUnitOfWork, world: World
) -> None:
    held = AssessmentLog(uow).documents([world.old, world.new, world.bare], None)
    assert {(assessment.id, artifact.id) for assessment, artifact in held} == {
        (world.old.id, world.rows["old"].id),
        (world.new.id, world.rows["new"].id),
        (world.new.id, world.rows["scan"].id),
    }
    assert AssessmentLog(uow).documents([world.old, world.new], ()) == []
