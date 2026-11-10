import json
import logging
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from threading import Event, current_thread
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.example.artifact_publishing import example_specs as default_specs
from tests.v1.fixtures import TRIAGE
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    DocumentError,
    IntegrityError,
    NotFoundError,
    RepositoryError,
)
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    FindingsCurrentArtifact,
    ReportArtifact,
    SecurityAuditArtifact,
    TriageArtifact,
)
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.repositories.traust.assessments import SqlArtifactRepository
from traust_core.v1.repositories.traust.assessments import artifact as artifact_repository
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishResult,
    PublishSpec,
    PublishSpecs,
)

engine = table_fixtures.engine
FINDING = {
    "id": "f001",
    "title": "SQL injection in handler",
    "verdict": "true_positive",
    "severity": "high",
    "file": "pkg/api/handler.go",
    "line": 42,
}


def triage_with(*findings: dict) -> bytes:
    doc = json.loads(TRIAGE)
    doc["findings"] = list(findings)
    return json.dumps(doc).encode()


@dataclass
class Publishing:
    service: ArtifactPublisher
    store: InMemoryObjectStore
    uow: SqlTraustUnitOfWork


@pytest.fixture
def setup(engine: sa.Engine) -> Publishing:
    unit, store = SqlTraustUnitOfWork(engine), InMemoryObjectStore()
    return Publishing(ArtifactPublisher(default_specs(), store, unit), store, unit)


@pytest.fixture
def publication_defaults(
    setup: Publishing, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[UUID, datetime], None]]:
    with setup.uow as unit:
        if unit.connection.dialect.name == "sqlite":
            values = ["", ""]
            driver = unit.connection.connection.driver_connection
            driver.create_function("uuid", 0, lambda: values[0])
            driver.create_function("strftime", -1, lambda *_: values[1])

            def set_defaults(artifact_id: UUID, at: datetime) -> None:
                values[:] = [
                    str(artifact_id),
                    at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                ]

        else:
            now = sa.text("current_setting('traust.test_publication_time')::timestamptz")
            monkeypatch.setattr(unit.artifacts.table.c.created_at.server_default, "arg", now)
            unit.connection.exec_driver_sql(
                "ALTER TABLE traust.artifact "
                "ALTER COLUMN id SET DEFAULT current_setting('traust.test_publication_id')::uuid, "
                "ALTER COLUMN created_at SET DEFAULT "
                "current_setting('traust.test_publication_time')::timestamptz"
            )

            def set_defaults(artifact_id: UUID, at: datetime) -> None:
                unit.connection.execute(
                    sa.text(
                        "SELECT set_config('traust.test_publication_id', :id, true), "
                        "set_config('traust.test_publication_time', :at, true)"
                    ),
                    {"id": str(artifact_id), "at": at.isoformat()},
                )

        yield set_defaults


def test_submit_writes_json_then_rendered_markdown(setup: Publishing) -> None:
    raw = triage_with(FINDING)
    result = setup.service.publish("triage", raw)
    assert result.written[0] == f"artifacts/triage/{sha256_hex(raw)}.json"
    assert result.written[1].endswith("-triage.md")
    assert len(result.written) == 2
    assert result.artifact_id is not None


def test_publish_artifact_reports_insert_status_without_changing_public_result(
    setup: Publishing,
) -> None:
    doc = TriageArtifact.parse(triage_with(FINDING))
    first, created = setup.service.publish_artifact_with_status(doc)
    repeated, inserted = setup.service.publish_artifact_with_status(doc)
    assert created and not inserted
    assert first == repeated == setup.service.publish_artifact(doc)


def test_markdown_is_rendered_from_the_validated_document(setup: Publishing) -> None:
    result = setup.service.publish("triage", triage_with(FINDING))
    md = setup.store.get(setup.store.stat(ObjectKey.parse(result.written[1]))).decode()
    assert "# Triage: example.invalid/synthetic/repository" in md
    assert (
        "| f001 | SQL injection in handler | true_positive | high | pkg/api/handler.go:42 |" in md
    )


def test_published_row_points_at_content_addressed_json(setup: Publishing) -> None:
    result = setup.service.publish("triage", triage_with(FINDING))
    with setup.uow as unit:
        row = unit.artifacts.get(result.artifact_id)
    assert row.uri == result.written[0]
    assert row.kind == "triage" and row.assessment_id is None


def test_invalid_input_writes_nothing_and_returns_every_issue(setup: Publishing) -> None:
    bad = triage_with({"id": "x1", "title": "no", "verdict": "maybe"})
    with pytest.raises(DocumentError) as err:
        setup.service.publish("triage", bad)
    assert {"findings/0/id", "findings/0/title", "findings/0/verdict"} <= {
        i.path for i in err.value.issues
    }
    assert list(setup.store.list()) == []


def test_non_json_input_is_a_single_issue(setup: Publishing) -> None:
    with pytest.raises(DocumentError) as err:
        setup.service.publish("triage", b"not json")
    assert err.value.issues[0].path == "$"


def test_unknown_artifact_lists_the_known_ones(setup: Publishing) -> None:
    with pytest.raises(ConfigError, match="known: triage"):
        setup.service.publish("nope", b"{}")


def test_save_a_typed_artifact_from_code(setup: Publishing) -> None:
    triage = TriageArtifact.from_document(json.loads(triage_with(FINDING)))
    result = setup.service.publish_artifact(triage)
    assert setup.service.get(result.artifact_id).payload == triage.payload


def test_reader_returns_the_named_artifact(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    publisher = ctx.artifact_publisher(default_specs())
    result = publisher.publish("triage", triage_with(FINDING))
    triage = publisher.get(result.artifact_id)
    assert isinstance(triage, TriageArtifact)
    assert triage.findings[0].title == "SQL injection in handler"


def test_context_artifact_reads_preserve_kind_and_stored_digest_checks(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    published = ctx.artifact_publisher(default_specs()).publish("triage", triage_with(FINDING))
    reader = ctx.services().artifacts
    assert reader.read(published.artifact_id, TriageArtifact).findings[0].title == FINDING["title"]
    with pytest.raises(IntegrityError):
        reader.read(published.artifact_id, ReportArtifact)
    ctx.object_store.put(ObjectKey.parse(published.written[0]), triage_with())
    with pytest.raises(IntegrityError):
        reader.get(published.artifact_id)


def test_context_artifact_reads_do_not_enable_domain_publication(tmp_path: Path) -> None:
    reader = Context(Config(home=tmp_path)).services().artifacts
    document = TriageArtifact.parse(triage_with(FINDING))
    with pytest.raises(ConfigError):
        reader.publish(document.name, document.payload)
    with pytest.raises(ConfigError):
        reader.publish_artifact(document)
    with pytest.raises(ConfigError):
        reader.publish_successor(document, None)


def test_record_failure_raises_without_claiming_success(
    setup: Publishing, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(*_: object) -> None:
        raise RepositoryError("database down")

    monkeypatch.setattr(SqlArtifactRepository, "get_or_add_with_status", broken)
    raw = triage_with()
    with (
        caplog.at_level(logging.INFO, logger="traust_core.v1.services.artifact_publishing"),
        pytest.raises(RepositoryError, match="database down"),
    ):
        setup.service.publish("triage", raw)
    assert "artifact published" not in caplog.text
    assert len(list(setup.store.list())) == 2
    with setup.uow as unit:
        assert unit.artifacts.find(None, sha256_hex(raw)) is None


def test_resubmitting_is_idempotent(setup: Publishing) -> None:
    first = setup.service.publish("triage", triage_with(FINDING))
    again = setup.service.publish("triage", triage_with(FINDING))
    assert again == first


def test_publish_event_is_committed_once_without_document_content(
    setup: Publishing, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.artifact_publishing"):
        first = setup.service.publish("triage", triage_with(FINDING))
        again = setup.service.publish("triage", triage_with(FINDING))
    events = [
        r.getMessage()
        for r in caplog.records
        if r.name == "traust_core.v1.services.artifact_publishing"
    ]
    assert again == first
    assert len(events) == 1
    assert str(first.artifact_id) in events[0] and "duration_ms=" in events[0]
    assert FINDING["title"] not in caplog.text


def test_context_always_records_an_artifact_id(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    result = ctx.artifact_publisher(default_specs()).publish("triage", TRIAGE)
    with ctx.unit_of_work(SqlTraustUnitOfWork) as unit:
        assert unit.artifacts.get(result.artifact_id).kind == "triage"


def test_tampered_bytes_are_checked_against_the_persisted_digest(setup: Publishing) -> None:
    result = setup.service.publish("triage", triage_with(FINDING))
    setup.store.put(ObjectKey.parse(result.written[0]), triage_with())
    with pytest.raises(IntegrityError):
        setup.service.get(result.artifact_id)


def test_a_later_publish_does_not_overwrite_earlier_evidence(setup: Publishing) -> None:
    first = setup.service.publish("triage", triage_with(FINDING))
    later = setup.service.publish("triage", triage_with())
    assert first.artifact_id != later.artifact_id
    assert setup.service.get(first.artifact_id).findings[0].title == FINDING["title"]
    assert setup.service.get(later.artifact_id).findings == ()


def test_plain_and_successor_publications_share_a_durable_ordered_stream(setup: Publishing) -> None:
    original = TriageArtifact.parse(triage_with())
    changed = TriageArtifact.parse(triage_with(FINDING))
    first = setup.service.publish_artifact(original)
    second = setup.service.publish_successor(changed, first.artifact_id)
    assert setup.service.publish_successor(changed, second.artifact_id) == second
    assert setup.service.publish_artifact(original) == first
    with pytest.raises(IntegrityError, match="not the newest version"):
        setup.service.publish_successor(original, second.artifact_id)
    history = setup.service.history(TriageArtifact, limit=10)
    assert [row.id for row in history] == [second.artifact_id, first.artifact_id]
    assert len({row.created_at for row in history}) == len(history)
    assert setup.service.latest(TriageArtifact).payload == changed.payload
    assert setup.service.get(first.artifact_id).payload == original.payload
    third = setup.service.publish_artifact(
        TriageArtifact.parse(triage_with(FINDING | {"title": "Third recorded finding"}))
    )
    assert setup.service.history(TriageArtifact, limit=1)[0].id == third.artifact_id


def test_rapid_publications_keep_true_order_with_adversarial_uuid_and_time_ties(
    setup: Publishing,
    publication_defaults: Callable[[UUID, datetime], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    at = datetime(2026, 10, 5, tzinfo=UTC)
    ids = [
        UUID("ffffffff-ffff-4fff-bfff-ffffffffffff"),
        UUID("00000000-0000-4000-8000-000000000002"),
        UUID("00000000-0000-4000-8000-000000000001"),
    ]
    docs = [
        TriageArtifact.parse(triage_with()),
        TriageArtifact.parse(triage_with(FINDING)),
        TriageArtifact.parse(triage_with(FINDING | {"title": "Third recorded finding"})),
    ]
    publication_defaults(ids[0], at)
    first = setup.service.publish_artifact(docs[0])
    original = setup.service.metadata(first.artifact_id)
    sleeps: list[float] = []

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        publication_defaults(ids[len(sleeps)], at + timedelta(milliseconds=len(sleeps)))

    monkeypatch.setattr(artifact_repository, "sleep", advance)
    publication_defaults(ids[1], at)
    second = setup.service.publish_successor(docs[1], first.artifact_id)
    second_row = setup.service.metadata(second.artifact_id)
    publication_defaults(ids[2], second_row.created_at)
    third = setup.service.publish_artifact(docs[2])
    assert [first.artifact_id, second.artifact_id, third.artifact_id] == ids
    history = setup.service.history(TriageArtifact, limit=10)
    assert [row.id for row in history] == list(reversed(ids))
    assert history[2] == original and history[1] == second_row
    assert original.created_at < second_row.created_at < history[0].created_at
    assert setup.service.latest_imported(TriageArtifact).artifact_id == third.artifact_id
    assert setup.service.latest(TriageArtifact, at).payload == docs[0].payload
    assert setup.service.latest(TriageArtifact, second_row.created_at).payload == docs[1].payload
    assert setup.service.publish_artifact(docs[0]) == first
    assert setup.service.publish_successor(docs[2], third.artifact_id) == third
    with pytest.raises(ConflictError, match="another writer published"):
        setup.service.publish_successor(docs[2], second.artifact_id)
    with pytest.raises(IntegrityError, match="not the newest version"):
        setup.service.publish_successor(docs[0], third.artifact_id)


@pytest.mark.parametrize("clock_offset", [timedelta(0), -timedelta(seconds=1)])
def test_frozen_or_backward_database_time_refuses_publication_without_changing_history(
    setup: Publishing,
    publication_defaults: Callable[[UUID, datetime], None],
    monkeypatch: pytest.MonkeyPatch,
    clock_offset: timedelta,
) -> None:
    at = datetime(2026, 10, 5, tzinfo=UTC)
    publication_defaults(UUID("ffffffff-ffff-4fff-bfff-ffffffffffff"), at)
    original = TriageArtifact.parse(triage_with())
    first = setup.service.publish_artifact(original)
    before = setup.service.metadata(first.artifact_id)
    publication_defaults(UUID("00000000-0000-4000-8000-000000000001"), at + clock_offset)
    monkeypatch.setattr(artifact_repository, "sleep", lambda _: None)
    changed = TriageArtifact.parse(triage_with(FINDING))
    with pytest.raises(
        RepositoryError, match=r"imported artifact triage .*database time did not advance"
    ):
        setup.service.publish_successor(changed, first.artifact_id)
    assert setup.service.history(TriageArtifact, limit=10) == [before]
    assert setup.service.latest_imported(TriageArtifact).artifact_id == first.artifact_id
    assert setup.service.find(sha256_hex(changed.payload)) is None
    assert setup.service.publish_successor(original, first.artifact_id) == first
    with pytest.raises(RepositoryError, match="rollback-only"):
        setup.uow.commit()


def test_rapid_committed_publications_follow_publication_order(setup: Publishing) -> None:
    published: list[PublishResult] = []
    snapshots: list[Artifact] = []
    for index in range(20):
        doc = TriageArtifact.parse(triage_with(FINDING | {"title": f"Recorded finding {index}"}))
        prior = None if not published else published[-1].artifact_id
        result = (
            setup.service.publish_artifact(doc)
            if index % 2 == 0
            else setup.service.publish_successor(doc, prior)
        )
        published.append(result)
        snapshots.append(setup.service.metadata(result.artifact_id))
        assert setup.service.latest_imported(TriageArtifact).artifact_id == result.artifact_id
    assert setup.service.history(TriageArtifact, limit=20) == list(reversed(snapshots))
    assert all(left.created_at < right.created_at for left, right in pairwise(snapshots))
    assert [setup.service.metadata(row.id) for row in snapshots] == snapshots


def test_successor_requires_the_exact_prior_even_for_a_current_digest_retry(
    setup: Publishing,
) -> None:
    original = TriageArtifact.parse(triage_with())
    changed = TriageArtifact.parse(triage_with(FINDING))
    with pytest.raises(ConflictError, match="another writer published"):
        setup.service.publish_successor(original, uuid4())
    first = setup.service.publish_successor(original, None)
    with pytest.raises(ConflictError, match="another writer published"):
        setup.service.publish_successor(original, None)
    second = setup.service.publish_successor(changed, first.artifact_id)
    with pytest.raises(ConflictError, match="another writer published"):
        setup.service.publish_successor(changed, first.artifact_id)
    assert setup.service.latest_imported(TriageArtifact).artifact_id == second.artifact_id
    assert len(setup.service.history(TriageArtifact, limit=10)) == 2


@pytest.mark.parametrize("existing", [False, True])
def test_concurrent_successors_serialize_prior_checks_and_keep_every_committed_snapshot(
    setup: Publishing, engine: sa.Engine, existing: bool
) -> None:
    prior = setup.service.publish("triage", triage_with()).artifact_id if existing else None
    inserted, competing, release = Event(), Event(), Event()
    first_thread: str | None = None

    def after_execute(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _many: object,
    ) -> None:
        if (
            statement.lstrip().upper().startswith("INSERT INTO")
            and "artifact" in statement
            and not inserted.is_set()
        ):
            inserted.set()
            assert release.wait(timeout=10)

    def before_execute(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _many: object,
    ) -> None:
        if current_thread().name != first_thread and (
            statement == "BEGIN IMMEDIATE" or "pg_advisory_xact_lock" in statement
        ):
            competing.set()

    first_doc = TriageArtifact.parse(triage_with(FINDING))
    second_doc = TriageArtifact.parse(
        triage_with(FINDING | {"title": "Competing recorded finding"})
    )

    def first_writer() -> PublishResult:
        nonlocal first_thread
        first_thread = current_thread().name
        return setup.service.publish_successor(first_doc, prior)

    other = ArtifactPublisher(default_specs(), setup.store, SqlTraustUnitOfWork(engine))
    sa.event.listen(engine, "after_cursor_execute", after_execute)
    sa.event.listen(engine, "before_cursor_execute", before_execute)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(first_writer)
            try:
                assert inserted.wait(timeout=10)
                second = pool.submit(other.publish_successor, second_doc, prior)
                assert competing.wait(timeout=10)
                assert not second.done()
            finally:
                release.set()
            committed = first.result(timeout=10)
            with pytest.raises(ConflictError, match="another writer published"):
                second.result(timeout=10)
    finally:
        release.set()
        sa.event.remove(engine, "after_cursor_execute", after_execute)
        sa.event.remove(engine, "before_cursor_execute", before_execute)

    assert other.latest_imported(TriageArtifact).artifact_id == committed.artifact_id
    retried = other.publish_successor(second_doc, committed.artifact_id)
    history = other.history(TriageArtifact, limit=10)
    expected = [retried.artifact_id, committed.artifact_id] + ([prior] if existing else [])
    assert [row.id for row in history] == expected
    assert other.get(committed.artifact_id).payload == first_doc.payload
    assert other.latest(TriageArtifact).payload == second_doc.payload


def test_missing_row_raises_not_found(setup: Publishing) -> None:
    with pytest.raises(NotFoundError):
        setup.service.get(uuid4())


def test_missing_object_raises_not_found(setup: Publishing) -> None:
    with setup.uow as unit:
        row = Seed(unit).artifact(kind="triage", uri="missing.json")
        unit.commit()
    with pytest.raises(NotFoundError):
        setup.service.get(row.id)


def test_bad_stored_document_is_rejected_even_when_its_digest_matches(setup: Publishing) -> None:
    raw = b"{}"
    ref = setup.store.put(ObjectKey.parse("invalid.json"), raw)
    with setup.uow as unit:
        row = Seed(unit).artifact(kind="triage", uri=str(ref.key), digest=ref.sha256)
        unit.commit()
    with pytest.raises(DocumentError):
        setup.service.get(row.id)


def test_read_does_not_hold_a_transaction_during_object_io(
    setup: Publishing, engine: sa.Engine
) -> None:
    result = setup.service.publish("triage", triage_with(FINDING))
    active = 0

    def checkout(*_: object) -> None:
        nonlocal active
        active += 1

    def checkin(*_: object) -> None:
        nonlocal active
        active -= 1

    sa.event.listen(engine, "checkout", checkout)
    sa.event.listen(engine, "checkin", checkin)
    original = setup.store.get

    def checked(ref: ObjectRef) -> bytes:
        assert active == 0
        return original(ref)

    setup.store.get = checked
    try:
        setup.service.get(result.artifact_id)
    finally:
        sa.event.remove(engine, "checkout", checkout)
        sa.event.remove(engine, "checkin", checkin)


@pytest.mark.parametrize("successor", [False, True])
def test_object_publication_finishes_before_acquiring_database_write_intent(
    setup: Publishing, engine: sa.Engine, successor: bool
) -> None:
    active = 0

    def checkout(*_: object) -> None:
        nonlocal active
        active += 1

    def checkin(*_: object) -> None:
        nonlocal active
        active -= 1

    original = setup.store.put

    def checked(key: ObjectKey, data: bytes) -> ObjectRef:
        assert active == 0
        return original(key, data)

    setup.store.put = checked
    sa.event.listen(engine, "checkout", checkout)
    sa.event.listen(engine, "checkin", checkin)
    try:
        artifact = TriageArtifact.parse(triage_with(FINDING))
        if successor:
            setup.service.publish_successor(artifact, None)
        else:
            setup.service.publish_artifact(artifact)
    finally:
        sa.event.remove(engine, "checkout", checkout)
        sa.event.remove(engine, "checkin", checkin)


def test_listing_is_scoped_to_the_assessment_and_optional_kind(setup: Publishing) -> None:
    with setup.uow as unit:
        seed = Seed(unit)
        assessment = seed.assessment()
        expected = seed.artifact(assessment, kind="triage")
        other = seed.artifact(assessment, kind="report")
        seed.artifact(kind="triage")
        unit.commit()
    assert {a.id for a in setup.service.list_for_assessment(assessment.id)} == {
        expected.id,
        other.id,
    }
    assert setup.service.list_for_assessment(assessment.id, kind="triage") == [expected]
    assert setup.service.list_for_assessment(uuid4()) == []


def test_unknown_schema_is_explicit(setup: Publishing) -> None:
    with setup.uow as unit:
        row = Seed(unit).artifact(kind="unknown", uri="unknown.json")
        unit.commit()
    with pytest.raises(ConfigError):
        setup.service.get(row.id)


def test_report_aliases_share_one_readable_contract_type(setup: Publishing) -> None:
    document = {
        "title": "Security Assessment",
        "metadata": {"date": "2026-01-01", "scope": "Synthetic test scope"},
        "executive_summary": {
            "prose": "Synthetic assessment for the shared report schema reader regression.",
            "severity_counts": dict.fromkeys(
                ("critical", "high", "medium", "low", "informational"), 0
            ),
        },
        "severity_criteria": [
            {"level": level, "definition": "Synthetic severity definition"}
            for level in ("critical", "high", "medium", "low")
        ],
        "findings": [],
        "findings_summary": [
            {"severity": level, "count": 0, "finding_ids": []}
            for level in ("critical", "high", "medium", "low")
        ],
        "remediation_roadmap": [
            {"priority": "P3", "action": "Synthetic maintenance task", "addresses": ["coverage"]}
        ],
    }
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(SecurityAuditArtifact), PublishSpec(FindingsCurrentArtifact)),
        setup.store,
        setup.uow,
    )
    first = publisher.publish_artifact(SecurityAuditArtifact.from_document(document))
    again = publisher.publish_artifact(FindingsCurrentArtifact.from_document(document))
    assert first.artifact_id == again.artifact_id
    read = publisher.get(first.artifact_id)
    assert type(read) is ReportArtifact
    assert read.title == document["title"] and read.role is None


def test_empty_input_is_rejected_before_writing(setup: Publishing) -> None:
    with pytest.raises(DocumentError, match="empty input"):
        setup.service.publish("triage", b"  ")
    assert list(setup.store.list()) == []


def test_unrelated_schema_aliases_are_rejected_at_registration() -> None:
    class UnrelatedTriage(ArtifactDocument, schema="triage", name="other-triage"): ...

    with pytest.raises(ConfigError, match="need a common artifact type"):
        PublishSpecs(PublishSpec(TriageArtifact), PublishSpec(UnrelatedTriage))


def test_duplicate_spec_names_are_rejected() -> None:
    with pytest.raises(ConfigError, match="registered twice"):
        PublishSpecs(PublishSpec(TriageArtifact), PublishSpec(TriageArtifact))
