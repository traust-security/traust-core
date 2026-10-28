import json
import logging
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.example.artifact_publishing import example_specs as default_specs
from tests.v1.fixtures import TRIAGE
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
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
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.repositories.traust.assessments import SqlArtifactRepository
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs

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
    with pytest.raises(ConfigError, match="expected one registered type, got 0"):
        setup.service.get(row.id)
    specs = PublishSpecs(PublishSpec(SecurityAuditArtifact), PublishSpec(FindingsCurrentArtifact))
    assert specs.artifact_type("report") is ReportArtifact


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
