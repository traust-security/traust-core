from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import pytest
import sqlalchemy as sa
from jsonschema import Draft202012Validator

from tests.v1.fixtures import TRIAGE
from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed, apart
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import DocumentError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import PqcFactsArtifact, TriageArtifact
from traust_core.v1.models.operations import Freshness
from traust_core.v1.models.pqc import PqcStamps
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.store import ObjectKey, ObjectRef
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    ArtifactSchemaProblem,
    AssessmentLog,
    PublishResult,
    PublishSpec,
    PublishSpecs,
)
from traust_core.v1.services.pqc.facts import facts_document

engine = table_fixtures.engine
STAMPS = PqcStamps(adapter_version="1.4.0", pqc_scan_commit="be5c760", rules_sha256="ab" * 32)


def restrict_repository(monkeypatch: pytest.MonkeyPatch, repository: str) -> None:
    original_validator = contracts._validator
    prior = original_validator(PqcFactsArtifact.schema)
    schema = deepcopy(prior.schema)
    schema["properties"]["repository"]["const"] = repository
    current = prior.evolve(schema=schema)

    def validator(name: str) -> Draft202012Validator:
        return current if name == PqcFactsArtifact.schema else original_validator(name)

    monkeypatch.setattr(contracts, "_validator", validator)


@dataclass
class Publishing:
    publisher: ArtifactPublisher
    store: InMemoryObjectStore
    uow: SqlTraustUnitOfWork

    def publish(self, repository: str) -> PublishResult:
        document = facts_document(f"https://example.invalid/widgets/{repository}", STAMPS, [], None)
        return self.publisher.publish_artifact(document)


@pytest.fixture
def publishing(engine: sa.Engine) -> Publishing:
    store, uow = InMemoryObjectStore(), SqlTraustUnitOfWork(engine)
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(PqcFactsArtifact), PublishSpec(TriageArtifact)), store, uow
    )
    return Publishing(publisher, store, uow)


def test_empty_corpus_is_distinguishable_from_a_valid_sample(publishing: Publishing) -> None:
    result = publishing.publisher.pqc_schema_compatibility()
    assert result.checked == 0
    assert result.artifact_ids == result.failures == ()
    assert not result.has_more


def test_only_the_newest_bounded_pqc_documents_are_read(
    publishing: Publishing, monkeypatch: pytest.MonkeyPatch
) -> None:
    oldest = publishing.publish("oldest")
    publishing.store.put(ObjectKey.parse(oldest.written[0]), b"damaged")
    apart()
    middle = publishing.publish("middle")
    apart()
    newest = publishing.publish("newest")
    publishing.publisher.publish("triage", TRIAGE)
    reads: list[ObjectKey] = []
    original_get = publishing.store.get

    def read(ref: ObjectRef) -> bytes:
        reads.append(ref.key)
        return original_get(ref)

    monkeypatch.setattr(publishing.store, "get", read)
    sample = publishing.publisher.pqc_schema_compatibility(sample_size=2)
    assert sample.artifact_ids == (newest.artifact_id, middle.artifact_id)
    assert sample.checked == 2 and sample.sample_size == 2
    assert sample.failures == () and sample.has_more
    assert reads == [ObjectKey.parse(row.written[0]) for row in (newest, middle)]

    full_sample = publishing.publisher.pqc_schema_compatibility(sample_size=3)
    assert full_sample.artifact_ids == (
        newest.artifact_id,
        middle.artifact_id,
        oldest.artifact_id,
    )
    assert full_sample.checked == 3 and not full_sample.has_more
    assert [(f.artifact_id, f.problem) for f in full_sample.failures] == [
        (oldest.artifact_id, ArtifactSchemaProblem.CORRUPT)
    ]


def test_schema_tightening_warns_before_a_consumer_reads_the_incompatible_document(
    publishing: Publishing, monkeypatch: pytest.MonkeyPatch
) -> None:
    older = publishing.publish("legacy")
    apart()
    compatible = publishing.publish("current")
    restrict_repository(monkeypatch, "https://example.invalid/widgets/current")
    result = publishing.publisher.pqc_schema_compatibility(sample_size=2)
    assert result.artifact_ids == (compatible.artifact_id, older.artifact_id)
    assert result.checked == 2 and not result.has_more
    assert [(f.artifact_id, f.problem) for f in result.failures] == [
        (older.artifact_id, ArtifactSchemaProblem.INCOMPATIBLE)
    ]
    assert [issue.path for issue in result.failures[0].issues] == ["repository"]
    with pytest.raises(DocumentError) as error:
        publishing.publisher.get(older.artifact_id)
    assert [issue.path for issue in error.value.issues] == ["repository"]
    assert publishing.publisher.get(compatible.artifact_id).repository.endswith("/current")


def test_attachment_copies_do_not_crowd_out_distinct_published_documents(
    publishing: Publishing,
) -> None:
    older = publishing.publish("older")
    apart()
    newer = publishing.publish("newer")
    with publishing.uow as uow:
        seed = Seed(uow)
        assessments = [seed.assessment() for _ in range(3)]
        uow.commit()
    log = AssessmentLog(publishing.uow)
    digest = publishing.publisher.metadata(older.artifact_id).digest
    with publishing.uow as uow:
        for assessment in assessments:
            assert assessment.id is not None
            log.attach(assessment.id, older.artifact_id, digest)
        uow.commit()
    result = publishing.publisher.pqc_schema_compatibility(sample_size=2)
    assert result.artifact_ids == (newer.artifact_id, older.artifact_id)
    assert result.checked == 2 and result.failures == () and not result.has_more


def test_corrupt_and_missing_objects_are_reported_without_aborting_the_sample(
    publishing: Publishing,
) -> None:
    corrupt = publishing.publish("corrupt")
    missing = publishing.publish("missing")
    valid = publishing.publish("valid")
    publishing.store.put(ObjectKey.parse(corrupt.written[0]), b"not the published document")
    del publishing.store._blobs[ObjectKey.parse(missing.written[0])]
    result = publishing.publisher.pqc_schema_compatibility(sample_size=3)
    assert set(result.artifact_ids) == {
        corrupt.artifact_id,
        missing.artifact_id,
        valid.artifact_id,
    }
    assert result.checked == 3 and not result.has_more
    failures = {failure.artifact_id: failure for failure in result.failures}
    assert {artifact_id: failure.problem for artifact_id, failure in failures.items()} == {
        corrupt.artifact_id: ArtifactSchemaProblem.CORRUPT,
        missing.artifact_id: ArtifactSchemaProblem.MISSING,
    }
    assert all([issue.path for issue in failure.issues] == ["$"] for failure in failures.values())
    with pytest.raises(IntegrityError):
        publishing.publisher.get(corrupt.artifact_id)
    with pytest.raises(NotFoundError):
        publishing.publisher.get(missing.artifact_id)
    assert isinstance(publishing.publisher.get(valid.artifact_id), PqcFactsArtifact)


def test_invalid_stored_json_with_a_matching_digest_is_an_incompatible_document(
    publishing: Publishing,
) -> None:
    valid = publishing.publish("valid")
    ref = publishing.store.put(ObjectKey.parse("artifacts/pqc-facts/invalid.json"), b"not JSON")
    with publishing.uow as uow:
        row = Seed(uow).artifact(
            assessment_id=None, kind=PqcFactsArtifact.schema, digest=ref.sha256, uri=str(ref.key)
        )
        uow.commit()
    result = publishing.publisher.pqc_schema_compatibility(sample_size=2)
    assert set(result.artifact_ids) == {valid.artifact_id, row.id}
    assert result.checked == 2 and not result.has_more
    assert [(failure.artifact_id, failure.problem) for failure in result.failures] == [
        (row.id, ArtifactSchemaProblem.INCOMPATIBLE)
    ]
    assert [issue.path for issue in result.failures[0].issues] == ["$"]


def test_invalid_stored_object_reference_is_corrupt_without_aborting_other_documents(
    publishing: Publishing,
) -> None:
    valid = publishing.publish("valid")
    with publishing.uow as uow:
        row = Seed(uow).artifact(
            assessment_id=None, kind=PqcFactsArtifact.schema, uri="../invalid.json"
        )
        uow.commit()
    result = publishing.publisher.pqc_schema_compatibility(sample_size=2)
    assert set(result.artifact_ids) == {valid.artifact_id, row.id}
    assert result.checked == 2
    assert [(failure.artifact_id, failure.problem) for failure in result.failures] == [
        (row.id, ArtifactSchemaProblem.CORRUPT)
    ]
    assert [issue.path for issue in result.failures[0].issues] == ["$"]


@pytest.mark.parametrize("sample_size", [-1, 0, 1001])
def test_unbounded_or_oversized_samples_are_rejected(
    publishing: Publishing, sample_size: int
) -> None:
    with pytest.raises(ValidationError):
        publishing.publisher.pqc_schema_compatibility(sample_size=sample_size)


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ("empty", Freshness.PENDING),
        ("valid", Freshness.FRESH),
        ("missing", Freshness.STALE),
        ("corrupt", Freshness.STALE),
        ("incompatible", Freshness.STALE),
    ],
)
def test_context_freshness_reports_stored_pqc_compatibility_without_a_consumer_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stored: str,
    expected: Freshness,
) -> None:
    ctx = Context(Config(home=tmp_path))
    published = None
    if stored != "empty":
        publisher = ctx.artifact_publisher(PublishSpecs(PublishSpec(PqcFactsArtifact)))
        document = facts_document("https://example.invalid/widgets/legacy", STAMPS, [], None)
        published = publisher.publish_artifact(document)
        key = ObjectKey.parse(published.written[0])
        if stored == "missing":
            (ctx.config.artifacts_path() / str(key)).unlink()
        elif stored == "corrupt":
            ctx.object_store.put(key, b"damaged stored bytes")
        elif stored == "incompatible":
            restrict_repository(monkeypatch, "https://example.invalid/widgets/current")
    rows = ctx.services().freshness.stale()
    (row,) = [item for item in rows if item.item == "pqc-facts-schema"]
    assert row.status is expected
    if expected is Freshness.STALE:
        assert row.refresh is not None
        assert published is not None
        assert str(published.artifact_id) in row.detail
    else:
        assert row.refresh is None
