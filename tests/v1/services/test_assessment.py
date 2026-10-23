from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import IntegrityError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.analysis_results import Subject
from traust_core.v1.models.artifacts import RepoStateArtifact
from traust_core.v1.models.assessment import AssessmentFilter, AssessmentKind
from traust_core.v1.models.common import ArtifactRef, Cursor, PageRequest, Provenance
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects.analysis_results import AnalysisResultsRepository
from traust_core.v1.repositories.traust.assessments import SqlArtifactRepository
from traust_core.v1.services.artifact_publishing import (
    ArtifactPublisher,
    PublishSpec,
    PublishSpecs,
    SqlArtifactIndex,
)
from traust_core.v1.services.assessment import AssessmentService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

DOC = RepoStateArtifact.from_document({"observed_at": "2026-10-05T00:00:00+00:00", "status": "ok"})


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> AssessmentService:
    return AssessmentService(uow)


def provenance(artifact_id: object | None, *, occurred_at: object = T0) -> Provenance:
    ref = (
        None
        if artifact_id is None
        else ArtifactRef(id=artifact_id, name="repo-state", digest="sha256:x")
    )
    return Provenance(
        run_id=uuid4(), artifact=ref, source=SourceType.INTERACTIVE, occurred_at=occurred_at
    )


def test_record_creates_assessment_and_links_a_new_artifact_row(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    published = seed.artifact(
        assessment_id=None, kind="repo-state", uri="file:///a.json", digest=sha256_hex(DOC.payload)
    )

    assessment = service.record(
        DOC,
        ref.id,
        AssessmentKind.REPO_STATE,
        "tool:gitlab-observer",
        "1.4.0",
        provenance(published.id),
    )

    assert assessment.repository_ref_id == ref.id
    assert assessment.kind == AssessmentKind.REPO_STATE
    assert assessment.assessor == "tool:gitlab-observer"
    assert assessment.assessor_version == "1.4.0"
    assert assessment.occurred_at == T0
    linked = seed.uow.artifacts.list_for_assessment(assessment.id)
    assert len(linked) == 1
    assert linked[0].id != published.id  # a new row, not the imported one
    assert linked[0].digest == published.digest
    assert linked[0].kind == published.kind
    assert linked[0].uri == published.uri


def test_record_without_a_published_artifact_raises(service: AssessmentService, seed: Seed) -> None:
    ref = seed.repository_ref()
    with pytest.raises(ValidationError):
        service.record(DOC, ref.id, AssessmentKind.REPO_STATE, "tool:x", "1.0", provenance(None))


def test_record_with_an_unknown_artifact_reference_raises_not_found(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    with pytest.raises(NotFoundError):
        service.record(DOC, ref.id, AssessmentKind.REPO_STATE, "tool:x", "1.0", provenance(uuid4()))


def test_record_rejects_a_reference_whose_bytes_dont_match_doc(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    stale = seed.artifact(assessment_id=None, kind="repo-state", digest="sha256:unrelated")
    with pytest.raises(IntegrityError):
        service.record(
            DOC, ref.id, AssessmentKind.REPO_STATE, "tool:x", "1.0", provenance(stale.id)
        )


def test_record_rolls_back_the_assessment_if_the_artifact_write_fails(
    engine: sa.Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Standalone uow, not the shared `uow`/`seed` fixture: SqlUnitOfWork is re-entrant and
    only the outermost `with` owns the rollback (repositories/sql.py), so a nested one (the
    fixture's) would swallow this. Patched on the class, not the instance: `_open_repositories`
    rebuilds `unit.artifacts` on every `with`, so an instance-level patch is discarded on
    `record`'s own re-entry."""
    unit = SqlTraustUnitOfWork(engine)
    with unit:
        setup = Seed(unit)
        ref = setup.repository_ref()
        published = setup.artifact(
            assessment_id=None,
            kind="repo-state",
            uri="file:///a.json",
            digest=sha256_hex(DOC.payload),
        )
        unit.commit()
    failing_add = Mock(side_effect=RepositoryError("artifact write failed"))
    monkeypatch.setattr(SqlArtifactRepository, "add", failing_add)
    with pytest.raises(RepositoryError, match="artifact write failed"):
        AssessmentService(unit).record(
            DOC, ref.id, AssessmentKind.REPO_STATE, "tool:x", "1.0", provenance(published.id)
        )
    failing_add.assert_called_once()
    monkeypatch.undo()  # a fresh transaction, read with the real repository
    with unit:
        assert unit.assessments.list_for_ref(ref.id) == []


def test_get_returns_the_recorded_assessment(service: AssessmentService, seed: Seed) -> None:
    saved = seed.assessment()
    assert service.get(saved.id) == saved


def test_get_missing_raises_not_found(service: AssessmentService) -> None:
    with pytest.raises(NotFoundError):
        service.get(uuid4())


def test_latest_is_none_without_assessments(service: AssessmentService, seed: Seed) -> None:
    ref = seed.repository_ref()
    assert service.latest(ref.id, AssessmentKind.SECURE_CODE) is None


def test_latest_returns_the_newest_by_occurred_at(service: AssessmentService, seed: Seed) -> None:
    ref = seed.repository_ref()
    seed.assessment(ref, kind="secure-code", occurred_at=T0)
    newest = seed.assessment(ref, kind="secure-code", occurred_at=T0 + timedelta(days=7))
    seed.assessment(ref, kind="threat-model", occurred_at=T0 + timedelta(days=30))
    assert service.latest(ref.id, AssessmentKind.SECURE_CODE) == newest


def test_list_filters_by_repository_ref_kind_and_status(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    other_ref = seed.repository_ref()
    match = seed.assessment(ref, kind="secure-code", status="completed")
    seed.assessment(ref, kind="threat-model", status="completed")  # wrong kind
    seed.assessment(ref, kind="secure-code", status="degraded")  # wrong status
    seed.assessment(other_ref, kind="secure-code", status="completed")  # wrong ref

    page = service.list(
        AssessmentFilter(
            repository_ref_id=ref.id, kind=AssessmentKind.SECURE_CODE, status="completed"
        ),
        PageRequest(),
    )

    assert page.items == (match,)
    assert page.next is None


def test_list_with_no_matches_is_empty(service: AssessmentService, seed: Seed) -> None:
    ref = seed.repository_ref()
    page = service.list(AssessmentFilter(repository_ref_id=ref.id), PageRequest())
    assert page.items == ()
    assert page.next is None


def test_list_paginates_newest_first_and_the_cursor_continues(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    oldest = seed.assessment(ref, occurred_at=T0)
    middle = seed.assessment(ref, occurred_at=T0 + timedelta(days=1))
    newest = seed.assessment(ref, occurred_at=T0 + timedelta(days=2))

    first = service.list(AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=2))
    assert first.items == (newest, middle)
    assert first.next is not None

    second = service.list(
        AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=2, cursor=first.next)
    )
    assert second.items == (oldest,)
    assert second.next is None


@pytest.mark.parametrize("limit", [0, -1])
def test_list_rejects_a_non_positive_limit(
    service: AssessmentService, seed: Seed, limit: int
) -> None:
    ref = seed.repository_ref()
    seed.assessment(ref)  # a nonempty result set is what used to crash on limit=0
    with pytest.raises(ValidationError):
        service.list(AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=limit))


def test_list_without_a_repository_ref_id_raises(service: AssessmentService) -> None:
    with pytest.raises(ValidationError):
        service.list(AssessmentFilter(), PageRequest())


@pytest.mark.parametrize("cursor", ["not-a-cursor", "2026-99-99|not-a-uuid", "2026-10-05|"])
def test_list_rejects_a_malformed_cursor(
    service: AssessmentService, seed: Seed, cursor: str
) -> None:
    ref = seed.repository_ref()
    with pytest.raises(ValidationError):
        service.list(AssessmentFilter(repository_ref_id=ref.id), PageRequest(cursor=Cursor(cursor)))


def test_list_with_tied_occurred_at_has_no_duplicates_or_gaps_across_pages(
    service: AssessmentService, seed: Seed
) -> None:
    ref = seed.repository_ref()
    tied = {seed.assessment(ref, occurred_at=T0).id for _ in range(3)}

    first = service.list(AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=2))
    assert len(first.items) == 2
    assert first.next is not None

    second = service.list(
        AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=2, cursor=first.next)
    )
    assert len(second.items) == 1
    assert second.next is None

    assert {a.id for a in (*first.items, *second.items)} == tied


def test_repo_state_flows_through_publish_then_record_like_any_other_kind(
    engine: sa.Engine, service: AssessmentService, seed: Seed
) -> None:
    """The plan's repo-state addendum: record/latest take kind repo-state with a
    RepoStateArtifact "like any other kind" once something has published it."""
    ref = seed.repository_ref()
    seed.uow.commit()  # release the write lock so the index's own uow can write (SQLite)
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(artifact=RepoStateArtifact)),
        AnalysisResultsRepository(InMemoryObjectStore()),
        SqlArtifactIndex(lambda: SqlTraustUnitOfWork(engine)),
    )
    result = publisher.publish_artifact(DOC, Subject(tree="t", repo_dir="r", base="main"), "run-1")
    assert not result.degraded
    assert result.artifact_id is not None

    assessment = service.record(
        DOC,
        ref.id,
        AssessmentKind.REPO_STATE,
        "tool:gitlab-observer",
        "1.4.0",
        provenance(result.artifact_id),
    )
    assert assessment.kind == AssessmentKind.REPO_STATE
    assert service.latest(ref.id, AssessmentKind.REPO_STATE) == assessment
