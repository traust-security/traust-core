from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import IntegrityError
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import record_artifact


def test_artifact_kind_filter_preserves_assessment_scope(seed: Seed) -> None:
    scan = seed.assessment(kind="tool_scan")
    expected = seed.artifact(scan, kind="code-facts")
    seed.artifact(scan, kind="triage")
    seed.artifact(kind="code-facts")
    assert seed.uow.artifacts.list_for_assessment(scan.id, kind="code-facts") == [expected]
    assert seed.uow.artifacts.list_for_assessment(scan.id, kind="missing") == []


def test_latest_breaks_exact_timestamp_ties_by_database_id(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    ref = seed.repository_ref()
    rows = [
        {
            "repository_ref_id": ref.id,
            "kind": "tool_scan",
            "status": "completed",
            "assessor": "tool:fixture",
            "assessor_version": "1",
            "occurred_at": T0,
        }
    ] * 2
    table = uow.assessments.table
    ids = (
        uow.connection.execute(sa.insert(table).values(rows).returning(table.c.id)).scalars().all()
    )
    latest = uow.assessments.latest(ref.id, "tool_scan")
    assert latest.id == max(ids)


def test_artifact_get_or_add_keeps_one_row_per_assessment_and_digest(seed: Seed) -> None:
    first_scan, other_scan = seed.assessment(), seed.assessment()
    unsaved = seed.new_artifact(first_scan, kind="code-facts")
    first = seed.uow.artifacts.get_or_add(unsaved)
    again = seed.uow.artifacts.get_or_add(unsaved)
    other = seed.uow.artifacts.get_or_add(
        unsaved.model_copy(update={"assessment_id": other_scan.id})
    )
    assert first == again
    assert first.id != other.id


def test_artifact_digest_does_not_silently_change_document_kind(seed: Seed) -> None:
    artifact = seed.new_artifact(assessment_id=None, kind="code-facts")
    first = record_artifact(seed.uow, artifact)
    with pytest.raises(IntegrityError, match="already recorded as code-facts"):
        record_artifact(seed.uow, artifact.model_copy(update={"kind": "triage"}))
    assert seed.uow.artifacts.get(first.id).kind == "code-facts"


def test_identical_publications_racing_with_an_uncommitted_row_return_one_id(
    engine: sa.Engine,
) -> None:
    artifact = Artifact(digest="a" * 64, kind="code-facts", uri="artifacts/fixture.json")
    started = Event()

    def inserting(
        _conn: object,
        _cursor: object,
        statement: str,
        _params: object,
        _context: object,
        _many: object,
    ) -> None:
        if statement.lstrip().upper().startswith("INSERT INTO"):
            started.set()

    def publish() -> Artifact:
        with SqlTraustUnitOfWork(engine) as unit:
            found = record_artifact(unit, artifact)
            unit.commit()
            return found

    with SqlTraustUnitOfWork(engine) as first:
        saved = record_artifact(first, artifact)
        sa.event.listen(engine, "before_cursor_execute", inserting)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                other = pool.submit(publish)
                try:
                    assert started.wait(timeout=5)
                    assert not other.done()
                finally:
                    first.commit()
                assert other.result(timeout=10).id == saved.id
        finally:
            sa.event.remove(engine, "before_cursor_execute", inserting)
