from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_latest_assessment_uses_ref_kind_index(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c = unit.assessments.table.c
        ref_id, kind = unit.connection.execute(
            sa.select(c.repository_ref_id, c.kind).limit(1)
        ).one()
    (latest,) = explained(lambda unit: unit.assessments.latest(ref_id, kind))
    fast(latest, "idx_assessment_ref_kind_occurred", 5)


def test_artifact_kind_read_stays_scoped_to_one_assessment(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c = unit.artifacts.table.c
        assessment_id = unit.connection.execute(
            sa.select(c.assessment_id).where(c.assessment_id.is_not(None)).limit(1)
        ).scalar_one()
    (artifacts,) = explained(
        lambda unit: unit.artifacts.list_for_assessment(assessment_id, kind="code-facts")
    )
    fast(artifacts, "idx_artifact_assessment", 5)


def test_published_artifact_dedupe_uses_the_imported_digest_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c = unit.artifacts.table.c
        digest = unit.connection.execute(
            sa.select(c.digest).where(c.assessment_id.is_(None)).limit(1)
        ).scalar_one()
    (artifact,) = explained(lambda unit: unit.artifacts.find(None, digest))
    fast(artifact, "uq_artifact_imported", 5)


def test_artifact_id_read_uses_the_primary_key(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        artifact_id = unit.connection.execute(
            sa.select(unit.artifacts.table.c.id).limit(1)
        ).scalar_one()
    (artifact,) = explained(lambda unit: unit.artifacts.get(artifact_id))
    fast(artifact, "artifact_pkey", 5)


def test_atomic_artifact_retry_reads_the_winner_by_digest(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        c = unit.artifacts.table.c
        existing = unit.connection.execute(
            sa.select(c.id).where(c.assessment_id.is_(None)).limit(1)
        ).scalar_one()
        row = unit.artifacts.get(existing)
    write, read = explained(
        lambda unit: unit.artifacts.get_or_add(
            Artifact(digest=row.digest, kind=row.kind, uri=row.uri)
        )
    )
    assert not write.seq_scans(), write.plan
    assert write.execution_ms < 5, write.plan
    fast(read, "uq_artifact_imported", 5)


def test_latest_imported_document_of_a_kind_uses_the_kind_index(explained: Profile) -> None:
    (latest,) = explained(lambda unit: unit.artifacts.latest_imported("code-facts"))
    fast(latest, "idx_artifact_imported_kind", 5)


def test_latest_imported_document_as_of_uses_the_kind_index(explained: Profile) -> None:
    at = datetime.now(UTC)
    (latest,) = explained(lambda unit: unit.artifacts.latest_imported("code-facts", at))
    fast(latest, "idx_artifact_imported_kind", 5)
