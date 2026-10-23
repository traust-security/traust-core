"""3a · Assessments at a year's volume: the ref+kind search a dashboard runs on every tick."""

from __future__ import annotations

import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_search_by_ref_and_kind_uses_the_covering_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(table.c.repository_ref_id, table.c.kind, table.c.status).limit(1)
        ).one()
    (statement,) = explained(
        lambda uow: uow.assessments.search(
            repository_ref_id=row.repository_ref_id, kind=row.kind, status=row.status, limit=50
        )
    )
    fast(statement, "idx_assessment_ref_kind_occurred", 5)


def test_one_kind_across_a_repositorys_refs_uses_the_covering_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        refs = unit.repository_refs.table
        repository_id = unit.connection.scalar(sa.select(refs.c.repository_id).limit(1))
        ref_ids = [r.id for r in unit.repository_refs.list_for(repository_id)]
    (statement,) = explained(lambda uow: uow.assessments.list_for_refs(ref_ids, "remediation"))
    fast(statement, "idx_assessment_ref_kind_occurred", 5)


def test_the_baseline_audit_across_a_repositorys_refs_uses_the_covering_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        refs, assessments = unit.repository_refs.table, unit.assessments.table
        row = unit.connection.execute(
            sa.select(assessments.c.kind, assessments.c.status, refs.c.repository_id)
            .join(refs, refs.c.id == assessments.c.repository_ref_id)
            .limit(1)
        ).one()
        ids = list(
            unit.connection.scalars(
                sa.select(refs.c.id).where(refs.c.repository_id == row.repository_id)
            )
        )
    (statement,) = explained(lambda uow: uow.assessments.latest_for_refs(ids, row.kind, row.status))
    fast(statement, "idx_assessment_ref_kind_occurred", 5)
