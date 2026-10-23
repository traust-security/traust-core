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
