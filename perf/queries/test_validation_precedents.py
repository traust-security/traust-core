import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_validation_timestamps_are_batched_by_primary_key(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        rows = unit.connection.execute(sa.select(unit.assessments.table).limit(50)).mappings().all()
    timestamps = {row["id"]: row["occurred_at"] for row in rows}
    (statement,) = explained(lambda unit: unit.assessments.list_at(timestamps))
    fast(statement, "assessment_pkey", 5)
