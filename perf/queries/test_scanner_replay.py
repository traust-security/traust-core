from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_scanner_replay_uses_ref_kind_and_native_timestamp_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        ref = unit.connection.execute(
            sa.select(unit.assessments.table.c.repository_ref_id).limit(1)
        ).scalar_one()
        scan = unit.assessments.add(
            Assessment(
                repository_ref_id=ref,
                kind=AssessmentKind.SCANNER,
                status="completed",
                assessor="scanner-replay-fixture",
                assessor_version="1",
                occurred_at=datetime(2026, 10, 23, 12, 1, 2, 123456, tzinfo=UTC),
            )
        )
        unit.commit()

    def replay(unit: SqlTraustUnitOfWork) -> None:
        assert unit.assessments.find_scan(ref, scan.assessor, scan.occurred_at) == scan

    (statement,) = explained(replay)
    fast(statement, "idx_assessment_ref_kind_occurred", 5)
