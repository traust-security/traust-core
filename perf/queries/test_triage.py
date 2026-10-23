"""3a/3b · A triage's input at a year's volume: one assessment's findings and their locations."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from perf.harness import Profile
from perf.queries.test_findings import reads
from perf.queries.test_ledger import fast
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.lint import Lint


def test_prepare_reads_each_table_once_by_index(engine: Engine, explained: Profile) -> None:
    with engine.connect() as conn:
        scan = conn.exec_driver_sql("SELECT id FROM traust.assessment LIMIT 1").scalar_one()
    clock = FixedClock(datetime.now(UTC))
    statements = explained(
        lambda uow: FindingDecisions(uow, None, Lint({}), clock=clock).prepare(scan)
    )
    assessment, ref, repository, occurrences, findings, locations = reads(statements)
    fast(assessment, "assessment_pkey", 1)
    fast(ref, "repository_ref_id_repository_id_key", 1)
    fast(repository, "repository_pkey", 1)
    fast(occurrences, "idx_occurrence_assessment", 1)
    fast(findings, "finding_pkey", 2)
    fast(locations, "uq_location_range", 2)
    fast(locations, "uq_location_file", 2)
