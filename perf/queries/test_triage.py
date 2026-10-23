"""3a/3b · A triage's input at a year's volume: one assessment's findings, locations, precedents."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from perf.harness import Profile
from perf.queries.test_findings import reads
from perf.queries.test_ledger import fast
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.review import ReviewPolicy
from traust_core.v1.services.lint import Lint


def test_prepare_reads_each_table_once_by_index(engine: Engine, explained: Profile) -> None:
    with engine.connect() as conn:
        scan = conn.exec_driver_sql("SELECT id FROM traust.assessment LIMIT 1").scalar_one()
    clock = FixedClock(datetime.now(UTC))
    statements = explained(
        lambda uow: FindingDecisions(
            uow,
            None,
            Lint({}),
            FindingPrecedents(uow),
            clock=clock,
            objects=InMemoryObjectStore(),
            review=ReviewPolicy(),
        ).prepare(scan)
    )
    assessment, ref, repository, occurrences, findings, locations, *precedents = reads(statements)
    fast(assessment, "assessment_pkey", 1)
    fast(ref, "repository_ref_id_repository_id_key", 1)
    fast(repository, "repository_pkey", 1)
    fast(occurrences, "idx_occurrence_assessment", 1)
    fast(findings, "finding_pkey", 2)
    fast(locations, "uq_location_range", 2)
    fast(locations, "uq_location_file", 2)
    same_function, their_occurrences, cwes, decisions = precedents[:4]
    fast(same_function, "idx_location_symbol", 2)
    fast(their_occurrences, "occurrence_pkey", 2)
    fast(cwes, "finding_cwe_finding_id_cwe_id_key", 2)
    fast(decisions, "idx_decision_finding_occurred", 2)
