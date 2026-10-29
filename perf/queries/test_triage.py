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


def test_prepare_reads_bounded_batches_by_index(engine: Engine, explained: Profile) -> None:
    with engine.connect() as conn:
        scan = conn.exec_driver_sql(
            "SELECT (array_agg(o.assessment_id))[1] FROM traust.location l "
            "JOIN traust.occurrence o ON o.id = l.occurrence_id "
            "JOIN traust.finding_cwe c ON c.finding_id = o.finding_id "
            "WHERE l.symbol = 'common.Parse' GROUP BY c.cwe_id "
            "HAVING count(DISTINCT o.finding_id) > 1 LIMIT 1"
        ).scalar_one()
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
    indexes = {
        "location": "idx_location_symbol_page",
        "location_hash": "location_hash_location_id_algorithm_key",
        "occurrence": "occurrence_pkey",
        "finding_cwe": "finding_cwe_finding_id_cwe_id_key",
        "decision": "idx_decision_finding_occurred",
        "assessment": "assessment_pkey",
        "finding": "finding_pkey",
        "repository_ref": "repository_ref_id_repository_id_key",
    }
    observed = set()
    for query in precedents:
        table = next(name for name in indexes if f"FROM traust.{name} " in query.sql)
        observed.add(table)
        index = indexes[table]
        if table == "repository_ref" and query.uses_index("repository_ref_pkey"):
            index = "repository_ref_pkey"
        fast(query, index, 2)
        assert query.sql.count("%(") <= 501
        if table == "location":
            assert "LIMIT" in query.sql
    assert observed == set(indexes)
