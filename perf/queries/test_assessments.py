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


def test_validation_recording_and_review_lookups_stay_scoped(
    engine: sa.Engine, explained: Profile
) -> None:
    """Seeded assessment-owned reports and forge refs exercise recording's query shapes.
    The seed uses different kind/system values but the same populated indexes."""
    with SqlTraustUnitOfWork(engine) as unit:
        occurrence = unit.connection.execute(sa.select(unit.occurrences.table).limit(1)).one()
        source = unit.assessments.get(occurrence.assessment_id)
        finding_ids = tuple(
            row.finding_id for row in unit.occurrences.list_for_assessment(occurrence.assessment_id)
        )
        external = unit.finding_external_refs.list_for_findings(finding_ids, "forge")[0]

    def lookups(unit: SqlTraustUnitOfWork) -> None:
        assessment_ids = tuple(
            row.id
            for row in unit.assessments.list_for_ref(source.repository_ref_id)
            if row.id is not None
            and row.kind == source.kind
            and row.baseline_assessment_id == source.baseline_assessment_id
        )
        assert occurrence.assessment_id in assessment_ids
        assert unit.artifacts.list_for_assessments(assessment_ids, ("report",))
        assert unit.finding_external_refs.list_for_ref(external.system, external.ref)
        assert len(unit.finding_external_refs.list_for_findings(finding_ids, "forge")) == len(
            finding_ids
        )
        assert unit.assessments.find_at(source.id, source.occurred_at) == source

    assessments, artifacts, linked, review, timestamp = explained(lookups)
    fast(assessments, "idx_assessment_ref_kind_occurred", 5)
    fast(artifacts, "idx_artifact_assessment", 5)
    fast(linked, "finding_external_ref_system_ref_finding_id_key", 5)
    fast(review, "idx_finding_external_ref_finding", 5)
    fast(timestamp, "assessment_pkey", 5)


def test_one_kind_across_a_repositorys_refs_uses_the_covering_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        refs = unit.repository_refs.table
        repository_id = unit.connection.scalar(sa.select(refs.c.repository_id).limit(1))
        ref_ids = [r.id for r in unit.repository_refs.list_for(repository_id)]
    (statement,) = explained(lambda uow: uow.assessments.list_for_refs(ref_ids, "remediation"))
    fast(statement, "idx_assessment_ref_kind_occurred", 5)
