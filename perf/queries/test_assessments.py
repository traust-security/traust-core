"""3a · Assessments at a year's volume: the ref+kind search a dashboard runs on every tick."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import sqlalchemy as sa

from perf.harness import Profile
from perf.queries.test_ledger import fast
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
    AssessmentKind,
)
from traust_core.v1.models.common import RecordBudget
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
from traust_core.v1.services.assessment import AssessmentService


@pytest.mark.parametrize("with_version", [False, True])
def test_search_by_ref_and_kind_uses_the_covering_index(
    engine: sa.Engine, explained: Profile, with_version: bool
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(
                table.c.repository_ref_id, table.c.kind, table.c.status, table.c.assessor_version
            ).limit(1)
        ).one()
    (statement,) = explained(
        lambda uow: uow.assessments.search(
            repository_ref_id=row.repository_ref_id,
            kind=row.kind,
            status=row.status,
            limit=50,
            assessor_version=row.assessor_version if with_version else None,
        )
    )
    fast(statement, "idx_assessment_ref_kind_occurred", 5)


def test_search_by_ref_set_uses_the_covering_index(engine: sa.Engine, explained: Profile) -> None:
    # The batch listings' set scope (GET /v1/assessments?repository_ids=): one
    # query over a page's worth of refs, never one per repository.
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        rows = unit.connection.execute(
            sa.select(table.c.repository_ref_id).distinct().limit(100)
        ).all()
    refs = [row.repository_ref_id for row in rows]
    (statement,) = explained(lambda uow: uow.assessments.search(repository_ref_ids=refs, limit=101))
    fast(statement, "idx_assessment_ref_kind_occurred", 100)


def test_bounded_version_scan_does_not_charge_other_versions(explained: Profile) -> None:
    def read(uow: SqlTraustUnitOfWork) -> None:
        budget = RecordBudget(1, "selected audits")
        assert (
            AssessmentLog(uow).list_of(
                None, assessor_version="not-a-recorded-perf-version", read_budget=budget
            )
            == []
        )
        assert budget.remaining == 1

    (statement,) = explained(read)
    assert statement.execution_ms < 100, statement.plan


def test_latest_measurement_at_a_cutoff_uses_the_ref_kind_index(
    engine: sa.Engine, explained: Profile
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(
                table.c.repository_ref_id, table.c.kind, table.c.status, table.c.occurred_at
            ).limit(1)
        ).one()
    (statement,) = explained(
        lambda uow: uow.assessments.latest(
            row.repository_ref_id, row.kind, row.status, as_of=row.occurred_at
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


@pytest.mark.parametrize("kind", [AssessmentKind.REPO_STATE, AssessmentKind.REPO_STATE_CANONICAL])
def test_latest_recorded_returns_one_nonempty_scoped_row_by_index(
    engine: sa.Engine, explained: Profile, kind: AssessmentKind
) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        refs, assessments = unit.repository_refs.table, unit.assessments.table
        row = unit.connection.execute(
            sa.select(assessments.c.id, assessments.c.repository_ref_id, refs.c.repository_id)
            .join(assessments, assessments.c.repository_ref_id == refs.c.id)
            .where(
                assessments.c.kind.in_(
                    (AssessmentKind.REPO_STATE, AssessmentKind.REPO_STATE_CANONICAL)
                ),
                assessments.c.status.in_((ASSESSMENT_COMPLETED, ASSESSMENT_DEGRADED)),
            )
            .order_by(assessments.c.occurred_at.desc(), assessments.c.id.desc())
            .limit(1)
        ).one()

    def read(unit: SqlTraustUnitOfWork) -> None:
        found = AssessmentService(unit).latest_recorded(row.repository_id, kind)
        assert found.id == row.id
        assert found.repository_ref_id == row.repository_ref_id
        assert found.kind == AssessmentKind.REPO_STATE_CANONICAL
        assert found.status in (ASSESSMENT_COMPLETED, ASSESSMENT_DEGRADED)

    repository, latest = explained(read)
    assert repository.execution_ms < 5, repository.plan
    assert latest.execution_ms < 5, latest.plan


@pytest.mark.parametrize("since", ["an hour ago", "the start"])
def test_the_feeds_assessments_after_a_cursor_by_index(explained: Profile, since: str) -> None:
    after = (datetime.now(UTC) - timedelta(hours=1), UUID(int=0)) if since != "the start" else None
    (found,) = explained(lambda uow: uow.assessments.feed_after(after, 1001))
    fast(found, "idx_assessment_created", 20)


def test_original_audit_lock_uses_primary_key(engine: sa.Engine, explained: Profile) -> None:
    with SqlTraustUnitOfWork(engine) as unit:
        assessment_id = unit.connection.scalar(sa.select(unit.assessments.table.c.id).limit(1))
    (statement,) = explained(lambda unit: unit.assessments.get_for_update(assessment_id))
    fast(statement, "assessment_pkey", 5)


def test_the_census_latest_per_ref_and_kind_groups_by_index(
    engine: sa.Engine, explained: Profile
) -> None:
    """The coverage fold's window: each (ref, kind)'s newest under the filters, one row per
    group — never the assessments below the newest."""
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(
                table.c.repository_ref_id, table.c.kind, table.c.status, table.c.occurred_at
            ).limit(1)
        ).one()
        ref_ids = list(
            unit.connection.scalars(
                sa.select(table.c.repository_ref_id)
                .where(table.c.kind == row.kind, table.c.status == row.status)
                .limit(2_500)
            )
        )
        distinct = len(set(ref_ids))

    def read(uow: SqlTraustUnitOfWork) -> None:
        found = uow.assessments.latest_per_ref_and_kind(
            ref_ids, [row.kind], row.status, until=row.occurred_at
        )
        assert 0 < len(found) <= distinct

    # one statement per 500-ref batch, each the same grouped window
    for statement in explained(read):
        fast(statement, "idx_assessment_ref_kind_occurred", 50)


def test_the_census_counts_group_by_index(engine: sa.Engine, explained: Profile) -> None:
    """The population fold's counts: narrow (ref, kind, runs) rows, never the assessments."""
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(table.c.repository_ref_id, table.c.kind, table.c.status).limit(1)
        ).one()
        ref_ids = list(
            unit.connection.scalars(
                sa.select(table.c.repository_ref_id)
                .where(table.c.kind == row.kind, table.c.status == row.status)
                .limit(2_500)
            )
        )

    def read(uow: SqlTraustUnitOfWork) -> None:
        found = uow.assessments.counts_for_refs(ref_ids, [row.kind], row.status)
        assert found and all(count >= 1 for _, _, count in found)

    # one statement per 500-ref batch, each the same grouped count
    for statement in explained(read):
        fast(statement, "idx_assessment_ref_kind_occurred", 50)


def _seed_component_assessments(engine: sa.Engine) -> tuple[UUID, UUID, str, str]:
    """Populate representative non-null target_purl rows so partial-index plans measure hits."""
    target_purl = "pkg:maven/org.springframework/spring-beans@7.1.0"
    sibling_purl = "pkg:maven/org.springframework/spring-context@7.1.0"
    with engine.begin() as conn:
        existing = conn.exec_driver_sql(
            "SELECT a.repository_ref_id, r.repository_id, a.kind "
            "FROM traust.assessment a JOIN traust.repository_ref r ON r.id = a.repository_ref_id "
            "WHERE a.target_purl = %s LIMIT 1",
            (target_purl,),
        ).first()
        if existing is not None:
            return existing[0], existing[1], existing[2], target_purl
        refs = conn.exec_driver_sql(
            "SELECT id, repository_id FROM traust.repository_ref LIMIT 100"
        ).all()
        rows = []
        base = datetime(2026, 11, 20, tzinfo=UTC)
        for i, (ref_id, _) in enumerate(refs):
            for j, purl in enumerate((target_purl, sibling_purl)):
                rows.append(
                    (
                        ref_id,
                        "secure_code",
                        "completed",
                        "skill:secure-code-audit",
                        "1.0.0",
                        base + timedelta(minutes=i * 2 + j),
                        purl,
                    )
                )
        conn.exec_driver_sql(
            "INSERT INTO traust.assessment "
            "(repository_ref_id, kind, status, assessor, assessor_version, "
            "occurred_at, target_purl) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            rows,
        )
        conn.exec_driver_sql("ANALYZE traust.assessment")
        return refs[0][0], refs[0][1], "secure_code", target_purl


def test_component_target_purl_latest_uses_partial_index(
    engine: sa.Engine, explained: Profile
) -> None:
    """Component-scoped latest lookup finds the intended PURL via the partial index (real hit)."""
    ref_id, repo_id, kind, target_purl = _seed_component_assessments(engine)

    def read_ref(uow: SqlTraustUnitOfWork) -> None:
        found = uow.assessments.latest(ref_id, kind, ASSESSMENT_COMPLETED, target_purl=target_purl)
        assert found is not None and found.target_purl == target_purl

    def read_repo(uow: SqlTraustUnitOfWork) -> None:
        found = uow.assessment_reads.latest_for_repository(
            repo_id, (kind,), (ASSESSMENT_COMPLETED, ASSESSMENT_DEGRADED), target_purl=target_purl
        )
        assert found is not None and found.target_purl == target_purl

    (by_ref,) = explained(read_ref)
    fast(by_ref, "idx_assessment_ref_target_kind_occurred", 5)
    (by_repo,) = explained(read_repo)
    fast(by_repo, "idx_assessment_ref_target_kind_occurred", 10)


def test_whole_repo_latest_is_null_stays_indexed_with_component_rows_present(
    engine: sa.Engine, explained: Profile
) -> None:
    """Whole-repo latest (target_purl IS NULL) stays indexed and excludes component PURL rows."""
    _seed_component_assessments(engine)
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.assessments.table
        row = unit.connection.execute(
            sa.select(table.c.repository_ref_id, table.c.kind, table.c.status)
            .where(table.c.target_purl.is_(None))
            .limit(1)
        ).one()

    def read_whole(uow: SqlTraustUnitOfWork) -> None:
        found = uow.assessments.latest(row.repository_ref_id, row.kind, row.status)
        assert found is not None and found.target_purl is None

    (stmt,) = explained(read_whole)
    fast(stmt, "idx_assessment_ref_kind_occurred", 5)
