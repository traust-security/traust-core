"""The findings census's SQL legs at a year's volume: the narrow column sets the rollup's
tallies read (wave (e) of the performance lane, foundry#56) — one bounded batch of whole
repositories at a time, each statement on its index, no model per row. The whole-estate
rollup build's own wall clock is the insights case (`test_insights.py`)."""

from __future__ import annotations

from uuid import UUID

import sqlalchemy as sa

from perf.harness import Profile, _issued
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

# The census's own batch of whole repositories: a scope this size is one walk; the
# whole-estate build the rollup serves is 20 of them.
SCOPE = 200

# A batch's decisions or occurrences can be a wide fraction of the table; the planner
# legitimately hash-joins with a scan rather than probing per finding, and the
# occurrence window's sort may spill (the work_mem note in foundry#56's plan). The
# budget is the joined legs' gate; the repository-keyed legs stay on their indexes.
_JOINED_BUDGET_MS = 100


def repositories_of(engine: sa.Engine, count: int) -> list[UUID]:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.repositories.table
        return list(unit.connection.scalars(sa.select(table.c.id).limit(count)))


def findings_of(engine: sa.Engine, repository_ids: list[UUID]) -> list[UUID]:
    with SqlTraustUnitOfWork(engine) as unit:
        table = unit.findings.table
        return list(
            unit.connection.scalars(
                sa.select(table.c.id).where(table.c.repository_id.in_(repository_ids))
            )
        )


def test_the_repository_keyed_census_legs_read_on_their_indexes(
    engine: sa.Engine, explained: Profile
) -> None:
    """The census's single-table legs: no sequential scan at volume."""
    repository_ids = repositories_of(engine, SCOPE)
    finding_ids = findings_of(engine, repository_ids)
    assert len(finding_ids) > SCOPE  # the seed's repositories carry findings

    def read(unit: SqlTraustUnitOfWork) -> None:
        found = unit.findings.census_for_repositories(repository_ids)
        assert len(found) == len(finding_ids)
        refs = unit.repository_refs.census_for_repositories(repository_ids)
        assert len(refs) >= len(repository_ids)

    for statement in explained(read):
        assert not statement.seq_scans(), statement.plan


def test_the_joined_census_legs_stay_under_budget(engine: sa.Engine, explained: Profile) -> None:
    """The census's joined legs — decisions, labels and the windowed occurrences, batched
    by repository — stay inside the budget at volume."""
    repository_ids = repositories_of(engine, SCOPE)

    def read(unit: SqlTraustUnitOfWork) -> None:
        said = unit.census_reads.decisions_for_repositories(repository_ids)
        assert said, "the seed's findings carry decisions"
        labels = unit.census_reads.labels_for_repositories(repository_ids)
        assert isinstance(labels, list)
        reported = unit.census_reads.occurrences_for_repositories(repository_ids)
        assert len(reported) == len(
            {row[0] for row in reported}
        )  # one latest report per finding, with its first's time
        lines = unit.assessments.census_by_ids(
            {row.assessment_id for row in said if row.assessment_id is not None}
        )
        assert isinstance(lines, list)

    for statement in explained(read):
        assert statement.execution_ms < _JOINED_BUDGET_MS, statement.key_line


def test_the_census_walks_a_scope_in_bounded_batches(engine: sa.Engine) -> None:
    """The statements a census issues are bounded by the scope's repositories (never one
    per finding), each batch counted and released."""
    repository_ids = repositories_of(engine, SCOPE)
    context = Context(
        Config(database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)))
    )
    counted: list[int] = []
    with _issued(context.database) as issued:
        context.services().findings.census(repository_ids, lambda rows: counted.append(len(rows)))
    assert sum(counted) == len(findings_of(engine, repository_ids))
    assert len(issued) < SCOPE, [sql[:80] for sql, _ in issued[:5]]
