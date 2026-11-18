"""FindingService.census on SQLite and Postgres: the counted facts without the views'
weight — one narrow column set per table, the disposition folded over tuples. The row a
finding yields must be the facts its own view carries (the adapter `_census_row`), the
identity the rollup's tallies stand on; each batch is delivered for counting, never
held for the whole scope."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.findings.test_reads import T0, service
from tests.v1.services.findings.test_rollups import new_repo
from traust_core.v1.context import Config, Context
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.census import FindingCensusRow as Row
from traust_core.v1.services.insight import _census_row

DAY = timedelta(days=1)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def census_of(engine: Engine, repository_ids: list[UUID], as_of=None) -> dict[UUID, Row]:
    rows: dict[UUID, Row] = {}
    service(engine).census(
        repository_ids,
        lambda batch: rows.update({row.finding_id: row for row in batch}),
        as_of,
    )
    return rows


def views_of(engine: Engine, repository_ids: list[UUID], as_of=None) -> dict[UUID, object]:
    found = service(engine).all_in(repository_ids, as_of)
    return {view.finding.id: _census_row(view) for rows in found.values() for view in rows}


def test_the_census_rows_are_the_views_counted_facts(engine: Engine) -> None:
    """Every disposition, severity, category and top fact a tally reads: the census row
    equals what the finding's own view carries, field for field."""
    left, right = new_repo(engine), new_repo(engine)
    open_high = left.reported(day=0, severity="high")
    top = left.reported(day=1, severity="critical", cvss_score="9.1")
    hardening = left.reported(day=0, severity="high", labels=(("category", "xss"),))
    left.judged(hardening, 1, validity="hardening")
    weakness = left.reported(day=0, severity="medium", labels=(("category", "xss"),))
    with SqlTraustUnitOfWork(engine) as uow:
        uow.findings.update(weakness.model_copy(update={"kind": "weakness"}))
        uow.commit()
    refuted = left.reported(day=0, severity="high")
    left.judged(refuted, 2, validity="false_positive", evidence_grade="E1")
    resolved = left.reported(day=0, severity="medium")
    left.judged(resolved, 2, resolution="resolved")
    accepted = left.reported(day=0, severity="low")
    left.judged(accepted, 3, resolution="risk_accepted")
    proven = left.reported(day=0, severity="high")
    left.assessed(proven, "triage", 4, validity="confirmed", evidence_grade="E0")
    unjugded_later = left.reported(day=9, severity="high")
    quiet = right.reported(day=1, severity="low")

    rows = census_of(engine, [left.repository.id, right.repository.id])
    views = views_of(engine, [left.repository.id, right.repository.id])

    assert set(rows) == set(views)
    for finding_id, row in rows.items():
        assert row == views[finding_id], f"row drifted from the view for {finding_id}"

    assert rows[top.id].state == "open" and rows[top.id].cvss_score is not None
    assert rows[top.id].sla_due is not None  # the top cut carries its SLA
    assert rows[open_high.id].sla_due == views[open_high.id].sla_due  # the view's own clock
    assert rows[hardening.id].state == "hardening" and rows[hardening.id].category == "xss"
    assert rows[weakness.id].state == "hardening" and rows[weakness.id].category == "xss"
    assert rows[refuted.id].state == "false_positive" and rows[refuted.id].decided
    assert rows[resolved.id].state == "resolved" and rows[resolved.id].decided
    assert rows[accepted.id].state == "accepted"
    assert rows[proven.id].proven and rows[proven.id].state == "open"
    assert rows[unjugded_later.id].unverified and not rows[unjugded_later.id].decided
    assert rows[quiet.id].state == "open" and rows[quiet.id].severity == "low"


def test_the_census_honours_the_as_of_cut_like_the_views_do(engine: Engine) -> None:
    """A report or decision after `as_of` is left out: the row counts what the view at
    that point in time would have carried, and a finding never reported by then yields
    no row at all."""
    repo = new_repo(engine)
    early = repo.reported(day=0, severity="critical")
    repo.reported(day=5, severity="high")
    refuted_later = repo.reported(day=0, severity="high")
    repo.judged(refuted_later, 6, validity="false_positive")

    as_of = T0 + timedelta(days=3)
    rows = census_of(engine, [repo.repository.id], as_of)
    views = views_of(engine, [repo.repository.id], as_of)

    assert set(rows) == {early.id, refuted_later.id}  # late's report is after the cut
    assert rows[early.id].state == "open" and rows[early.id].severity == "critical"
    assert rows[refuted_later.id].state == "open"  # the refutation is after the cut
    for finding_id, row in rows.items():
        assert row == views[finding_id], f"row drifted from the view for {finding_id}"


def test_the_census_walks_bounded_batches_and_serves_nothing_for_no_scope(
    engine: Engine,
) -> None:
    repos = [new_repo(engine) for _ in range(3)]
    for repo in repos:
        repo.reported(day=0)
    batches: list[int] = []
    findings = service(engine)
    findings.census(
        [repo.repository.id for repo in repos],
        lambda batch: batches.append(len(batch)),
    )
    assert batches == [3]  # one bounded batch for a scope this size
    findings.census([], lambda batch: batches.append(len(batch)))
    assert batches == [3]


def test_the_census_counts_a_repositorys_findings_newest_first(
    engine: Engine, tmp_path: Path
) -> None:
    """The top cut's stable-sort ties (same severity and CVSS in one repository) break on
    the fold's own newest-first order: two tied findings keep the order the views' fold
    delivered them in, exactly (the estate-scale parity caught this once)."""
    repo = new_repo(engine)
    older = repo.reported(day=0, severity="critical")
    newer = repo.reported(day=5, severity="critical")
    rows = census_of(engine, [repo.repository.id])
    assert list(rows) == [newer.id, older.id]  # newest first, the fold's own order

    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    built = ctx.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter())
    assert [t.finding_id for t in built.top] == [newer.id, older.id]


def test_the_kind_crosswalk_cache_is_bounded_by_the_vocabulary_not_the_histories() -> None:
    """Varied and growing decision histories must not grow the kind crosswalk's cache:
    the memo is per distinct validity value, so a long-running process holds the
    vocabulary an estate spells and nothing else (Qodo's finding on the first pass)."""
    from traust_core.v1.models.findings import kind_of, validity_kind_pairs

    validities = ["confirmed", "false_positive", "true_positive", "hardening", None]
    validity_kind_pairs.cache_clear()
    for n in range(200):
        kind_of(None, tuple(validities[: 1 + n % 4]) * (1 + n % 3))
    assert validity_kind_pairs.cache_info().currsize <= len({v for v in validities if v})


def test_a_census_batch_is_bounded_by_findings_not_repository_count(engine: Engine) -> None:
    """A batch closes once it holds enough findings (the fold's own `_FACTS_BATCH`
    discipline), so a monorepo estate cannot load a whole table in one batch; a single
    repository larger than the bound is its own batch, whole (Qodo's finding on the
    third pass)."""
    from traust_core.v1.services.findings import census as census_module

    small, monorepo = new_repo(engine), new_repo(engine)
    for _ in range(census_module._FINDINGS_PER_BATCH + 2):
        monorepo.reported(day=0)
    for _ in range(3):
        small.reported(day=0)
    counted: list[int] = []
    service(engine).census(
        [small.repository.id, monorepo.repository.id],
        lambda rows: counted.append(len(rows)),
    )
    # the monorepo is one whole batch over the bound; the small repositories one under it
    assert counted == [3, census_module._FINDINGS_PER_BATCH + 2]


def test_an_empty_scope_reads_no_claims_and_counts_nothing(engine: Engine) -> None:
    """A scope of repositories with no findings never runs the estate-wide claim-candidate
    query (Qodo's finding on the fifth pass): an empty rollup costs its counts read and
    nothing else."""
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.models.findings import Decision, DecisionReason

    repo = new_repo(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        # a claim-candidate decision exists somewhere in the database
        seed = Seed(uow)
        other = seed.finding()
        artifact = seed.artifact()
        uow.decisions.add(
            Decision(
                finding_id=other.id,
                statement_key="claim",
                reason=DecisionReason.BASELINE_REWRITE,
                artifact_id=artifact.id,
                actor="human:analyst@example.com",
                occurred_at=T0,
            )
        )
        uow.commit()
    counted: list[int] = []
    service(engine).census([repo.repository.id], lambda rows: counted.append(len(rows)))
    assert counted == []
