"""The duress apparatus: dashboard reads under the stamped write door.

The duress run is gated by TRAUST_PERF_LOAD (it mutates the rig: decisions
are written); `make perf-load` sets it. Readers default past the engine
pool's size — the 504 shape the first concurrent receipt could not reach.
The card population itself is pure and always runs."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from perf.load import (
    READ_P95_BUDGET,
    TRIAGE_WAIT_BUDGET,
    WRITE_SLOWDOWN_LIMIT,
    cards,
    run_duress,
    run_mixed_duress,
    run_rescan_duress,
)
from traust_core.v1.context import Context
from traust_core.v1.models.dashboard import Dimension, Subject

skip_unless_gated = pytest.mark.skipif(
    not os.environ.get("TRAUST_PERF_LOAD"), reason="TRAUST_PERF_LOAD not set (make perf-load)"
)


def _grants() -> tuple[tuple, tuple]:
    return tuple(uuid4() for _ in range(3)), tuple(uuid4() for _ in range(366))


def test_the_population_covers_every_card_shape_over_every_grant_size() -> None:
    small, granted = _grants()
    population = cards(small, granted)
    assert len(population) == 15  # five shapes x three grant sizes
    assert all(card.subject is Subject.FINDINGS for card in population)
    grants = {card.repository_ids for card in population}
    assert grants == {small, granted, ()}
    shapes = {card.group_by for card in population}
    assert {(Dimension.SEVERITY,), (Dimension.CATEGORY,), (Dimension.REPOSITORY,)} <= shapes


def test_every_card_is_a_body_the_route_accepts() -> None:
    from traust_core.v1.models.dashboard import DashboardQuery

    small, granted = _grants()
    for card in cards(small, granted):
        body = card.model_dump(mode="json")
        assert DashboardQuery.model_validate(body) == card


@skip_unless_gated
def test_dashboard_reads_under_the_stamped_write_door(engine: Engine, context: Context) -> None:
    """The farm's duress bar: dashboard p95 under a second with zero failures, and the
    write door's p95 within twice its own, measured alone first."""
    duress = run_duress(engine, context, seconds=int(os.environ.get("TRAUST_PERF_SECONDS", "60")))
    print(duress.report())
    assert duress.reads.failures == 0, "no dashboard read may fail under duress"
    assert duress.writes.failures == 0, "the write door must not fail under read load"
    assert duress.reads.pct(95) < READ_P95_BUDGET, "dashboard p95 over budget"
    assert duress.writes.pct(95) <= WRITE_SLOWDOWN_LIMIT * duress.baseline.pct(95), (
        "readers slowed the write door past twice its own p95"
    )


@skip_unless_gated
def test_dashboard_reads_through_a_full_rescan(engine: Engine, context: Context) -> None:
    """A full rescan of the long-tail repository: dashboards keep their budget, nothing
    fails, and a person's decision on that repository waits at most one stamp batch -
    never the rescan's length (one transaction held every row: a 68s wait, measured)."""
    duress = run_rescan_duress(engine, context)
    print(duress.report())
    assert duress.reads.failures == 0, "no dashboard read may fail during a rescan"
    assert duress.triage.failures == 0, "a triage decision must wait for a rescan, not fail"
    assert duress.reads.pct(95) < READ_P95_BUDGET, "dashboard p95 over budget during a rescan"
    assert duress.triage.max < TRIAGE_WAIT_BUDGET, (
        "a person's decision waited on the rescan past one stamp batch"
    )


@skip_unless_gated
def test_everything_at_once_holds_the_budgets(engine: Engine, context: Context) -> None:
    """The steady spread (TRAUST_PERF_MIXED_SECONDS, default ten minutes): dashboards keep
    their budget beside findings pages, a report-grade build, the write door and a full
    rescan; nothing fails; the write door stays within twice its own p95."""
    seconds = int(os.environ.get("TRAUST_PERF_MIXED_SECONDS", "600"))
    report = os.environ.get("TRAUST_PERF_MIXED_REPORT", "1") != "0"  # attribution runs
    duress = run_mixed_duress(engine, context, seconds=seconds, report=report)
    print(duress.report_lines())
    for side in (duress.dashboards, duress.pages, duress.report, duress.writes):
        assert side.failures == 0, "nothing may fail in the steady spread"
    assert duress.report.latencies or not report, "the report-grade build must complete"
    assert duress.dashboards.pct(95) < READ_P95_BUDGET, "dashboard p95 over budget"
    assert duress.writes.pct(95) <= WRITE_SLOWDOWN_LIMIT * duress.writes_alone.pct(95), (
        "the steady spread slowed the write door past twice its own p95"
    )


@skip_unless_gated
def test_the_dashboard_beats_the_road_it_replaced_on_the_same_rig(
    engine: Engine, context: Context
) -> None:
    """Before and after on one rig, one run, the same duress: readers building the findings
    rollup (the old road), then readers on the dashboard query. The dashboard holds its bar
    and is at least ten times faster at p95; nothing it serves fails."""
    seconds = int(os.environ.get("TRAUST_PERF_SECONDS", "60"))
    before = run_duress(engine, context, seconds=seconds, rollup=True)
    after = run_duress(engine, context, seconds=seconds)
    print("before - the findings rollup:\n" + before.report())
    print("after - the dashboard query:\n" + after.report())
    assert after.reads.failures == 0
    assert after.reads.pct(95) < READ_P95_BUDGET
    assert after.reads.pct(95) * 10 < before.reads.pct(95), "not ten times faster at p95"
