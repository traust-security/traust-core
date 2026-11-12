"""Insight views at a year's volume: a whole-portfolio dashboard read is a bounded batch of
round trips, not one per repository (the dashboard 504s at SCI's 30s timeout when it is)."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from time import perf_counter

import pytest
from sqlalchemy.engine import Engine

from perf.harness import Explained, _issued, explain
from perf.seed import REPOSITORIES
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.models.insight import ViewFilter, ViewName


@pytest.fixture(scope="session")
def context(engine: Engine) -> Iterator[Context]:
    with tempfile.TemporaryDirectory() as home:
        yield Context(
            Config(
                home=Path(home),
                database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
            )
        )


Profiled = Callable[[ViewName], tuple[list[Explained], float]]


@pytest.fixture
def profiled(context: Context, report: list, request: pytest.FixtureRequest) -> Profiled:
    def run(view: ViewName) -> tuple[list[Explained], float]:
        with _issued(context.database) as statements:
            start = perf_counter()
            context.services().insight.build(view, ViewFilter())
            wall_ms = (perf_counter() - start) * 1000
        with context.database.connect() as conn:
            found = [explain(conn, sql, params) for sql, params in statements]
        report.extend((request.node.name, e) for e in found)
        return found, wall_ms

    return run


def test_rollup_trend_and_patterns_read_the_whole_scope_in_bounded_batches(
    profiled: Profiled, clock_rows: list[tuple[str, str, float]], request: pytest.FixtureRequest
) -> None:
    for view in (ViewName.FINDINGS_ROLLUP, ViewName.FINDINGS_TREND, ViewName.INSECURE_PATTERNS):
        statements, wall_ms = profiled(view)
        # fewer round trips than the seed has repositories: a read that degrades into one
        # per repository (the dashboard timeouts) crosses this at once
        assert len(statements) < REPOSITORIES, len(statements)
        assert all(e.execution_ms < 1_000 for e in statements), [e.key_line for e in statements]
        clock_rows.append((request.node.name, f"build({view.value})", wall_ms))


def test_a_stored_census_serve_reads_the_build_and_the_freshness_bound_only(
    context: Context, report: list, request: pytest.FixtureRequest, clock_rows: list
) -> None:
    # wave (d)'s serving path: the newest artifact row, one person-statement read, and the
    # cached parse — never the fold's whole-scope reads (the 72-134s cold path this replaces)
    context.services().insight.record_builds()

    with _issued(context.database) as statements:
        start = perf_counter()
        served = context.services().insight.serve(ViewName.FINDINGS_ROLLUP, ViewFilter())
        wall_ms = (perf_counter() - start) * 1000
    assert served.built_at is not None
    assert len(statements) <= 3, [sql for sql, _ in statements]
    with context.database.connect() as conn:
        found = [explain(conn, sql, params) for sql, params in statements]
    report.extend((request.node.name, e) for e in found)
    for e in found:
        assert e.execution_ms < 1_000, e.key_line
    clock_rows.append((request.node.name, "serve(findings-rollup, stored)", wall_ms))
