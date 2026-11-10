"""Insight views at a year's volume: a whole-portfolio dashboard read is a bounded batch of
round trips, not one per repository (the dashboard 504s at SCI's 30s timeout when it is)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from time import perf_counter
from uuid import UUID

import pytest

from perf.harness import _issued, explain
from perf.seed import REPOSITORIES
from traust_core.v1.context import Context
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework

NOW = datetime.now(UTC)
YEAR = TimeWindow(start=NOW - timedelta(days=365), end=NOW)

# The seed builds no object-store artifacts, and some views need recorded inputs it does not
# carry; every other registered view is gated.
CANNOT_BUILD: Mapping[ViewName, str] = {
    ViewName.CONTAINER_FINDINGS: "renders one container assessment's stored report",
    ViewName.TRIAGE: "renders one published triage document",
    ViewName.OSCAL: "exports one recorded compliance artifact",
    ViewName.INVENTORY_EXPORT: "the whole-scope export exceeds the view's record budget",
    ViewName.CRITICAL_MISSES: "a month at seed volume exceeds the view's record budget",
    ViewName.BENCHMARK_SCORECARDS: "no benchmark answer key recorded",
    ViewName.PQC_VENDORS: "no curated vendor claims recorded",
}


def _filter_for(view: ViewName, hot_repository: UUID) -> ViewFilter:
    if view in (ViewName.SPEND, ViewName.PROGRAM):
        return ViewFilter(window=YEAR)
    if view is ViewName.CRITICAL_MISSES:
        return ViewFilter(window=TimeWindow.month_of(NOW))  # its window is capped at 31 days
    if view is ViewName.SARIF:
        return ViewFilter(repository_id=hot_repository)
    if view is ViewName.COMPLIANCE_PRECISION:
        return ViewFilter(framework=ComplianceFramework.NIST_800_53_REV5)
    return ViewFilter()


@pytest.mark.parametrize(
    "view", [n for n in ViewName if n not in CANNOT_BUILD], ids=lambda n: n.value
)
def test_every_view_builds_a_whole_scope_read_in_bounded_batches(
    view: ViewName,
    context: Context,
    hot_repository: UUID,
    clock_rows: list[tuple[str, str, float]],
    report: list,
    request: pytest.FixtureRequest,
) -> None:
    with _issued(context.database) as statements:
        start = perf_counter()
        context.services().insight.build(view, _filter_for(view, hot_repository))
        wall_ms = (perf_counter() - start) * 1000
    # fewer round trips than the seed has repositories: a read that degrades into one per
    # repository (the dashboard timeouts) crosses this at once — before any plan is run
    assert len(statements) < REPOSITORIES, [sql for sql, _ in statements[:3]]
    with context.database.connect() as conn:
        found = [explain(conn, sql, params) for sql, params in statements]
    report.extend((request.node.name, e) for e in found)
    # 2s, not 1s: the nightly gate runs on a cold CI database, where a month-window spend
    # join over 3M events can take over a second on its first plan
    assert all(e.execution_ms < 2_000 for e in found), [e.key_line for e in found]
    clock_rows.append((request.node.name, f"build({view.value})", wall_ms))
