"""Insight views at a year's volume: a whole-portfolio dashboard read is a bounded batch of
round trips, not one per repository (the dashboard 504s at SCI's 30s timeout when it is)."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from uuid import UUID

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from perf.harness import _issued, explain
from perf.seed import HOT_REPOSITORY, REPOSITORIES
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework

# The spend view prices against a model registry; the seed's spend reads need one wired.
FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
REGISTRY = FIXTURES / "operations" / "model-registry.yaml"
SLA_POLICY = FIXTURES / "insight" / "sla-policy.yaml"
ATTACK_TECHNIQUES = FIXTURES / "insight" / "attack" / "attack-techniques.json"
ATTACK_MAPPING = FIXTURES / "insight" / "attack" / "attack-mapping.json"

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


@pytest.fixture(scope="session")
def context(engine: Engine) -> Iterator[Context]:
    with tempfile.TemporaryDirectory() as home:
        found = Context(
            Config(
                home=Path(home),
                database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
            )
        )
        found.register_model_catalog(REGISTRY)
        found.register_default_sla_policy(SLA_POLICY)
        found.register_attack_catalog(ATTACK_TECHNIQUES, ATTACK_MAPPING)
        yield found


@pytest.fixture(scope="session")
def hot_repository(engine: Engine) -> UUID:
    with engine.connect() as conn:
        return conn.execute(
            sa.text("SELECT id FROM traust.repository WHERE url = :url"), {"url": HOT_REPOSITORY}
        ).scalar_one()


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
    assert all(e.execution_ms < 1_000 for e in found), [e.key_line for e in found]
    clock_rows.append((request.node.name, f"build({view.value})", wall_ms))
