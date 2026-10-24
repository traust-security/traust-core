"""The findings trend, program and triage views through Context, on SQLite and Postgres."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_triage_view import TRIAGE
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.findings import FindingSeriesPoint
from traust_core.v1.models.insight import (
    FindingsTrend,
    ProgramMetrics,
    TriageDocument,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.operations import OrderState
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
from traust_core.v1.services.insight import TriageView, _summed

HUMAN = "human:analyst@example.com"
DAY = timedelta(days=1)
WEEK = TimeWindow(start=T0, end=T0 + 14 * DAY)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def seed_findings(engine: Engine) -> Any:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product(slug="alpha", name="Alpha")
        svc = seed.repository(url="https://github.com/example-org/svc")
        api = seed.repository(url="https://github.com/example-org/api")
        seed.repository(url="https://github.com/example-org/quiet")
        svc_ref = seed.repository_ref(svc)
        seed.component(seed.release(product), svc_ref)
        early = seed.assessment(svc_ref, occurred_at=T0)
        fixed = seed.finding(svc, title="Fixed later")
        seed.occurrence(fixed, early, severity="critical")
        seed.decision(
            fixed,
            validity="confirmed",
            resolution="resolved",
            actor=HUMAN,
            occurred_at=T0 + 9 * DAY,
        )
        later = seed.assessment(seed.repository_ref(api), occurred_at=T0 + 8 * DAY)
        seed.occurrence(seed.finding(api, title="Found later"), later, severity="high")
        uow.commit()
    return product


def opened(p: FindingSeriesPoint) -> dict[Severity, int]:
    return {s: n for s, n in p.open_by_severity.items() if n}


def test_the_trend_sums_each_repositorys_series_to_now(context: Context, engine: Engine) -> None:
    seed_findings(engine)
    trend = context.services().insight.build(
        ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK)
    )
    assert isinstance(trend, FindingsTrend)
    assert (trend.as_of, trend.repositories) == (T0 + 20 * DAY, 3)
    assert [(p.bucket, opened(p), p.new, p.resolved, p.mttr_days) for p in trend.points] == [
        (T0, {Severity.CRITICAL: 1}, 1, 0, None),
        (T0 + 7 * DAY, {Severity.HIGH: 1}, 1, 1, 9.0),
        (T0 + 14 * DAY, {Severity.HIGH: 1}, 0, 0, None),
    ]


def test_the_trend_follows_scope_point_in_time_and_window(context: Context, engine: Engine) -> None:
    product = seed_findings(engine)
    insight = context.services().insight
    scoped = insight.build(
        ViewName.FINDINGS_TREND, ViewFilter(product_ids=(product.id,), bucket=TimeBucket.WEEK)
    )
    assert scoped.repositories == 1  # type: ignore[attr-defined]
    assert [p.resolved for p in scoped.points] == [0, 1, 0]  # type: ignore[attr-defined]
    earlier = insight.build(
        ViewName.FINDINGS_TREND, ViewFilter(as_of=T0 + 2 * DAY, bucket=TimeBucket.WEEK)
    )
    assert [opened(p) for p in earlier.points] == [{Severity.CRITICAL: 1}]  # type: ignore[attr-defined]
    windowed = insight.build(
        ViewName.FINDINGS_TREND,
        ViewFilter(window=TimeWindow(start=T0 + 7 * DAY, end=T0 + 14 * DAY), bucket="week"),
    )
    assert [p.bucket for p in windowed.points] == [T0 + 7 * DAY]  # type: ignore[attr-defined]
    md = insight.publish(ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK)).markdown
    assert "| 2026-10-12 | 0 | 1 |" in md


def test_an_empty_trend_says_so(context: Context) -> None:
    rendered = context.services().insight.publish(ViewName.FINDINGS_TREND, ViewFilter())
    assert rendered.model.points == ()  # type: ignore[attr-defined]
    assert "_No findings reported in scope._" in rendered.markdown


def point(resolved: int, mttr: float | None, risk: float = 1.0, **open_by: int) -> Any:
    return FindingSeriesPoint(
        bucket=T0,
        open_by_severity={Severity(k): v for k, v in open_by.items()},
        new=1,
        resolved=resolved,
        accepted=1,
        hardening=0,
        false_positives=0,
        regressions=1,
        mttr_days=mttr,
        risk_index=risk,
    )


@pytest.mark.parametrize(
    ("points", "mttr", "risk", "open_by"),
    [
        ([point(1, 2.0, high=1), point(3, 6.0, high=2, low=1)], 5.0, 2.0, {"high": 3, "low": 1}),
        ([point(0, None), point(2, 4.0)], 4.0, 2.0, {}),
        ([point(0, None, 0.25), point(0, None, 0.3)], None, 0.6, {}),
    ],
)
def test_summing_series_weights_mttr_by_resolutions(
    points: list[Any], mttr: float | None, risk: float, open_by: dict[str, int]
) -> None:
    summed = _summed(T0, points)
    assert (summed.mttr_days, summed.risk_index) == (mttr, risk)
    assert dict(summed.open_by_severity) == {Severity(k): v for k, v in open_by.items()}
    assert (summed.new, summed.regressions, summed.accepted) == (len(points),) * 3


def seed_program(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        audit = seed.run_order(asset="audit", lane="full-audit", state="succeeded", finished_at=T0)
        seed.run_order(asset="audit", state="failed", finished_at=T0 + 8 * DAY)
        seed.run_order(asset="audit", state="queued")
        seed.spend_event(run_order_id=audit.id, lane="full-audit", skill="audit", cost_usd=2)
        seed.spend_event(model="claude-opus", cost_usd=Decimal("0.5"), occurred_at=T0 + DAY)
        seed.spend_event(cost_usd=9, occurred_at=WEEK.end)  # past the window
        uow.commit()


def test_the_program_view_derives_spend_and_throughput_over_the_window(
    context: Context, engine: Engine
) -> None:
    seed_program(engine)
    for asset in ("feeds_cache", "audit"):
        context.assets.register(asset, lambda: None)  # type: ignore[arg-type, return-value]
    model = context.services().insight.build(
        ViewName.PROGRAM, ViewFilter(window=WEEK, bucket=TimeBucket.WEEK)
    )
    assert isinstance(model, ProgramMetrics)
    assert (model.spend.attributed_usd, model.spend.unattributed_usd) == (2, Decimal("0.5"))
    assert [(r.key, r.cost_usd) for r in model.by_model] == [
        ("claude", 2),
        ("claude-opus", Decimal("0.5")),
    ]
    assert [(r.key, r.events) for r in model.by_lane] == [("full-audit", 1), (None, 1)]
    assert [(r.key, r.events) for r in model.by_skill] == [("audit", 1), (None, 1)]
    assert [r.key for r in model.by_month] == ["2026-10"]
    assert list(model.throughput) == ["audit", "feeds_cache"]
    assert [
        (p.bucket, p.finished[OrderState.SUCCEEDED], p.finished[OrderState.FAILED])
        for p in model.throughput["audit"]
    ] == [(T0, 1, 0), (T0 + 7 * DAY, 0, 1)]
    assert [p.total for p in model.throughput["feeds_cache"]] == [0, 0]


def test_the_program_report_and_its_empty_sections(context: Context, engine: Engine) -> None:
    insight = context.services().insight
    empty = insight.publish(ViewName.PROGRAM, ViewFilter(window=WEEK)).markdown
    assert "_No spend._" in empty and "_No assets registered._" in empty
    seed_program(engine)
    context.assets.register("audit", lambda: None)  # type: ignore[arg-type, return-value]
    md = insight.publish(ViewName.PROGRAM, ViewFilter(window=WEEK)).markdown
    assert "$2.50 spent, $2.00 on run orders and $0.50 no order claims" in md
    assert "| audit | 2026-10-01 | 1 | 0 | 0 | 0 | 1 |" in md


def test_the_program_view_needs_a_window(context: Context) -> None:
    with pytest.raises(ValidationError, match="needs a window"):
        context.services().insight.build(ViewName.PROGRAM, ViewFilter())


def published_triage(context: Context, engine: Engine) -> Any:
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(TriageArtifact)), context.object_store, SqlTraustUnitOfWork(engine)
    )
    doc = TriageArtifact.from_document(json.loads(TRIAGE.read_text()))
    return publisher.publish_artifact(doc).artifact_id


def test_the_triage_view_renders_a_stored_triage(context: Context, engine: Engine) -> None:
    artifact_id = published_triage(context, engine)
    rendered = context.services().insight.publish(
        ViewName.TRIAGE, ViewFilter(artifact_id=artifact_id)
    )
    assert isinstance(rendered.model, TriageDocument)
    assert rendered.model.artifact_id == artifact_id
    direct = TriageView().report(TriageArtifact.parse(rendered.model.payload.encode()))
    assert rendered.markdown.startswith("# Triage Report")
    assert direct.title == "Triage Report"


@pytest.mark.parametrize(
    ("view", "filter", "error"),
    [
        (TriageView(), ViewFilter(artifact_id=uuid4()), ConfigError),
        (TriageView(), ViewFilter(), ValidationError),
    ],
)
def test_the_triage_view_needs_a_document_and_a_reader(
    view: TriageView, filter: ViewFilter, error: type[Exception]
) -> None:
    with pytest.raises(error):
        view.build(filter)


def test_refresh_of_every_view_leaves_single_item_renders_out(
    context: Context, engine: Engine
) -> None:
    result = context.services().insight.refresh(None, ViewFilter(window=WEEK))
    assert ViewName.TRIAGE not in {*result.rendered, *result.failed}
    assert {ViewName.FINDINGS_ROLLUP, ViewName.FINDINGS_TREND, ViewName.PROGRAM} <= set(
        result.rendered
    )


def test_a_triage_report_is_dated_by_completion(context: Context, engine: Engine) -> None:
    artifact_id = published_triage(context, engine)
    report = context.services().insight.report(
        ViewName.TRIAGE, ViewFilter(artifact_id=artifact_id, as_of=datetime(2030, 1, 1))
    )
    assert report.generated_at.year != 2030
