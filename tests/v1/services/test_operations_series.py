"""OpsService.schedule and timeline, SpendService.collect, on SQLite and Postgres."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_operations import OPERATOR, ops, seeded, seeded_repository
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.common import PageRequest, TimeBucket, TimeWindow
from traust_core.v1.models.operations import (
    AssetName,
    ModelUsage,
    OrderFilter,
    OrderState,
    SchedulePlan,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendSource,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.model_catalog import TokenUsage
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import SpendService

DAY = timedelta(days=1)
VIEWS = (AssetName("view:findings-rollup"), AssetName("view:program"))
FEEDS = AssetName("feeds_cache")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_schedule_queues_one_order_per_asset_for_the_requester(engine: Engine) -> None:
    batch = _batch(engine)
    plan = SchedulePlan(assets=VIEWS, priority=3, run_batch_id=batch)
    orders = ops(engine).schedule(plan, OPERATOR)
    assert [(o.asset, o.state, o.priority, o.lane, o.run_batch_id) for o in orders] == [
        (a, OrderState.QUEUED, 3, None, batch) for a in VIEWS
    ]
    assert {o.requested_by for o in orders} == {OPERATOR.ref}


def test_schedule_again_keeps_the_open_orders(engine: Engine) -> None:
    first = ops(engine).schedule(SchedulePlan(assets=VIEWS[:1], priority=3), OPERATOR)
    again = ops(engine).schedule(SchedulePlan(assets=VIEWS, priority=1), OPERATOR)
    assert again[0] == first[0]
    assert again[1].asset == VIEWS[1] and again[1].priority == 1


def test_schedule_again_does_not_claim_existing_orders_as_new(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    plan = SchedulePlan(assets=VIEWS[:1], priority=3)
    logger = logging.getLogger("traust_core.v1.services.operations")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            first = ops(engine).schedule(plan, OPERATOR)
            assert "scheduled 1 orders" in caplog.text
            caplog.clear()
            assert ops(engine).schedule(plan, OPERATOR) == first
            assert "scheduled" not in caplog.text
        finally:
            logger.removeHandler(caplog.handler)


def test_schedule_after_a_finished_order_queues_a_new_one(engine: Engine) -> None:
    done = seeded(engine, asset=VIEWS[0], state="succeeded", finished_at=T0)
    [order] = ops(engine).schedule(SchedulePlan(assets=VIEWS[:1], priority=3), OPERATOR)
    assert order.id != done.id and order.state is OrderState.QUEUED


def test_schedule_keeps_subjects_apart(engine: Engine) -> None:
    fleet = ops(engine).schedule(SchedulePlan(assets=VIEWS[:1], priority=3), OPERATOR)
    repo = seeded_repository(engine)
    plan = SchedulePlan(assets=VIEWS[:1], priority=3, repository_id=repo)
    [scoped] = ops(engine).schedule(plan, OPERATOR)
    assert scoped.id != fleet[0].id and scoped.repository_id == repo


@pytest.mark.parametrize(
    ("assets", "error"),
    [((VIEWS[0], VIEWS[0]), "names an asset twice"), ((), "at least 1")],
)
def test_schedule_refuses_a_malformed_plan(
    engine: Engine, assets: tuple[AssetName, ...], error: str
) -> None:
    with pytest.raises((ValidationError, ValueError), match=error):
        ops(engine).schedule(SchedulePlan(assets=assets, priority=1), OPERATOR)


def finished(engine: Engine, state: str, at: datetime, asset: str = FEEDS, **kw: Any) -> None:
    seeded(engine, asset=asset, state=state, finished_at=at, **kw)


def test_timeline_counts_finished_orders_per_bucket_by_outcome(engine: Engine) -> None:
    finished(engine, "succeeded", T0 + timedelta(hours=1))
    finished(engine, "succeeded", T0 + timedelta(hours=23))
    finished(engine, "failed", T0 + DAY)
    finished(engine, "degraded", T0 + 2 * DAY + timedelta(hours=5))
    finished(engine, "succeeded", T0 + 3 * DAY)  # past the window
    finished(engine, "succeeded", T0 - timedelta(seconds=1))  # before it
    finished(engine, "succeeded", T0 + timedelta(hours=2), asset="dashboards")
    seeded(engine, asset=FEEDS, state="queued")
    window = TimeWindow(start=T0, end=T0 + 3 * DAY)
    points = ops(engine).timeline(OrderFilter(asset=FEEDS, window=window), TimeBucket.DAY)
    assert [(p.bucket, p.finished[OrderState.SUCCEEDED], p.total) for p in points] == [
        (T0, 2, 2),
        (T0 + DAY, 0, 1),
        (T0 + 2 * DAY, 0, 1),
    ]
    assert points[1].finished[OrderState.FAILED] == 1
    assert set(points[0].finished) == {
        OrderState.SUCCEEDED,
        OrderState.DEGRADED,
        OrderState.REFUSED,
        OrderState.WITHHELD,
        OrderState.FAILED,
    }


def test_timeline_narrows_by_outcome_subject_and_batch(engine: Engine) -> None:
    repo = seeded_repository(engine)
    batch = _batch(engine)
    finished(engine, "succeeded", T0, repository_id=repo, run_batch_id=batch)
    finished(engine, "failed", T0, repository_id=repo)
    finished(engine, "succeeded", T0)
    window = TimeWindow.month_of(T0)
    cases = {
        OrderFilter(asset=FEEDS, window=window, states=(OrderState.FAILED,)): 1,
        OrderFilter(asset=FEEDS, window=window, repository_id=repo): 2,
        OrderFilter(asset=FEEDS, window=window, run_batch_id=batch): 1,
    }
    for filter, total in cases.items():
        [point] = ops(engine).timeline(filter, TimeBucket.MONTH)
        assert point.total == total, filter


def test_timeline_has_a_point_for_every_bucket_even_with_no_orders(engine: Engine) -> None:
    window = TimeWindow(start=T0 + DAY, end=T0 + 15 * DAY)  # a Tuesday, two weeks on
    points = ops(engine).timeline(OrderFilter(asset=FEEDS, window=window), TimeBucket.WEEK)
    assert [p.bucket for p in points] == [T0, T0 + 7 * DAY, T0 + 14 * DAY]
    assert all(p.total == 0 for p in points)


@pytest.mark.parametrize(
    ("filter", "error"),
    [
        (OrderFilter(window=TimeWindow.month_of(T0)), "needs an asset and a window"),
        (OrderFilter(asset=FEEDS), "needs an asset and a window"),
        (
            OrderFilter(asset=FEEDS, window=TimeWindow.month_of(T0), states=(OrderState.QUEUED,)),
            "counts finished orders",
        ),
    ],
)
def test_timeline_refuses_an_unbounded_or_unfinished_query(
    engine: Engine, filter: OrderFilter, error: str
) -> None:
    with pytest.raises(ValidationError, match=error):
        ops(engine).timeline(filter, TimeBucket.DAY)


def test_list_refuses_a_window(engine: Engine) -> None:
    filter = OrderFilter(states=(OrderState.QUEUED,), window=TimeWindow.month_of(T0))
    with pytest.raises(ValidationError, match="window bounds a timeline"):
        ops(engine).list(filter, PageRequest())


class PerRequestPrices:
    """$1 per thousand fresh tokens, a tenth for cache reads, $5 per request over 1000 in."""

    def __init__(self) -> None:
        self.priced: list[TokenUsage] = []

    def check(self) -> Any:
        raise AssertionError

    def resolve(self, name: Any) -> Any:
        raise AssertionError

    def cost(self, model: Any, usage: TokenUsage) -> Decimal:
        self.priced.append(usage)
        fresh = usage.tokens_in + usage.tokens_out + usage.cache_creation
        long_prompt = Decimal(5) if usage.tokens_in > 1000 else Decimal(0)
        return Decimal(fresh) / 1000 + Decimal(usage.cache_read) / 10000 + long_prompt


def collector(engine: Engine, now: datetime = T0 + 3 * DAY) -> tuple[SpendService, Any]:
    prices = PerRequestPrices()
    return SpendService(SqlTraustUnitOfWork(engine), FixedClock(now), lambda: (), prices), prices


def usage(
    at: datetime, tokens_in: int = 500, model: str = "claude-sonnet", **kw: Any
) -> ModelUsage:
    values = {"provider": "anthropic", "tokens_out": 500}
    return ModelUsage(**{**values, **kw}, model=model, occurred_at=at, tokens_in=tokens_in)


def events(engine: Engine) -> list[SpendEvent]:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.spend_events.list_between(T0 - 30 * DAY, T0 + 30 * DAY)


def test_collect_records_one_unattributed_event_per_day_and_model(engine: Engine) -> None:
    source = SpendSource(
        name="sessions",
        usages=(
            usage(T0 + timedelta(hours=1)),
            usage(T0 + timedelta(hours=9), tokens_in=2000, cache_read=10000),
            usage(T0 + timedelta(hours=2), model="claude-opus"),
            usage(T0 + DAY + timedelta(hours=3)),
        ),
    )
    service, prices = collector(engine)
    assert service.collect(source, TimeWindow(start=T0, end=T0 + 3 * DAY)) == 3
    assert sorted(
        (e.occurred_at, e.model, e.tokens_in, e.tokens_out, e.cost_usd, e.run_order_id, e.skill)
        for e in events(engine)
    ) == [
        (T0, "claude-opus", 500, 500, Decimal(1), None, None),
        (T0, "claude-sonnet", 2500, 1000, Decimal("9.5"), None, None),
        (T0 + DAY, "claude-sonnet", 500, 500, Decimal(1), None, None),
    ]
    assert len(prices.priced) == 4  # each request priced on its own (long prompts)


def test_collect_again_adds_nothing(engine: Engine) -> None:
    source = SpendSource(name="sessions", usages=(usage(T0), usage(T0 + DAY)))
    window = TimeWindow(start=T0, end=T0 + 2 * DAY)
    assert collector(engine)[0].collect(source, window) == 2
    assert collector(engine)[0].collect(source, window) == 0
    assert collector(engine)[0].collect(source, TimeWindow.month_of(T0)) == 0
    assert len(events(engine)) == 2


def test_collect_skips_today_and_days_the_window_only_partly_covers(engine: Engine) -> None:
    source = SpendSource(
        name="sessions",
        usages=(
            usage(T0 - timedelta(hours=1)),
            usage(T0 + timedelta(hours=13)),  # its day starts before the window
            usage(T0 + DAY + timedelta(hours=1)),
            usage(T0 + 3 * DAY + timedelta(hours=1)),  # today: not over yet
        ),
    )
    window = TimeWindow(start=T0 + timedelta(hours=12), end=T0 + 10 * DAY)
    service, _ = collector(engine, now=T0 + 3 * DAY + timedelta(hours=2))
    assert service.collect(source, window) == 1
    assert [e.occurred_at for e in events(engine)] == [T0 + DAY]


def test_collect_leaves_declared_and_order_spend_alone(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.spend_event(model="claude-sonnet", occurred_at=T0, skill="triage")
        order = seed.run_order()
        seed.spend_event(model="claude-sonnet", occurred_at=T0, run_order_id=order.id)
        uow.commit()
    source = SpendSource(name="sessions", usages=(usage(T0),))
    assert collector(engine)[0].collect(source, TimeWindow.month_of(T0)) == 1
    split = collector(engine)[0].attribute(TimeWindow.month_of(T0))
    assert split.unattributed_usd == Decimal("0.25") + Decimal(1)


def test_collect_of_nothing_writes_nothing(engine: Engine) -> None:
    assert collector(engine)[0].collect(SpendSource(name="sessions"), TimeWindow.month_of(T0)) == 0


def test_collect_needs_a_model_catalog(engine: Engine) -> None:
    service = SpendService(SqlTraustUnitOfWork(engine), FixedClock(T0), lambda: ())
    with pytest.raises(ConfigError, match="register_model_catalog"):
        service.collect(SpendSource(name="sessions"), TimeWindow.month_of(T0))


def test_collected_spend_rolls_up_by_model(engine: Engine) -> None:
    source = SpendSource(name="sessions", usages=(usage(T0), usage(T0 + DAY, model="claude-opus")))
    service, _ = collector(engine)
    service.collect(source, TimeWindow.month_of(T0))
    rollups = service.summary(SpendFilter(window=TimeWindow.month_of(T0)), SpendDimension.MODEL)
    assert [(r.key, r.events) for r in rollups] == [("claude-opus", 1), ("claude-sonnet", 1)]


def _batch(engine: Engine) -> Any:
    with SqlTraustUnitOfWork(engine) as uow:
        batch = Seed(uow).run_batch()
        uow.commit()
    return batch.id
