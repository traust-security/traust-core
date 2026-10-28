"""Settling an order's measured usage as spend when it completes (same transaction as the order's
state), and lane costs from settled orders, on SQLite and Postgres."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from tests.v1.services.test_operations import (
    LEASE,
    W1,
    W2,
    manifest,
    publisher,
    seeded,
    stored,
)
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    SPEND_UNPRICED,
    JobResult,
    LaneCost,
    ModelName,
    ModelUsage,
    OrderState,
    ProviderName,
    RunOrder,
    SkillName,
    SpendEvent,
    WorkerId,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.model_catalog import ModelCatalog, TokenUsage
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import OpsService, SpendService

REGISTRY = Path(__file__).parents[2] / "fixtures" / "operations" / "model-registry.yaml"
AUDIT = "full-audit"
WEEK = TimeWindow(start=T0 - timedelta(days=7), end=T0 + timedelta(days=1))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture(scope="module")
def catalog(tmp_path_factory: pytest.TempPathFactory) -> ModelCatalog:
    ctx = Context(Config(home=tmp_path_factory.mktemp("home")))
    ctx.register_model_catalog(REGISTRY)
    assert ctx.model_catalog is not None
    return ctx.model_catalog


def settling(engine: Engine, catalog: ModelCatalog | None) -> OpsService:
    uow, clock = SqlTraustUnitOfWork(engine), FixedClock(T0 + timedelta(minutes=3))
    spend = SpendService(uow, clock, lambda: (), catalog)
    return OpsService(uow, clock, publisher(engine), spend=spend)


def usage(model: str, tokens_in: int = 10**6, tokens_out: int = 0, **kw: Any) -> ModelUsage:
    values: dict[str, Any] = {"occurred_at": T0, "skill": SkillName("secure-code-audit")}
    return ModelUsage(
        provider=ProviderName("anthropic"),
        model=ModelName(model),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        **{**values, **kw},
    )


def ran(*usages: ModelUsage) -> JobResult:
    return JobResult.succeeded().model_copy(update={"usage": usages})


def leased_in(engine: Engine, lane: str | None = AUDIT, worker: WorkerId = W1) -> RunOrder:
    order = seeded(engine, lane=lane, state="leased", lease_holder=worker,
                   lease_expires_at=T0 + LEASE, started_at=T0)  # fmt: skip
    assert order.id is not None
    return order


def recorded(engine: Engine, order: RunOrder | None = None) -> list[SpendEvent]:
    with SqlTraustUnitOfWork(engine) as uow:
        if order is not None:
            assert order.id is not None
            return uow.spend_events.list_for_order(order.id)
        return uow.spend_events.list_between(T0 - timedelta(days=365), WEEK.end)


def test_complete_settles_one_event_per_model_in_the_orders_lane(
    engine: Engine, catalog: ModelCatalog
) -> None:
    order = leased_in(engine)
    result = ran(
        usage("claude-opus-5-5", tokens_out=10**6, cache_read=10**6, cache_creation=10**6),
        usage("claude-haiku-5-5", tokens_in=1000, tokens_out=1000),
    )
    done = settling(engine, catalog).complete(order.id, W1, result)
    assert stored(engine, order) == done and done.state == OrderState.SUCCEEDED
    events = sorted(recorded(engine, order), key=lambda e: e.model)
    assert [(e.model, e.lane, e.skill, e.run_order_id) for e in events] == [
        ("claude-haiku-5-5", AUDIT, "secure-code-audit", order.id),
        ("claude-opus-5-5", AUDIT, "secure-code-audit", order.id),
    ]
    # haiku 1k in at $0.1 + 1k out at $0.5; opus 1M in $4 + 1M out $20 + cache read $0.2 + write $5
    assert [e.cost_usd for e in events] == [Decimal("0.0006"), Decimal("29.2")]
    assert [(e.tokens_in, e.tokens_out) for e in events] == [(1000, 1000), (10**6, 10**6)]
    assert done.artifact_id is None  # nothing unpriced, nothing degraded


def test_usage_of_one_model_and_skill_settles_as_one_event(
    engine: Engine, catalog: ModelCatalog
) -> None:
    order = leased_in(engine)
    later = T0 + timedelta(minutes=1)
    settling(engine, catalog).complete(
        order.id,
        W1,
        ran(
            usage("claude-opus-5-5"),
            usage("claude-opus-5-5", occurred_at=later),
            usage("claude-opus-5-5", skill=SkillName("threat-model")),
        ),
    )
    events = sorted(recorded(engine, order), key=lambda e: e.skill or "")
    assert [(e.skill, e.tokens_in, e.cost_usd, e.occurred_at) for e in events] == [
        ("secure-code-audit", 2 * 10**6, Decimal(8), later),
        ("threat-model", 10**6, Decimal(4), T0),
    ]


def test_an_order_without_a_lane_settles_without_one(engine: Engine, catalog: ModelCatalog) -> None:
    order = leased_in(engine, lane=None)
    settling(engine, catalog).complete(order.id, W1, ran(usage("claude-opus-5-5")))
    assert [(e.lane, e.cost_usd) for e in recorded(engine, order)] == [(None, Decimal(4))]


@pytest.mark.parametrize(
    "result",
    [JobResult.failed("runner-crashed"), JobResult.partly({"unreachable": 1})],
    ids=["failed", "degraded"],
)
def test_a_run_that_did_not_succeed_still_settles_what_it_spent(
    engine: Engine, catalog: ModelCatalog, result: JobResult
) -> None:
    order = leased_in(engine)
    with_usage = result.model_copy(update={"usage": (usage("claude-opus-5-5"),)})
    done = settling(engine, catalog).complete(order.id, W1, with_usage)
    assert done.state == OrderState(result.outcome)
    assert [e.cost_usd for e in recorded(engine, order)] == [Decimal(4)]


def test_a_run_without_usage_settles_nothing(engine: Engine, catalog: ModelCatalog) -> None:
    order = leased_in(engine)
    assert (
        settling(engine, catalog).complete(order.id, W1, JobResult.succeeded()).artifact_id is None
    )
    assert recorded(engine) == []


def test_completing_again_adds_no_spend(engine: Engine, catalog: ModelCatalog) -> None:
    order = leased_in(engine)
    result = ran(usage("claude-opus-5-5"))
    done = settling(engine, catalog).complete(order.id, W1, result)
    assert settling(engine, catalog).complete(order.id, W1, result) == done
    with pytest.raises(ConflictError):
        settling(engine, catalog).complete(
            order.id, W1, JobResult.failed("late").model_copy(update={"usage": result.usage})
        )
    assert len(recorded(engine, order)) == 1


def test_a_refused_completion_records_no_spend(engine: Engine, catalog: ModelCatalog) -> None:
    order = leased_in(engine)
    with pytest.raises(ConflictError):
        settling(engine, catalog).complete(order.id, W2, ran(usage("claude-opus-5-5")))
    assert stored(engine, order).state == OrderState.LEASED
    assert recorded(engine) == []


class Negative:
    """A catalog whose price the database refuses (cost_usd >= 0): the spend insert fails."""

    def cost(self, model: ModelName, usage: TokenUsage) -> Decimal:
        return Decimal(-1)


def test_spend_the_database_refuses_rolls_the_completion_back(engine: Engine) -> None:
    order = leased_in(engine)
    with pytest.raises(ConflictError):
        settling(engine, Negative()).complete(order.id, W1, ran(usage("claude-opus-5-5")))  # type: ignore[arg-type]
    assert stored(engine, order).state == OrderState.LEASED
    assert recorded(engine) == []


def test_without_a_model_registry_the_order_completes_and_the_gap_is_recorded(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    order = leased_in(engine)
    result = ran(usage("claude-opus-5-5"), usage("claude-haiku-5-5"))
    done = settling(engine, None).complete(order.id, W1, result)
    assert done.state == OrderState.SUCCEEDED
    assert recorded(engine) == []
    assert manifest(engine, order)["degraded"] == {SPEND_UNPRICED: 2}
    assert SPEND_UNPRICED in caplog.text and "count=2" in caplog.text
    assert "claude-opus-5-5" not in caplog.text


def test_a_model_the_registry_cannot_price_is_a_gap_and_the_rest_settles(
    engine: Engine, catalog: ModelCatalog
) -> None:
    order = leased_in(engine)
    result = JobResult.partly({"unreachable": 1}).model_copy(
        update={
            "usage": (
                usage("claude-opus-5-5"),
                usage("claude-unknown"),
                usage("claude-unpriced"),
            )
        }
    )
    done = settling(engine, catalog).complete(order.id, W1, result)
    assert done.state == OrderState.DEGRADED
    assert [e.model for e in recorded(engine, order)] == ["claude-opus-5-5"]
    assert manifest(engine, order)["degraded"] == {"unreachable": 1, SPEND_UNPRICED: 2}


def test_the_context_wires_settlement_to_the_registered_registry(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_model_catalog(REGISTRY)
    services = ctx.services()
    with SqlTraustUnitOfWork(ctx.database) as uow:
        uow.run_orders.add(
            RunOrder(asset="audit", state=OrderState.QUEUED, priority=1, requested_by="user:me")
        )
        uow.commit()
    order = services.ops.claim(W1, LEASE)
    assert order is not None and order.id is not None
    services.ops.complete(order.id, W1, ran(usage("claude-opus-5-5")))
    with SqlTraustUnitOfWork(ctx.database) as uow:
        (event,) = uow.spend_events.list_for_order(order.id)
    assert event.cost_usd == Decimal(4)


def test_two_orders_completed_at_once_each_settle_their_own_spend(
    engine: Engine, catalog: ModelCatalog
) -> None:
    orders = [leased_in(engine, worker=W1), leased_in(engine, lane="diff-scan", worker=W2)]
    results = [ran(usage("claude-opus-5-5")), ran(usage("claude-haiku-5-5", tokens_in=1000))]
    start, failures = threading.Barrier(2), []

    def complete(order: RunOrder, worker: WorkerId, result: JobResult) -> None:
        start.wait()
        try:
            settling(engine, catalog).complete(order.id, worker, result)
        except Exception as e:
            failures.append(e)

    threads = [
        threading.Thread(target=complete, args=args)
        for args in zip(orders, (W1, W2), results, strict=True)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert failures == []
    assert [stored(engine, o).state for o in orders] == [OrderState.SUCCEEDED] * 2
    assert [[(e.lane, e.model, e.cost_usd) for e in recorded(engine, o)] for o in orders] == [
        [(AUDIT, "claude-opus-5-5", Decimal(4))],
        [("diff-scan", "claude-haiku-5-5", Decimal("0.0001"))],
    ]


def spent(engine: Engine, lane: str | None, *costs: str, **kw: Any) -> None:
    """One order in `lane` with one spend event per cost (None lane, no order: unattributed)."""
    with SqlTraustUnitOfWork(engine) as uow:
        order = uow.run_orders.add(
            RunOrder(
                asset="audit", state="succeeded", priority=1, requested_by="user:me", lane=lane
            )
        )
        for cost in costs:
            uow.spend_events.add(
                SpendEvent(
                    run_order_id=order.id if kw.get("attributed", True) else None,
                    lane=lane if kw.get("attributed", True) else None,
                    provider="anthropic",
                    model="claude-opus-5-5",
                    tokens_in=1,
                    tokens_out=1,
                    cost_usd=Decimal(cost),
                    occurred_at=kw.get("at", T0),
                )
            )
        uow.commit()


def lane_costs(engine: Engine) -> list[LaneCost]:
    return SpendService(SqlTraustUnitOfWork(engine), FixedClock(T0), lambda: ()).lane_costs(WEEK)


def test_lane_costs_are_the_median_settled_cost_per_order(engine: Engine) -> None:
    spent(engine, AUDIT, "1.00", "2.00")  # one order of two events: $3
    spent(engine, AUDIT, "5.00")
    spent(engine, AUDIT, "4.00")
    spent(engine, "diff-scan", "0.40")
    spent(engine, "diff-scan", "0.60")
    assert lane_costs(engine) == [
        LaneCost(lane="diff-scan", orders=2, events=2, median_usd=Decimal("0.50")),
        LaneCost(lane=AUDIT, orders=3, events=4, median_usd=Decimal("4.00")),
    ]


def test_lane_costs_count_only_settled_orders_in_the_window(engine: Engine) -> None:
    spent(engine, AUDIT, "2.00")
    spent(engine, AUDIT, "9.00", at=WEEK.end)  # after the window
    spent(engine, AUDIT, "9.00", at=WEEK.start - timedelta(seconds=1))  # before it
    spent(engine, AUDIT, "9.00", attributed=False)  # workstation spend, no order
    spent(engine, None, "9.00")  # an order with no lane
    spent(engine, AUDIT)  # an order that recorded no spend
    assert lane_costs(engine) == [
        LaneCost(lane=AUDIT, orders=1, events=1, median_usd=Decimal("2.00"))
    ]


def test_lane_costs_of_an_empty_window_are_empty(engine: Engine) -> None:
    assert lane_costs(engine) == []


def test_a_job_result_carries_its_usage_across_the_runner_boundary() -> None:
    result = ran(usage("claude-opus-5-5", cache_read=7, session="s-1"))
    assert JobResult.model_validate_json(result.model_dump_json()) == result
