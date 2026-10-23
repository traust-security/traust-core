"""OpsService order lifecycle (submit, claim, heartbeat, complete, approve, requeue) and
SpendService rollups and budget verdicts, on SQLite and Postgres."""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    Budget,
    BudgetStatus,
    JobResult,
    LaneName,
    OrderRequest,
    OrderState,
    Outcome,
    RunOrder,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    WorkerId,
)
from traust_core.v1.models.vocabulary import ActorKind, BudgetEnforcement
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import OpsService, SpendService

LEASE = timedelta(minutes=5)
W1, W2 = WorkerId("w1"), WorkerId("w2")
OPERATOR = Principal(identity="operator@example.com", kind=ActorKind("human"), display="operator")
RESULTS = {
    Outcome.SUCCEEDED: JobResult.succeeded(),
    Outcome.DEGRADED: JobResult.partly({"unreachable": 2}),
    Outcome.REFUSED: JobResult.refused("diff-too-large"),
    Outcome.FAILED: JobResult.failed("runner-crashed"),
}


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def ops(engine: Engine, at: timedelta = timedelta()) -> OpsService:
    return OpsService(SqlTraustUnitOfWork(engine), FixedClock(T0 + at))


def seeded(engine: Engine, **kw: Any) -> RunOrder:
    with SqlTraustUnitOfWork(engine) as uow:
        order = Seed(uow).run_order(**kw)
        uow.commit()
    return order


def stored(engine: Engine, order: RunOrder) -> RunOrder:
    assert order.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.run_orders.get(order.id)


def leased(engine: Engine, worker: WorkerId = W1) -> RunOrder:
    seeded(engine)
    order = ops(engine).claim(worker, LEASE)
    assert order is not None
    return order


def test_submit_queues_the_asset_for_its_requester(engine: Engine) -> None:
    order = ops(engine).submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
    assert stored(engine, order) == order
    assert (order.asset, order.lane, order.state) == ("feeds_cache", None, OrderState.QUEUED)
    assert order.requested_by == f"human:{OPERATOR.identity}"


def test_submit_refuses_an_order_both_routed_and_injected(engine: Engine) -> None:
    request = OrderRequest(asset="diff_scan", priority=1, rule="rule-4", event_source="cve")
    with pytest.raises(ConflictError):
        ops(engine).submit(request, OPERATOR)


def test_claim_leases_the_next_order_and_none_when_the_queue_is_empty(engine: Engine) -> None:
    service = ops(engine)
    assert service.claim(W1, LEASE) is None
    queued = seeded(engine)
    order = service.claim(W1, LEASE)
    assert order is not None and order.id == queued.id
    assert (order.state, order.lease_holder, order.started_at) == (OrderState.LEASED, W1, T0)
    assert service.claim(W2, LEASE) is None


def test_heartbeat_extends_the_holders_lease(engine: Engine) -> None:
    order = leased(engine)
    renewed = ops(engine, timedelta(minutes=4)).heartbeat(order.id, W1, LEASE)
    assert renewed.lease_expires_at == T0 + timedelta(minutes=9)
    assert stored(engine, order).lease_expires_at == renewed.lease_expires_at


@pytest.mark.parametrize(
    ("worker", "at"),
    [(W2, timedelta()), (W1, LEASE + timedelta(seconds=1))],
    ids=["another worker", "expired lease"],
)
def test_heartbeat_is_refused(engine: Engine, worker: WorkerId, at: timedelta) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).heartbeat(order.id, worker, LEASE)
    assert stored(engine, order).lease_expires_at == T0 + LEASE


def test_heartbeat_refuses_an_order_that_is_not_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).heartbeat(order.id, W1, LEASE)


def test_unknown_orders_are_not_found(engine: Engine) -> None:
    service, missing = ops(engine), uuid4()
    with pytest.raises(NotFoundError):
        service.heartbeat(missing, W1, LEASE)
    with pytest.raises(NotFoundError):
        service.complete(missing, W1, JobResult.succeeded())
    with pytest.raises(NotFoundError):
        service.approve(missing, OPERATOR)


@pytest.mark.parametrize("outcome", list(Outcome))
def test_complete_finishes_the_order_with_its_outcome(engine: Engine, outcome: Outcome) -> None:
    order = leased(engine)
    result = RESULTS[outcome]
    done = ops(engine, timedelta(minutes=2)).complete(order.id, W1, result)
    assert stored(engine, order) == done
    assert (done.state, done.reason) == (OrderState(outcome), result.reason)
    assert (done.lease_holder, done.lease_expires_at) == (None, None)
    assert (done.started_at, done.finished_at) == (T0, T0 + timedelta(minutes=2))


def test_complete_retried_with_the_same_outcome_changes_nothing(engine: Engine) -> None:
    order = leased(engine)
    done = ops(engine).complete(order.id, W1, JobResult.succeeded())
    assert ops(engine, timedelta(minutes=1)).complete(order.id, W1, JobResult.succeeded()) == done


def test_complete_refuses_a_second_different_outcome(engine: Engine) -> None:
    order = leased(engine)
    ops(engine).complete(order.id, W1, JobResult.succeeded())
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W1, JobResult.failed("late"))
    assert stored(engine, order).state == OrderState.SUCCEEDED


def test_complete_refuses_a_worker_that_does_not_hold_the_lease(engine: Engine) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W2, JobResult.succeeded())
    assert stored(engine, order).state == OrderState.LEASED


def test_complete_refuses_an_order_that_was_never_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W1, JobResult.succeeded())
    assert stored(engine, order).state == OrderState.QUEUED


def test_complete_accepts_an_expired_lease_the_reaper_has_not_taken(engine: Engine) -> None:
    order = leased(engine)
    done = ops(engine, LEASE + timedelta(minutes=1)).complete(order.id, W1, JobResult.succeeded())
    assert done.state == OrderState.SUCCEEDED


def test_complete_after_the_reaper_requeued_is_refused(engine: Engine) -> None:
    order = leased(engine)
    later = ops(engine, LEASE + timedelta(seconds=1))
    assert later.requeue_expired() == 1
    with pytest.raises(ConflictError):
        later.complete(order.id, W1, JobResult.succeeded())


def test_approve_queues_an_order_awaiting_approval(engine: Engine) -> None:
    order = seeded(engine, state="awaiting_approval")
    approved = ops(engine).approve(order.id, OPERATOR)
    assert approved.state == stored(engine, order).state == OrderState.QUEUED


@pytest.mark.parametrize("state", ["planned", "queued", "withheld", "succeeded"])
def test_approve_refuses_an_order_not_awaiting_approval(engine: Engine, state: str) -> None:
    order = seeded(engine, state=state)
    with pytest.raises(ConflictError):
        ops(engine).approve(order.id, OPERATOR)
    assert stored(engine, order).state == state


def test_requeue_expired_returns_lapsed_leases_and_keeps_live_ones(engine: Engine) -> None:
    lapsed = leased(engine, W1)
    live = seeded(engine)
    ops(engine, LEASE).claim(W2, LEASE)
    service = ops(engine, LEASE + timedelta(seconds=1))
    assert service.requeue_expired() == 1
    assert (stored(engine, lapsed).state, stored(engine, live).state) == (
        OrderState.QUEUED,
        OrderState.LEASED,
    )
    assert service.requeue_expired() == 0
    reclaimed = service.claim(W1, LEASE)
    assert reclaimed is not None and reclaimed.id == lapsed.id


@pytest.mark.integration
def test_ten_concurrent_claimers_never_lease_the_same_order(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    orders = {seeded(engine, priority=i).id for i in range(7)}
    start, got = threading.Barrier(10), []

    def claimer(n: int) -> None:
        start.wait()
        got.append(ops(engine).claim(WorkerId(f"w{n}"), LEASE))

    threads = [threading.Thread(target=claimer, args=(n,)) for n in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    claimed = [o.id for o in got if o is not None]
    assert sorted(map(str, claimed)) == sorted(map(str, orders))
    assert got.count(None) == 3


AUDIT = LaneName("full-audit")
OCTOBER = TimeWindow.month_of(T0)


def spend(engine: Engine, *budgets: Budget, at: timedelta = timedelta()) -> SpendService:
    return SpendService(SqlTraustUnitOfWork(engine), FixedClock(T0 + at), budgets)


def audit_budget(enforcement: str, monthly: str = "10") -> Budget:
    return Budget(
        lane=AUDIT, monthly_usd=Decimal(monthly), enforcement=BudgetEnforcement(enforcement)
    )


def spent(engine: Engine, usd: str, lane: str | None = AUDIT, **kw: Any) -> SpendEvent:
    order = seeded(engine, lane=lane) if lane else None
    values = {"provider": "anthropic", "model": "claude", "tokens_in": 100, "tokens_out": 20}
    event = SpendEvent(
        **{**values, "occurred_at": T0, **kw},
        run_order_id=order.id if order else None,
        cost_usd=Decimal(usd),
    )
    return spend(engine).record(event)


def test_record_saves_spend_with_database_identity(engine: Engine) -> None:
    saved = spent(engine, "1.25")
    assert saved.id is not None and saved.created_at is not None
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.spend_events.get(saved.id) == saved


def test_record_stamps_the_orders_lane(engine: Engine) -> None:
    assert (spent(engine, "1.00").lane, spent(engine, "1.00", lane=None).lane) == (AUDIT, None)
    order = seeded(engine, lane="diff-scan")
    claimed = SpendEvent(
        run_order_id=order.id,
        lane="full-audit",
        provider="anthropic",
        model="claude",
        tokens_in=1,
        tokens_out=1,
        cost_usd=Decimal("0.01"),
        occurred_at=T0,
    )
    assert spend(engine).record(claimed).lane == "diff-scan"


def test_summary_rolls_up_by_lane(engine: Engine) -> None:
    spent(engine, "2.00")
    spent(engine, "0.50", lane="diff-scan")
    spent(engine, "0.25", lane=None)
    rollups = spend(engine).summary(SpendFilter(window=OCTOBER), SpendDimension.LANE)
    assert [(r.key, r.cost_usd) for r in rollups] == [
        ("diff-scan", Decimal("0.50")),
        ("full-audit", Decimal("2.00")),
        (None, Decimal("0.25")),
    ]


def test_attribution_splits_spend_without_losing_any(engine: Engine) -> None:
    spent(engine, "3.00")
    spent(engine, "0.75", lane=None)
    spent(engine, "9.00", occurred_at=OCTOBER.end)
    split = spend(engine).attribute(OCTOBER)
    assert (split.attributed_usd, split.unattributed_usd) == (Decimal("3.00"), Decimal("0.75"))
    (total,) = spend(engine).summary(SpendFilter(window=OCTOBER), SpendDimension.MONTH)
    assert split.total_usd == total.cost_usd


def test_attribution_of_an_empty_window_is_zero_measured_spend(engine: Engine) -> None:
    split = spend(engine).attribute(OCTOBER)
    assert (split.attributed_usd, split.unattributed_usd) == (Decimal(0), Decimal(0))


@pytest.mark.parametrize(
    ("estimate", "status"),
    [("1.99", BudgetStatus.WITHIN), ("2.01", BudgetStatus.OVER)],
)
def test_check_budget_judges_month_to_date_lane_spend(
    engine: Engine, estimate: str, status: BudgetStatus
) -> None:
    spent(engine, "8.00")
    spent(engine, "50.00", lane="diff-scan")
    spent(engine, "50.00", lane=None)
    spent(engine, "50.00", occurred_at=OCTOBER.start - timedelta(microseconds=1000))
    verdict = spend(engine, audit_budget("advisory")).check_budget(AUDIT, Decimal(estimate))
    assert (verdict.status, verdict.spent_usd, verdict.budget_usd) == (
        status,
        Decimal("8.00"),
        Decimal("10"),
    )


def test_check_budget_uses_the_clocks_month(engine: Engine) -> None:
    spent(engine, "8.00")
    november = OCTOBER.end - T0
    verdict = spend(engine, audit_budget("advisory"), at=november).check_budget(AUDIT, Decimal(5))
    assert (verdict.status, verdict.spent_usd) == (BudgetStatus.WITHIN, Decimal(0))


@pytest.mark.parametrize("enforcement", ["none", "observe"])
def test_check_budget_never_binds_outside_enforcement(engine: Engine, enforcement: str) -> None:
    spent(engine, "50.00")
    verdict = spend(engine, audit_budget(enforcement)).check_budget(AUDIT, Decimal(1))
    assert (verdict.status, verdict.binding) == (BudgetStatus.OVER, False)


def test_check_budget_without_a_budget_reports_spend_and_never_binds(engine: Engine) -> None:
    spent(engine, "50.00")
    verdict = spend(engine).check_budget(AUDIT, None)
    assert (verdict.status, verdict.spent_usd, verdict.enforcement, verdict.binding) == (
        BudgetStatus.NO_BUDGET,
        Decimal("50.00"),
        None,
        False,
    )


def test_check_budget_logs_an_overrun_as_a_warning(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    spent(engine, "50.00")
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.operations"):
        spend(engine, audit_budget("observe")).check_budget(AUDIT, Decimal(1))
    assert [r.levelno for r in caplog.records if "budget" in r.message] == [logging.WARNING]


def test_two_budgets_for_one_lane_are_refused(engine: Engine) -> None:
    with pytest.raises(ConfigError):
        spend(engine, audit_budget("observe"), audit_budget("advisory", "20"))
