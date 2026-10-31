"""4 · Operations repositories: the run-order queue, spend windows and feed freshness."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed, apart, repository_for
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    LaneName,
    RunOrder,
    SpendDimension,
    SpendFilter,
    SpendRollup,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

LEASE = timedelta(minutes=5)


def test_claim_takes_priority_then_age_and_skips_non_queued(seed: Seed) -> None:
    orders = seed.uow.run_orders
    seed.run_order(state="planned", priority=0)
    seed.run_order(state="succeeded", priority=0)
    later = seed.run_order(priority=5)
    soon_old = seed.run_order(priority=1)
    seed.uow.commit()  # separate transactions: distinct created_at on Postgres
    apart()
    soon_new = seed.run_order(priority=1)
    claimed = [orders.claim(f"w{i}", T0, LEASE) for i in range(4)]
    assert [c.id if c else None for c in claimed] == [soon_old.id, soon_new.id, later.id, None]


def test_claim_records_the_lease(seed: Seed) -> None:
    order = seed.run_order()
    claimed = seed.uow.run_orders.claim("worker-1", T0, LEASE)
    assert claimed is not None and claimed.id == order.id
    assert (claimed.state, claimed.lease_holder) == ("leased", "worker-1")
    assert claimed.lease_expires_at == T0 + LEASE
    assert claimed.updated_at >= order.updated_at


def test_claim_selected_id_only_leases_that_queued_order(seed: Seed) -> None:
    orders = seed.uow.run_orders
    other = seed.run_order(priority=1)
    selected = seed.run_order(priority=9)
    planned = seed.run_order(state="planned")
    assert orders.claim("w1", T0, LEASE, order_id=planned.id) is None
    claimed = orders.claim("w1", T0, LEASE, order_id=selected.id)
    assert claimed is not None and claimed.id == selected.id
    assert orders.claim("w2", T0, LEASE, order_id=selected.id) is None
    assert orders.get(other.id).state == "queued"
    assert orders.get(planned.id).state == "planned"


def test_claim_stamps_when_work_started(seed: Seed) -> None:
    seed.run_order()
    claimed = seed.uow.run_orders.claim("worker-1", T0, LEASE)
    assert claimed is not None and claimed.started_at == T0


def test_get_for_update_reads_the_order_and_refuses_unknown_ids(seed: Seed) -> None:
    order = seed.run_order(asset="feeds_cache", lane=None)
    assert seed.uow.run_orders.get_for_update(order.id) == order
    with pytest.raises(NotFoundError):
        seed.uow.run_orders.get_for_update(uuid4())


def test_expired_leases_return_to_the_queue(seed: Seed) -> None:
    orders = seed.uow.run_orders
    expired, live = seed.run_order(priority=1), seed.run_order(priority=2)
    orders.claim("w1", T0, LEASE)
    orders.claim("w2", T0 + LEASE, LEASE)
    assert orders.requeue_expired(T0 + LEASE + timedelta(seconds=1)) == 1
    released = orders.get(expired.id)
    assert (released.state, released.lease_holder, released.lease_expires_at) == (
        "queued",
        None,
        None,
    )
    assert orders.get(live.id).state == "leased"


def test_orders_by_batch_and_by_repository_state(seed: Seed) -> None:
    orders = seed.uow.run_orders
    batch, repo = seed.run_batch(), seed.repository()
    in_batch = seed.run_order(run_batch_id=batch.id)
    planned = seed.run_order(repository_id=repo.id, state="planned", priority=2)
    urgent = seed.run_order(repository_id=repo.id, state="planned", priority=1)
    seed.run_order(repository_id=repo.id)
    assert orders.list_for_batch(batch.id) == [in_batch]
    assert orders.list_for_repository(repo.id, "planned") == [urgent, planned]


def test_one_batch_per_kind_and_period(seed: Seed) -> None:
    batch = seed.run_batch(kind="drain_tranche", period="2026-W31")
    assert seed.uow.run_batches.find("drain_tranche", "2026-W31") == batch
    assert seed.uow.run_batches.find("router_run", "2026-W31") is None


def test_spend_by_order_and_half_open_window(seed: Seed) -> None:
    spend = seed.uow.spend_events
    order = seed.run_order()
    start = seed.spend_event(run_order_id=order.id, occurred_at=T0)
    inside = seed.spend_event(occurred_at=T0 + timedelta(hours=23))
    seed.spend_event(occurred_at=T0 + timedelta(days=1))  # end is exclusive
    assert spend.list_for_order(order.id) == [start]
    assert spend.list_between(T0, T0 + timedelta(days=1)) == [start, inside]


OCTOBER = TimeWindow.month_of(T0)


def rollup(key: str | None, events: int, usd: str) -> SpendRollup:
    return SpendRollup(
        key=key,
        events=events,
        tokens_in=100 * events,
        tokens_out=20 * events,
        cost_usd=Decimal(usd),
    )


def test_spend_sums_by_lane_with_unrouted_and_unattributed_as_no_lane(seed: Seed) -> None:
    audit, diff = seed.run_order(lane="full-audit"), seed.run_order(lane="diff-scan")
    unrouted = seed.run_order(asset="feeds_cache")
    seed.spend_event(run_order_id=audit.id, lane="full-audit", cost_usd=Decimal("1.10"))
    seed.spend_event(run_order_id=audit.id, lane="full-audit", cost_usd=Decimal("2.20"))
    seed.spend_event(run_order_id=diff.id, lane="diff-scan", cost_usd=Decimal("0.30"))
    seed.spend_event(run_order_id=unrouted.id, cost_usd=Decimal("0.40"))
    seed.spend_event(cost_usd=Decimal("0.50"))
    assert seed.uow.spend_events.sum_by(SpendFilter(window=OCTOBER), SpendDimension.LANE) == [
        rollup("diff-scan", 1, "0.30"),
        rollup("full-audit", 2, "3.30"),
        rollup(None, 2, "0.90"),
    ]


def test_spend_sums_by_utc_month_model_and_skill(seed: Seed) -> None:
    spend = seed.uow.spend_events
    year = TimeWindow(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2027, 1, 1, tzinfo=UTC))
    late_sept = datetime(2026, 10, 1, 1, tzinfo=timezone(timedelta(hours=3)))  # 22:00 UTC, Sept
    seed.spend_event(occurred_at=late_sept, model="opus", skill="triage")
    seed.spend_event(occurred_at=T0, model="opus")
    seed.spend_event(occurred_at=T0, model="haiku", skill="triage")
    assert spend.sum_by(SpendFilter(window=year), SpendDimension.MONTH) == [
        rollup("2026-09", 1, "0.25"),
        rollup("2026-10", 2, "0.50"),
    ]
    assert spend.sum_by(SpendFilter(window=year), SpendDimension.MODEL) == [
        rollup("haiku", 1, "0.25"),
        rollup("opus", 2, "0.50"),
    ]
    assert spend.sum_by(SpendFilter(window=year), SpendDimension.SKILL) == [
        rollup("triage", 2, "0.50"),
        rollup(None, 1, "0.25"),
    ]


def test_spend_total_filters_by_window_lane_and_attribution(seed: Seed) -> None:
    spend = seed.uow.spend_events
    audit, diff = seed.run_order(lane="full-audit"), seed.run_order(lane="diff-scan")
    seed.spend_event(run_order_id=audit.id, lane="full-audit", cost_usd=Decimal("1.00"))
    seed.spend_event(
        run_order_id=audit.id, lane="full-audit", occurred_at=OCTOBER.end, cost_usd=Decimal("9.00")
    )
    seed.spend_event(run_order_id=diff.id, lane="diff-scan", cost_usd=Decimal("0.10"))
    seed.spend_event(cost_usd=Decimal("0.01"))
    lane = LaneName("full-audit")
    assert spend.sum_by(SpendFilter(window=OCTOBER)) == [rollup(None, 3, "1.11")]
    assert spend.sum_by(SpendFilter(window=OCTOBER, lane=lane)) == [rollup(None, 1, "1.00")]
    assert spend.sum_by(SpendFilter(window=OCTOBER, attributed=False)) == [rollup(None, 1, "0.01")]
    assert spend.sum_by(SpendFilter(window=OCTOBER, attributed=True)) == [rollup(None, 2, "1.10")]


def test_spend_sums_are_empty_without_spend(seed: Seed) -> None:
    spend = seed.uow.spend_events
    seed.spend_event(occurred_at=OCTOBER.end)
    assert spend.sum_by(SpendFilter(window=OCTOBER)) == []
    assert spend.sum_by(SpendFilter(window=OCTOBER), SpendDimension.LANE) == []
    assert spend.sum_by(SpendFilter(window=OCTOBER, lane=LaneName("full-audit"))) == []


def test_spend_sums_keep_decimal_cents(seed: Seed) -> None:
    for _ in range(10):
        seed.spend_event(cost_usd=Decimal("0.10"))
    (total,) = seed.uow.spend_events.sum_by(SpendFilter(window=OCTOBER))
    assert total.cost_usd == Decimal("1.00")


def test_latest_feed_snapshot_by_retrieval_time(seed: Seed) -> None:
    feeds = seed.uow.feed_snapshots
    assert feeds.latest("osv") is None
    new = seed.feed_snapshot(feed="osv", retrieved_at=T0 + timedelta(days=1))
    seed.feed_snapshot(feed="osv", retrieved_at=T0)
    seed.feed_snapshot(feed="epss", retrieved_at=T0 + timedelta(days=9))
    assert feeds.latest("osv") == new


def test_assessment_inputs_link_results_to_snapshots(seed: Seed) -> None:
    inputs = seed.uow.assessment_inputs
    snapshot, assessment = seed.feed_snapshot(), seed.assessment()
    link = seed.assessment_input(assessment, snapshot)
    assert inputs.list_for_assessment(assessment.id) == [link]
    assert inputs.list_for_snapshot(snapshot.id) == [link]


@pytest.mark.integration
def test_concurrent_workers_never_claim_the_same_order(engine: Engine) -> None:
    """Postgres row locks: an uncommitted lease is skipped, not waited on or doubled."""
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite serialises writers; concurrency is a Postgres property")
    with SqlTraustUnitOfWork(engine) as setup:
        seed = Seed(setup)
        first, second = seed.run_order(priority=1), seed.run_order(priority=2)
        setup.commit()
    with SqlTraustUnitOfWork(engine) as a, SqlTraustUnitOfWork(engine) as b:
        got_a = a.run_orders.claim("a", T0, LEASE)
        got_b = b.run_orders.claim("b", T0, LEASE)  # a's lease is not committed yet
        assert got_a is not None and got_b is not None
        assert {got_a.id, got_b.id} == {first.id, second.id}
        a.commit()
        b.commit()


def test_find_open_matches_asset_and_subject_and_skips_finished(seed: Seed) -> None:
    orders, repo = seed.uow.run_orders, seed.repository()
    seed.run_order(asset="diff_scan", repository_id=repo.id, state="succeeded")
    assert orders.find_open("diff_scan", repo.id) is None
    mine = seed.run_order(asset="diff_scan", repository_id=repo.id, state="planned")
    seed.run_order(asset="repo_state", repository_id=repo.id, state="queued")
    fleet = seed.run_order(
        asset="diff_scan", state="leased", lease_holder="w1", lease_expires_at=T0
    )
    assert orders.find_open("diff_scan", repo.id) == mine
    assert orders.find_open("diff_scan", None) == fleet
    assert orders.find_open("feeds_cache", None) is None


def test_search_combines_filters_and_pages_by_age(seed: Seed) -> None:
    orders, repo = seed.uow.run_orders, seed.repository()
    batch = seed.run_batch()
    old = seed.run_order(asset="diff_scan", repository_id=repo.id, run_batch_id=batch.id)
    seed.uow.commit()
    apart()
    new = seed.run_order(asset="diff_scan", repository_id=repo.id, run_batch_id=batch.id)
    seed.run_order(asset="diff_scan", repository_id=repo.id, state="failed")
    seed.run_order(asset="repo_state", repository_id=repo.id)
    hits = orders.search(
        states=("queued",), asset="diff_scan", repository_id=repo.id, run_batch_id=batch.id, limit=5
    )
    assert hits == [new, old]
    assert orders.search(states=("queued",), asset="diff_scan", limit=1) == [new]
    assert new.created_at is not None and new.id is not None
    after = orders.search(
        states=("queued",), asset="diff_scan", limit=5, after=(new.created_at, new.id)
    )
    assert after == [old]


FEED = ("succeeded", "refused", "awaiting_approval")


def touched_together(seed: Seed, *orders: RunOrder) -> list[RunOrder]:
    """One UPDATE gives the orders one updated_at (the statement time on Postgres)."""
    table = repository_for(seed.uow, "run_order").table
    ids = [o.id for o in orders if o.id]
    seed.uow.connection.execute(sa.update(table).where(table.c.id.in_(ids)).values(updated_at=T0))
    return sorted((seed.uow.run_orders.get(i) for i in ids), key=lambda o: str(o.id))


def test_feed_after_reads_orders_in_states_by_change_oldest_first(seed: Seed) -> None:
    orders = seed.uow.run_orders
    assert orders.feed_after(None, FEED, 10) == []
    done = seed.run_order(state="succeeded")
    apart()
    seed.run_order(state="queued")
    held = seed.run_order(state="awaiting_approval")
    apart()
    refused = seed.run_order(state="refused", reason="diff-too-large")
    assert orders.feed_after(None, FEED, 10) == [done, held, refused]
    assert orders.feed_after(None, FEED, 2) == [done, held]
    assert held.updated_at is not None and held.id is not None
    assert orders.feed_after((held.updated_at, held.id), FEED, 10) == [refused]


def test_feed_after_moves_a_changed_order_behind_later_changes(seed: Seed) -> None:
    orders = seed.uow.run_orders
    held = seed.run_order(state="awaiting_approval")
    apart()
    done = seed.run_order(state="succeeded")
    apart()
    refused = orders.update(held.model_copy(update={"state": "refused"}))
    assert orders.feed_after(None, FEED, 10) == [done, refused]


def test_feed_after_breaks_ties_by_id_and_resumes_just_after_the_cursor(seed: Seed) -> None:
    orders = seed.uow.run_orders
    tied = touched_together(seed, *(seed.run_order(state="succeeded") for _ in range(3)))
    assert len({o.updated_at for o in tied}) == 1
    assert orders.feed_after(None, FEED, 10) == tied
    first, last = tied[0], tied[-1]
    assert first.updated_at is not None and first.id is not None
    assert orders.feed_after((first.updated_at, first.id), FEED, 10) == tied[1:]
    assert last.updated_at is not None and last.id is not None
    assert orders.feed_after((last.updated_at, last.id), FEED, 10) == []


def test_last_routed_is_the_newest_routed_orders_creation(seed: Seed) -> None:
    orders = seed.uow.run_orders
    assert orders.last_routed() is None
    seed.run_order(lane="diff-scan")
    apart()
    newest = seed.run_order(lane="full-audit", state="succeeded")
    apart()
    seed.run_order(asset="feeds_cache")
    assert orders.last_routed() == newest.created_at
