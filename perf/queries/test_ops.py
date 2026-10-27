"""4 · Operations queries at volume: the engine and runners issue these every tick and claim."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from perf.harness import Explained, Profile
from perf.seed import TYPICAL_REPOSITORY
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    FEED_ORDER_STATES,
    FINISHED_ORDER_STATES,
    OPEN_ORDER_STATES,
    LaneName,
    OrderState,
    SpendDimension,
    SpendFilter,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

NOW = datetime.now(UTC)
LEASE = timedelta(minutes=5)


def fast(e: Explained, index: str, budget_ms: float) -> None:
    assert e.uses_index(index), e.plan
    assert not e.seq_scans(), e.plan
    assert e.execution_ms < budget_ms, e.plan


def test_claim_takes_the_queue_head_by_index(explained: Profile) -> None:
    lease, reread = explained(lambda uow: uow.run_orders.claim("perf", NOW, LEASE))
    fast(lease, "idx_ops_run_order_claim", 5)
    fast(reread, "run_order_pkey", 1)


def test_claim_of_some_assets_walks_the_queue_head_by_index(explained: Profile) -> None:
    assets = ("feeds_cache", "repo_state", "ledger_audit")
    lease, *_ = explained(lambda uow: uow.run_orders.claim("perf", NOW, LEASE, assets))
    fast(lease, "idx_ops_run_order_claim", 5)


def test_order_lock_is_a_primary_key_lookup(explained: Profile) -> None:
    def lock(uow: SqlTraustUnitOfWork) -> None:
        (order,) = uow.run_orders.list_for_batch(_any_batch(uow))[:1]
        assert order.id is not None
        uow.run_orders.get_for_update(order.id)

    *_, locked = explained(lock)
    fast(locked, "run_order_pkey", 1)


def test_reaper_finds_expired_leases_by_index(explained: Profile) -> None:
    (requeue,) = explained(lambda uow: uow.run_orders.requeue_expired(NOW))
    fast(requeue, "idx_ops_run_order_lease", 5)


def test_a_tranches_orders_by_index(explained: Profile) -> None:
    *_, listed = explained(lambda uow: uow.run_orders.list_for_batch(_any_batch(uow)))
    fast(listed, "idx_ops_run_order_batch", 100)


def test_a_repositorys_open_orders_by_index(explained: Profile) -> None:
    def open_orders(uow: SqlTraustUnitOfWork) -> None:
        repo = uow.repositories.find_by_url("https://forge.example/org/r1")
        assert repo is not None and repo.id is not None
        uow.run_orders.list_for_repository(repo.id, OrderState.QUEUED)

    *_, listed = explained(open_orders)
    fast(listed, "idx_ops_run_order_repository_state", 1)


def _any_batch(uow: SqlTraustUnitOfWork) -> UUID:
    batch = uow.run_batches.find("drain_tranche", "2026-W01")
    assert batch is not None and batch.id is not None
    return batch.id


MONTH = TimeWindow.month_of(NOW)


def test_month_to_date_spend_reads_the_window_by_index(explained: Profile) -> None:
    (total,) = explained(lambda uow: uow.spend_events.sum_by(SpendFilter(window=MONTH)))
    fast(total, "idx_ops_spend_event_occurred", 200)


def test_a_lanes_month_to_date_spend_reads_its_lane_by_index(explained: Profile) -> None:
    lane = SpendFilter(window=MONTH, lane=LaneName("full-audit"))
    (total,) = explained(lambda uow: uow.spend_events.sum_by(lane))
    fast(total, "idx_ops_spend_event_lane_occurred", 100)


def test_spend_by_lane_and_by_month(explained: Profile) -> None:
    (by_lane,) = explained(
        lambda uow: uow.spend_events.sum_by(SpendFilter(window=MONTH), SpendDimension.LANE)
    )
    fast(by_lane, "idx_ops_spend_event_occurred", 500)
    year = TimeWindow(start=NOW - timedelta(days=365), end=NOW)
    (by_month,) = explained(
        lambda uow: uow.spend_events.sum_by(SpendFilter(window=year), SpendDimension.MONTH)
    )
    assert by_month.execution_ms < 2000, by_month.plan


def test_the_open_order_for_a_repositorys_asset_by_index(explained: Profile) -> None:
    def find(uow: SqlTraustUnitOfWork) -> None:
        repo = uow.repositories.find_by_url(TYPICAL_REPOSITORY)
        assert repo is not None and repo.id is not None
        uow.run_orders.find_open("audit", repo.id)

    *_, found = explained(find)
    indexes = ("idx_ops_run_order_repository_state", "idx_ops_run_order_asset_state")
    assert any(found.uses_index(i) for i in indexes), found.plan
    assert not found.seq_scans() and found.execution_ms < 1, found.plan


@pytest.mark.parametrize("subject", ["fleet", "page"])
def test_an_assets_open_orders_by_index(explained: Profile, subject: str) -> None:
    def read(uow: SqlTraustUnitOfWork) -> object:
        if subject == "fleet":
            return uow.run_orders.find_open("feeds_cache", None)
        return uow.run_orders.search(states=OPEN_ORDER_STATES, asset="diff_scan", limit=101)

    (found,) = explained(read)
    fast(found, "idx_ops_run_order_asset_state", 5)


# The estate grows slowly (~10k repositories): a top-N sort over the table stays ~1 ms.
def test_a_page_of_repositories(explained: Profile) -> None:
    (page,) = explained(lambda uow: uow.repositories.search(limit=101, after=None))
    assert page.execution_ms < 20, page.plan


@pytest.mark.parametrize("states", ["open", "finished this month"])
def test_an_assets_subjects_are_index_only(explained: Profile, states: str) -> None:
    def read(uow: SqlTraustUnitOfWork) -> object:
        if states == "open":
            return uow.run_orders.subjects("diff_scan", OPEN_ORDER_STATES)
        done = (OrderState.SUCCEEDED, OrderState.DEGRADED, OrderState.REFUSED, OrderState.FAILED)
        return uow.run_orders.subjects("repo_state", done, NOW - timedelta(days=30))

    (found,) = explained(read)
    fast(found, "idx_ops_run_order_asset_state", 20)


def test_an_assets_stale_stops_in_a_window_read_its_index(explained: Profile) -> None:
    (found,) = explained(
        lambda uow: uow.run_orders.subjects(
            "diff_scan", (OrderState.WITHHELD,), NOW - timedelta(days=1), "upstream-stale"
        )
    )
    fast(found, "idx_ops_run_order_asset_state", 20)


def test_an_assets_throughput_over_a_month_is_index_only(explained: Profile) -> None:
    (found,) = explained(
        lambda uow: uow.run_orders.finished_between(
            "repo_state", FINISHED_ORDER_STATES, NOW - timedelta(days=30), NOW
        )
    )
    fast(found, "idx_ops_run_order_asset_state", 50)


def test_spend_by_repository_joins_the_month_to_its_orders_by_key(explained: Profile) -> None:
    (by_repository,) = explained(
        lambda uow: uow.spend_events.sum_by(SpendFilter(window=MONTH), SpendDimension.REPOSITORY)
    )
    fast(by_repository, "idx_ops_spend_event_occurred", 500)


@pytest.mark.parametrize("since", ["a minute ago", "a day ago", "the start"])
def test_the_feeds_orders_after_a_cursor_by_index(explained: Profile, since: str) -> None:
    """A consumer polls from its last event; the engine catches up a day after a restart."""
    after = {
        "a minute ago": (NOW - timedelta(minutes=1), UUID(int=0)),
        "a day ago": (NOW - timedelta(days=1), UUID(int=0)),
        "the start": None,
    }[since]
    (found,) = explained(lambda uow: uow.run_orders.feed_after(after, FEED_ORDER_STATES, 1001))
    fast(found, "idx_ops_run_order_updated", 20)


# Once per engine start (the routing cursor after a restart), so a scan is the honest plan.
def test_the_last_routed_order_is_read_once_per_start(explained: Profile) -> None:
    (found,) = explained(lambda uow: uow.run_orders.last_routed())
    assert found.execution_ms < 1000, found.plan
