"""OpsService order lifecycle (submit, claim, heartbeat, complete, approve, requeue) and
SpendService rollups and budget verdicts, on SQLite and Postgres."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4
from weakref import WeakKeyDictionary

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Cursor, PageRequest, TimeWindow
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    Budget,
    BudgetStatus,
    BudgetVerdict,
    ConfigDigest,
    JobResult,
    LaneName,
    OrderFilter,
    OrderProgress,
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
from traust_core.v1.repositories.objects.store import InMemoryObjectStore
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
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


_stores: WeakKeyDictionary[Engine, InMemoryObjectStore] = WeakKeyDictionary()


def publisher(engine: Engine) -> ArtifactPublisher:
    store = _stores.setdefault(engine, InMemoryObjectStore())
    specs = PublishSpecs(PublishSpec(RunManifestArtifact))
    return ArtifactPublisher(specs, store, SqlTraustUnitOfWork(engine))


def ops(engine: Engine, at: timedelta = timedelta()) -> OpsService:
    return OpsService(SqlTraustUnitOfWork(engine), FixedClock(T0 + at), publisher(engine))


def manifest(engine: Engine, order: RunOrder) -> dict[str, Any]:
    order = stored(engine, order)
    assert order.artifact_id is not None
    return json.loads(publisher(engine).get(order.artifact_id).payload)


def seeded(engine: Engine, **kw: Any) -> RunOrder:
    with SqlTraustUnitOfWork(engine) as uow:
        order = Seed(uow).run_order(**kw)
        uow.commit()
    return order


def stored(engine: Engine, order: RunOrder) -> RunOrder:
    assert order.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.run_orders.get(order.id)


def in_state(state: str) -> dict[str, Any]:
    lease = {"lease_holder": W1, "lease_expires_at": T0 + LEASE} if state == "leased" else {}
    return {"state": state, **lease}


def seeded_repository(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository(url=f"https://github.com/example/{uuid4()}")
        uow.commit()
    assert repo.id is not None
    return repo.id


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


def test_plan_stores_a_routed_request_as_planned(engine: Engine) -> None:
    repo = seeded_repository(engine)
    request = OrderRequest(
        asset="diff_scan", priority=2, repository_id=repo, lane="diff-scan", rule="rule-4"
    )
    order = ops(engine).plan(request, OPERATOR)
    assert stored(engine, order) == order
    assert (order.state, order.lane, order.rule) == (OrderState.PLANNED, "diff-scan", "rule-4")
    assert ops(engine).claim(W1, LEASE) is None


def test_plan_re_ranks_the_planned_order_for_the_same_subject(engine: Engine) -> None:
    repo, service = seeded_repository(engine), ops(engine)
    first = service.plan(OrderRequest(asset="diff_scan", priority=5, repository_id=repo), OPERATOR)
    again = OrderRequest(asset="diff_scan", priority=1, repository_id=repo, lane="diff-scan")
    second = service.plan(again, OPERATOR)
    assert second.id == first.id
    assert (stored(engine, first).priority, stored(engine, first).lane) == (1, "diff-scan")


@pytest.mark.parametrize("state", ["awaiting_approval", "queued", "leased"])
def test_plan_keeps_an_order_already_past_planning(engine: Engine, state: str) -> None:
    repo = seeded_repository(engine)
    held = seeded(engine, asset="diff_scan", repository_id=repo, priority=5, **in_state(state))
    request = OrderRequest(asset="diff_scan", priority=1, repository_id=repo)
    assert ops(engine).plan(request, OPERATOR) == held
    assert stored(engine, held) == held


@pytest.mark.parametrize("state", ["succeeded", "degraded", "refused", "withheld", "failed"])
def test_plan_after_a_finished_order_plans_a_new_one(engine: Engine, state: str) -> None:
    repo = seeded_repository(engine)
    done = seeded(engine, asset="diff_scan", repository_id=repo, state=state)
    order = ops(engine).plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=repo), OPERATOR
    )
    assert order.id != done.id and order.state == OrderState.PLANNED


def test_plan_keeps_subjects_apart(engine: Engine) -> None:
    repo, other, service = seeded_repository(engine), seeded_repository(engine), ops(engine)
    orders = {
        service.plan(OrderRequest(asset=asset, priority=1, repository_id=subject), OPERATOR).id
        for asset, subject in [
            ("diff_scan", repo),
            ("diff_scan", other),
            ("repo_state", repo),
            ("diff_scan", None),
            ("feeds_cache", None),
        ]
    }
    assert len(orders) == 5
    assert service.plan(OrderRequest(asset="feeds_cache", priority=0), OPERATOR).id in orders


def test_plan_refuses_an_order_both_routed_and_injected(engine: Engine) -> None:
    request = OrderRequest(asset="diff_scan", priority=1, rule="rule-4", event_source="cve")
    with pytest.raises(ConflictError):
        ops(engine).plan(request, OPERATOR)


def test_admit_queues_a_planned_order_for_claim(engine: Engine) -> None:
    order = seeded(engine, state="planned")
    assert ops(engine).admit(order.id).state == OrderState.QUEUED
    claimed = ops(engine).claim(W1, LEASE)
    assert claimed is not None and claimed.id == order.id


def test_withhold_finishes_a_planned_order_with_its_reason(engine: Engine) -> None:
    order = seeded(engine, state="planned")
    withheld = ops(engine, timedelta(hours=1)).withhold(order.id, "budget-exhausted")
    assert stored(engine, order) == withheld
    assert (withheld.state, withheld.reason) == (OrderState.WITHHELD, "budget-exhausted")
    assert withheld.finished_at == T0 + timedelta(hours=1)


@pytest.mark.parametrize("state", ["awaiting_approval", "queued", "leased", "withheld", "failed"])
def test_admission_refuses_an_order_that_is_not_planned(engine: Engine, state: str) -> None:
    order = seeded(engine, **in_state(state))
    with pytest.raises(ConflictError):
        ops(engine).admit(order.id)
    with pytest.raises(ConflictError):
        ops(engine).withhold(order.id, "budget-exhausted")
    assert stored(engine, order).state == state


def test_request_approval_holds_a_planned_order_until_approved(engine: Engine) -> None:
    order = seeded(engine, state="planned")
    held = ops(engine).request_approval(order.id)
    assert held.state == stored(engine, order).state == OrderState.AWAITING_APPROVAL
    assert ops(engine).claim(W1, LEASE) is None
    assert ops(engine).approve(order.id, OPERATOR).state == OrderState.QUEUED


def test_request_approval_refuses_an_order_that_is_not_planned(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).request_approval(order.id)


def test_subjects_answers_open_and_recently_finished_per_asset(engine: Engine) -> None:
    repo, other = seeded_repository(engine), seeded_repository(engine)
    seeded(engine, asset="repo_state", repository_id=repo, state="planned")
    seeded(engine, asset="repo_state", state="queued")
    seeded(engine, asset="repo_state", repository_id=other, state="succeeded", finished_at=T0)
    seeded(engine, asset="diff_scan", repository_id=other, state="queued")
    service, asset = ops(engine), AssetName("repo_state")
    assert service.subjects(asset, OPEN_ORDER_STATES) == {repo, None}
    finished = (OrderState.SUCCEEDED, OrderState.DEGRADED)
    assert service.subjects(asset, finished) == {other}
    assert service.subjects(asset, finished, finished_after=T0 - timedelta(hours=1)) == {other}
    assert service.subjects(asset, finished, finished_after=T0) == set()
    assert service.subjects(AssetName("feeds_cache"), OPEN_ORDER_STATES) == set()


def test_subjects_needs_a_state(engine: Engine) -> None:
    with pytest.raises(ValidationError):
        ops(engine).subjects(AssetName("repo_state"), ())


def test_get_reads_an_order(engine: Engine) -> None:
    order = seeded(engine)
    assert ops(engine).get(order.id) == order


def test_order_reads_and_admission_of_an_unknown_order_are_not_found(engine: Engine) -> None:
    service, missing = ops(engine), uuid4()
    for call in (service.get, service.admit, lambda o: service.withhold(o, "x")):
        with pytest.raises(NotFoundError):
            call(missing)


def test_list_filters_open_orders_by_asset(engine: Engine) -> None:
    repo = seeded_repository(engine)
    planned = seeded(engine, asset="diff_scan", state="planned", repository_id=repo)
    queued = seeded(engine, asset="diff_scan", state="queued")
    seeded(engine, asset="diff_scan", state="succeeded")
    seeded(engine, asset="repo_state", state="queued")
    page = ops(engine).list(
        OrderFilter(states=OPEN_ORDER_STATES, asset=AssetName("diff_scan")), PageRequest()
    )
    assert {o.id for o in page.items} == {planned.id, queued.id}
    assert page.next is None
    by_repo = ops(engine).list(OrderFilter(repository_id=repo), PageRequest())
    assert by_repo.items == (planned,)


def test_list_filters_by_batch(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        batch = Seed(uow).run_batch()
        uow.commit()
    mine = seeded(engine, run_batch_id=batch.id)
    seeded(engine)
    page = ops(engine).list(OrderFilter(run_batch_id=batch.id), PageRequest())
    assert page.items == (mine,)


def test_list_pages_every_order_once(engine: Engine) -> None:
    orders = {seeded(engine).id for _ in range(5)}
    service, seen, cursor = ops(engine), [], None
    while True:
        page = service.list(
            OrderFilter(states=(OrderState.QUEUED,)), PageRequest(limit=2, cursor=cursor)
        )
        seen += [o.id for o in page.items]
        if (cursor := page.next) is None:
            break
    assert len(seen) == len(orders) and set(seen) == orders


def test_list_pages_newest_first(engine: Engine) -> None:
    older = seeded(engine)
    apart()
    newer = seeded(engine)
    page = ops(engine).list(OrderFilter(states=(OrderState.QUEUED,)), PageRequest(limit=1))
    assert page.items == (newer,)
    rest = ops(engine).list(
        OrderFilter(states=(OrderState.QUEUED,)), PageRequest(limit=1, cursor=page.next)
    )
    assert rest.items == (older,)


@pytest.mark.parametrize(
    ("filter", "page"),
    [
        (OrderFilter(asset=AssetName("diff_scan")), PageRequest()),
        (OrderFilter(), PageRequest()),
        (OrderFilter(states=(OrderState.QUEUED,)), PageRequest(limit=0)),
        (OrderFilter(states=(OrderState.QUEUED,)), PageRequest(cursor=Cursor("nope"))),
    ],
    ids=["asset alone", "no filter", "zero limit", "malformed cursor"],
)
def test_list_rejects_an_unindexed_or_malformed_request(
    engine: Engine, filter: OrderFilter, page: PageRequest
) -> None:
    with pytest.raises(ValidationError):
        ops(engine).list(filter, page)


PACK = ConfigDigest(name="pack:security", digest="a" * 64)
VERDICT = BudgetVerdict(
    lane=LaneName("diff-scan"),
    status=BudgetStatus.OVER,
    enforcement=BudgetEnforcement("advisory"),
    spent_usd=Decimal("120.50"),
    estimate_usd=Decimal("2.00"),
    budget_usd=Decimal("100"),
)


def test_plan_records_the_pack_version_and_orders_share_one_manifest(engine: Engine) -> None:
    repo, other = seeded_repository(engine), seeded_repository(engine)
    service = ops(engine)
    first = service.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=repo), OPERATOR, [PACK]
    )
    second = ops(engine).plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=other), OPERATOR, [PACK]
    )
    assert manifest(engine, first) == {
        "artifact": "run-manifest",
        "config": [{"name": "pack:security", "digest": "a" * 64}],
    }
    assert first.artifact_id is not None and first.artifact_id == second.artifact_id


def test_replanning_with_a_new_pack_version_moves_the_manifest(engine: Engine) -> None:
    repo = seeded_repository(engine)
    request = OrderRequest(asset="diff_scan", priority=1, repository_id=repo)
    first = ops(engine).plan(request, OPERATOR, [PACK])
    newer = ConfigDigest(name="pack:security", digest="b" * 64)
    again = ops(engine).plan(request, OPERATOR, [newer])
    assert again.id == first.id and again.artifact_id != first.artifact_id
    assert manifest(engine, again)["config"] == [{"name": "pack:security", "digest": "b" * 64}]


def test_plan_without_config_writes_no_manifest(engine: Engine) -> None:
    order = ops(engine).plan(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert stored(engine, order).artifact_id is None


@pytest.mark.parametrize("decide", ["admit", "withhold"])
def test_admission_records_the_budget_verdict_beside_the_config(
    engine: Engine, decide: str
) -> None:
    order = ops(engine).plan(OrderRequest(asset="diff_scan", priority=1), OPERATOR, [PACK])
    service = ops(engine)
    if decide == "admit":
        service.admit(order.id, VERDICT)
    else:
        service.withhold(order.id, "budget-over", VERDICT)
    recorded = manifest(engine, order)
    assert recorded["config"] == [{"name": "pack:security", "digest": "a" * 64}]
    assert recorded["budget"] == {
        "lane": "diff-scan",
        "status": "over",
        "enforcement": "advisory",
        "spent_usd": "120.50",
        "estimate_usd": "2.00",
        "budget_usd": "100",
    }


def test_admission_without_a_verdict_leaves_the_manifest(engine: Engine) -> None:
    order = ops(engine).plan(OrderRequest(asset="diff_scan", priority=1), OPERATOR, [PACK])
    assert ops(engine).admit(order.id).artifact_id == order.artifact_id


def test_approve_records_the_approver(engine: Engine) -> None:
    order = seeded(engine, state="awaiting_approval")
    ops(engine, timedelta(hours=1)).approve(order.id, OPERATOR)
    assert manifest(engine, order) == {
        "artifact": "run-manifest",
        "approval": {
            "approver": "human:operator@example.com",
            "approved_at": (T0 + timedelta(hours=1)).isoformat(),
        },
    }


def test_save_progress_records_where_a_leased_order_got_to(engine: Engine) -> None:
    order = leased(engine)
    first = ops(engine).save_progress(order.id, OrderProgress(step=1))
    later = ops(engine, timedelta(minutes=2)).save_progress(
        order.id, OrderProgress(step=2, shards_done=("a", "b"))
    )
    assert stored(engine, order).artifact_id == later != first
    assert manifest(engine, order)["progress"] == {
        "step": 2,
        "shards_done": ["a", "b"],
        "updated_at": (T0 + timedelta(minutes=2)).isoformat(),
    }
    earlier = json.loads(publisher(engine).get(first).payload)
    assert earlier["progress"]["step"] == 1


@pytest.mark.parametrize("state", ["planned", "queued", "succeeded"])
def test_save_progress_refuses_an_order_that_is_not_running(engine: Engine, state: str) -> None:
    order = seeded(engine, state=state)
    with pytest.raises(ConflictError):
        ops(engine).save_progress(order.id, OrderProgress(step=1))
    assert stored(engine, order).artifact_id is None


def test_complete_records_degraded_keys(engine: Engine) -> None:
    order = leased(engine)
    ops(engine).complete(order.id, W1, JobResult.partly({"unreachable": 2, "db-stale": 1}))
    assert manifest(engine, order)["degraded"] == {"unreachable": 2, "db-stale": 1}


def test_a_clean_complete_leaves_the_manifest(engine: Engine) -> None:
    order = leased(engine)
    assert ops(engine).complete(order.id, W1, JobResult.succeeded()).artifact_id is None


def test_a_manifest_moved_by_another_writer_is_a_conflict(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = leased(engine)
    service = ops(engine)
    real = service._publish

    def racing(prior: UUID | None, change: Any) -> UUID:
        ops(engine).save_progress(order.id, OrderProgress(step=9))
        return real(prior, change)

    monkeypatch.setattr(service, "_publish", racing)
    with pytest.raises(ConflictError):
        service.save_progress(order.id, OrderProgress(step=1))
    assert manifest(engine, order)["progress"]["step"] == 9


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
