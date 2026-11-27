"""OpsService order lifecycle (submit, claim, heartbeat, complete, approve, requeue) and
SpendService rollups and budget verdicts, on SQLite and Postgres."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4
from weakref import WeakKeyDictionary

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Cursor, PageRequest, TimeWindow
from traust_core.v1.models.identity import IdentitySource, Principal
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
    OrderReason,
    OrderRequest,
    OrderState,
    Outcome,
    PreflightRequest,
    RecordingStartScope,
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
from traust_core.v1.services.operations import OpsService, PolicyDenied, SpendService
from traust_core.v1.services.portfolio import Inventory

if TYPE_CHECKING:
    from traust_core.v1.models.operations import ModelUsage
    from traust_core.v1.providers.model_catalog import RegistryModelCatalog

LEASE = timedelta(minutes=5)
W1, W2 = WorkerId("w1"), WorkerId("w2")
OPERATOR = Principal(
    identity="operator@example.com",
    kind=ActorKind("human"),
    display="operator",
    verified_by=IdentitySource.OIDC,
)
PLANNER = Principal(
    identity="engine",
    kind=ActorKind("machine"),
    display="engine",
    verified_by=IdentitySource.DATABASE,
)
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


def publisher(engine: Engine, uow: SqlTraustUnitOfWork | None = None) -> ArtifactPublisher:
    store = _stores.setdefault(engine, InMemoryObjectStore())
    specs = PublishSpecs(PublishSpec(RunManifestArtifact))
    return ArtifactPublisher(specs, store, uow or SqlTraustUnitOfWork(engine))


def _ops_with(engine: Engine, clock: FixedClock, **kw: Any) -> OpsService:
    """Ops wired as Context wires it: the run-manifest publisher shares the ops unit of work."""
    uow = SqlTraustUnitOfWork(engine)
    return OpsService(uow, clock, publisher(engine, uow), **kw)


def ops(engine: Engine, at: timedelta = timedelta()) -> OpsService:
    return _ops_with(engine, FixedClock(T0 + at))


def scoped_ops(engine: Engine, starts: Sequence[RecordingStartScope]) -> OpsService:
    """Ops with `recording.start` scopes: the ServiceAccounts a deployment granted."""
    return _ops_with(engine, FixedClock(T0), recording_starts=starts)


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
    if state == "leased":
        return {
            "state": state,
            "lease_holder": W1,
            "lease_expires_at": T0 + LEASE,
            "lease_generation": 1,
        }
    return {"state": state}


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


def reclaim_at_same_clock(engine: Engine, first: RunOrder) -> RunOrder:
    assert ops(engine, LEASE + timedelta(seconds=1)).requeue_expired() == 1
    queued = stored(engine, first)
    assert (queued.state, queued.lease_generation) == (OrderState.QUEUED, first.lease_generation)
    second = ops(engine).claim(W1, LEASE, order_id=first.id)
    assert second is not None and second.id == first.id
    assert second.lease_holder == first.lease_holder == W1
    assert second.started_at == first.started_at == T0
    assert second.lease_expires_at == first.lease_expires_at == T0 + LEASE
    assert second.lease_generation == first.lease_generation + 1
    return second


def test_order_event_does_not_log_requester_email(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.operations"):
        ops(engine).submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
    assert "planned" in caplog.text
    assert OPERATOR.identity not in caplog.text


def test_an_order_event_does_not_precede_an_outer_rollback(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    service = ops(engine)
    with caplog.at_level(logging.INFO, logger="traust_core.v1.services.operations"):
        with service._uow:
            order = service.submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
            assert "planned" not in caplog.text
        assert "planned" not in caplog.text
    with pytest.raises(NotFoundError):
        stored(engine, order)


def test_submit_plans_the_asset_for_its_requester(engine: Engine) -> None:
    order = ops(engine).submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
    assert stored(engine, order) == order
    assert (order.asset, order.lane, order.state) == ("feeds_cache", None, OrderState.PLANNED)
    assert order.requested_by == f"human:{OPERATOR.identity}"
    assert order.lease_generation == 0


def test_a_submitted_order_runs_once_admission_queues_it(engine: Engine) -> None:
    """Submit plans, admission (the engine's tick) queues, a runner claims: one path for
    every order, whatever door asked for it."""
    service = ops(engine)
    order = service.submit(OrderRequest(asset="feeds_cache", priority=3), OPERATOR)
    assert service.claim(W1, LEASE) is None
    assert service.admit(order.id).state == OrderState.QUEUED
    claimed = service.claim(W1, LEASE)
    assert claimed is not None and claimed.id == order.id


def test_submit_refuses_a_door_only_asset(engine: Engine) -> None:
    """remediate_finding is queued only by the remediation scheduling door, which sets its
    fork facts after its checks; the orders door refuses it."""
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        ops(engine).submit(OrderRequest(asset="remediate_finding", priority=1), OPERATOR)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.run_orders.search(asset="remediate_finding", limit=10) == []


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
    assert queued.lease_generation == 0
    assert stored(engine, order).lease_generation == order.lease_generation == 1
    assert service.claim(W2, LEASE) is None


def test_claim_of_a_finished_order_cannot_start_its_new_planned_pair(engine: Engine) -> None:
    first = seeded(engine, asset="feeds_cache")
    other = seeded(engine, asset="ledger_audit")
    service = ops(engine)
    claimed = service.claim(W1, LEASE, order_id=first.id)
    assert claimed is not None and claimed.id == first.id
    service.complete(
        claimed.id, W1, JobResult.succeeded(), lease_generation=claimed.lease_generation
    )
    planned = seeded(engine, asset="feeds_cache", state="planned")

    assert service.claim(W2, LEASE, order_id=first.id) is None
    assert stored(engine, planned).state == OrderState.PLANNED
    assert stored(engine, other).state == OrderState.QUEUED


def test_claim_takes_only_the_assets_a_runner_makes(engine: Engine) -> None:
    session = seeded(engine, asset="dependency_watch", priority=1)
    command = seeded(engine, asset="feeds_cache", priority=9)
    service = ops(engine)
    order = service.claim(W1, LEASE, ["feeds_cache", "ledger_audit"])
    assert order is not None and order.id == command.id
    assert service.claim(W1, LEASE, ["feeds_cache"]) is None
    assert stored(engine, session).state == OrderState.QUEUED
    other = service.claim(W2, LEASE)
    assert other is not None and other.id == session.id


def test_claim_sweeps_a_dead_runners_expired_lease(engine: Engine) -> None:
    leased = seeded(engine)
    service = ops(engine)
    first = service.claim(W1, LEASE)
    assert first is not None and first.id == leased.id
    assert stored(engine, leased).state == OrderState.LEASED
    # The lease expires; another runner's claim re-queues and takes it.
    with SqlTraustUnitOfWork(engine) as uow:
        uow.run_orders.requeue_expired(T0 + LEASE + timedelta(seconds=1))
        uow.commit()
    second = service.claim(W2, LEASE)
    assert second is not None and second.id == leased.id
    assert (second.lease_holder, second.state) == (W2, OrderState.LEASED)
    assert second.lease_generation == first.lease_generation + 1


def test_claim_of_no_assets_claims_nothing(engine: Engine) -> None:
    queued = seeded(engine)
    assert ops(engine).claim(W1, LEASE, []) is None
    assert stored(engine, queued).state == OrderState.QUEUED


def test_mirror_affinity_skips_a_repository_another_worker_holds(engine: Engine) -> None:
    held = seeded_repository(engine)
    free = seeded_repository(engine)
    running = seeded(engine, asset="diff_scan", repository_id=held, **in_state("leased"))
    waiting = seeded(engine, asset="repo_state", repository_id=held, priority=1)
    later = seeded(engine, asset="repo_state", repository_id=free, priority=9)
    service = ops(engine)

    assert service.claim(W2, LEASE, mirror_affinity=True).id == later.id
    assert stored(engine, running).lease_holder == W1
    assert stored(engine, waiting).state == OrderState.QUEUED


def test_mirror_affinity_takes_the_holders_own_next_order_on_its_repository(
    engine: Engine,
) -> None:
    repository_id = seeded_repository(engine)
    running = seeded(engine, asset="diff_scan", repository_id=repository_id, **in_state("leased"))
    waiting = seeded(engine, asset="repo_state", repository_id=repository_id)

    assert ops(engine).claim(W1, LEASE, mirror_affinity=True).id == waiting.id
    assert stored(engine, running).lease_holder == W1


def test_mirror_affinity_leases_the_head_when_nothing_is_held(engine: Engine) -> None:
    repository_id = seeded_repository(engine)
    head = seeded(engine, asset="repo_state", repository_id=repository_id, priority=1)
    tail = seeded(engine, asset="repo_state", priority=9)

    assert ops(engine).claim(W2, LEASE, mirror_affinity=True).id == head.id
    assert stored(engine, tail).state == OrderState.QUEUED


def test_claim_without_affinity_leases_a_held_repositorys_order(engine: Engine) -> None:
    held = seeded_repository(engine)
    running = seeded(engine, asset="diff_scan", repository_id=held, **in_state("leased"))
    waiting = seeded(engine, asset="repo_state", repository_id=held, priority=1)

    assert ops(engine).claim(W2, LEASE).id == waiting.id
    assert stored(engine, running).lease_holder == W1


def test_mirror_affinity_skips_a_pair_an_open_order_occupies(engine: Engine) -> None:
    repository_id = seeded_repository(engine)
    # Two open orders of one (asset, repository) subject can only exist through
    # submit beside plan; the claim's busy rule keeps the queued sibling waiting.
    gated = seeded(engine, asset="repo_state", repository_id=repository_id, state="planned")
    waiting = seeded(engine, asset="repo_state", repository_id=repository_id)

    assert ops(engine).claim(W2, LEASE, mirror_affinity=True) is None
    assert stored(engine, gated).state == OrderState.PLANNED
    assert stored(engine, waiting).state == OrderState.QUEUED


def test_a_named_order_is_claimed_as_asked_despite_affinity(engine: Engine) -> None:
    held = seeded_repository(engine)
    running = seeded(engine, asset="diff_scan", repository_id=held, **in_state("leased"))
    waiting = seeded(engine, asset="repo_state", repository_id=held, priority=1)
    assert waiting.id is not None

    assert ops(engine).claim(W2, LEASE, order_id=waiting.id, mirror_affinity=True).id == (
        waiting.id
    )
    assert stored(engine, running).lease_holder == W1


def test_mirror_affinity_takes_a_fleet_wide_order_past_the_workers_own_lease(
    engine: Engine,
) -> None:
    # A leased sibling is no gate: a runner whose fleet-wide order's completion
    # left it leased (a refusal the order keeps) can take the asset's next
    # queued order — its own lease never blocks it.
    running = seeded(engine, asset="feeds_cache", **in_state("leased"))
    waiting = seeded(engine, asset="feeds_cache", priority=9)

    assert ops(engine).claim(W1, LEASE, ["feeds_cache"], mirror_affinity=True).id == waiting.id
    assert stored(engine, running).lease_holder == W1


def test_mirror_affinity_never_blocks_a_fleet_wide_order(engine: Engine) -> None:
    running = seeded(engine, asset="diff_scan", repository_id=seeded_repository(engine))
    fleet = seeded(engine, asset="repo_state", priority=9)  # no repository: fleet-wide
    service = ops(engine)
    first = service.claim(W1, LEASE, ["diff_scan", "repo_state"])
    assert first is not None and first.id == running.id

    assert service.claim(W2, LEASE, ["repo_state"], mirror_affinity=True).id == fleet.id


def test_start_stores_a_run_already_underway_leased_to_its_runner(engine: Engine) -> None:
    repository_id = seeded_repository(engine)
    request = OrderRequest(asset="repo_state", priority=20, repository_id=repository_id)
    order = ops(engine).start(request, OPERATOR, W1, LEASE)
    assert stored(engine, order) == order
    assert (order.state, order.lease_holder, order.lease_expires_at, order.started_at) == (
        OrderState.LEASED,
        W1,
        T0 + LEASE,
        T0,
    )
    assert order.requested_by == f"human:{OPERATOR.identity}"
    assert order.lease_generation == 1
    done = ops(engine, timedelta(minutes=1)).complete(
        order.id, W1, JobResult.succeeded(), lease_generation=order.lease_generation
    )
    assert done.state == OrderState.SUCCEEDED


def test_start_takes_over_the_subjects_queued_order(engine: Engine) -> None:
    waiting = seeded(engine, asset="feeds_cache", state="queued")
    order = ops(engine).start(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, W1, LEASE)
    assert order.id == waiting.id
    assert (order.state, order.lease_holder, order.priority) == (OrderState.LEASED, W1, 5)
    assert (waiting.lease_generation, order.lease_generation) == (0, 1)
    assert ops(engine).claim(W2, LEASE) is None


def test_start_refuses_a_planned_order_admission_has_not_seen(engine: Engine) -> None:
    waiting = seeded(engine, asset="feeds_cache", state="planned")
    with pytest.raises(ConflictError, match="awaiting admission"):
        ops(engine).start(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, W1, LEASE)
    assert ops(engine).get(waiting.id).state == OrderState.PLANNED


def test_a_submitted_gated_order_is_taken_over_only_once_admitted_and_approved(
    engine: Engine,
) -> None:
    """The start door can't jump admission: a person's submitted order is refused while
    planned and while held for approval, and taken over once approval has queued it."""
    service = ops(engine)
    submitted = service.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert submitted.id is not None
    start = OrderRequest(asset="feeds_cache", priority=1)
    with pytest.raises(ConflictError, match="awaiting admission"):
        service.start(start, OPERATOR, W1, LEASE)
    service.request_approval(submitted.id)
    with pytest.raises(ConflictError, match="awaiting approval"):
        service.start(start, OPERATOR, W1, LEASE)
    service.approve(submitted.id, OPERATOR)
    taken = service.start(start, OPERATOR, W1, LEASE)
    assert (taken.id, taken.state) == (submitted.id, OrderState.LEASED)


def test_start_refuses_to_create_a_new_door_only_order(engine: Engine) -> None:
    """A start with no order to take over stores a new order, so the door-only rule refuses
    it as a submit would: only the scheduling door queues the asset."""
    repo = seeded_repository(engine)
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        ops(engine).start(
            OrderRequest(asset="remediate_finding", priority=1, repository_id=repo),
            OPERATOR,
            W1,
            LEASE,
        )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.run_orders.search(asset="remediate_finding", limit=10) == []


def test_start_takes_over_the_order_the_scheduling_door_queued(engine: Engine) -> None:
    """The door-only rule refuses new orders, never the run the door asked for: a runner
    takes over the door's queued order, fork facts and all."""
    repo = seeded_repository(engine)
    queued = seeded(
        engine,
        asset="remediate_finding",
        state="queued",
        priority=0,
        repository_id=repo,
        requested_by="machine:remediation-scheduling",
        fork_url="https://github.com/mirror-org/fix",
        fork_branch="fix/finding",
    )
    order = ops(engine).start(
        OrderRequest(asset="remediate_finding", priority=0, repository_id=repo), OPERATOR, W1, LEASE
    )
    assert (order.id, order.state, order.lease_holder) == (queued.id, OrderState.LEASED, W1)
    assert (order.fork_url, order.fork_branch) == (
        "https://github.com/mirror-org/fix",
        "fix/finding",
    )


def test_start_refuses_to_take_over_an_order_awaiting_approval(engine: Engine) -> None:
    """Admission held the order for a person; the start door must not release it around the
    approval the pack asked for."""
    held = seeded(engine, asset="feeds_cache", **in_state("awaiting_approval"))
    with pytest.raises(ConflictError, match="awaiting approval"):
        ops(engine).start(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, W2, LEASE)
    assert stored(engine, held).state == "awaiting_approval"


def test_start_refuses_a_subject_already_running(engine: Engine) -> None:
    held = seeded(engine, asset="feeds_cache", **in_state("leased"))
    with pytest.raises(ConflictError):
        ops(engine).start(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, W2, LEASE)
    assert stored(engine, held).state == "leased"


def test_start_leaves_finished_orders_and_other_subjects_alone(engine: Engine) -> None:
    done = seeded(engine, asset="feeds_cache", state="succeeded", finished_at=T0)
    other = seeded(engine, asset="feeds_cache", repository_id=seeded_repository(engine))
    order = ops(engine).start(OrderRequest(asset="feeds_cache", priority=1), OPERATOR, W1, LEASE)
    assert order.id not in (done.id, other.id)
    assert stored(engine, other).state == OrderState.QUEUED


def test_a_started_order_whose_runner_vanished_is_requeued(engine: Engine) -> None:
    service = ops(engine)
    request = OrderRequest(asset="feeds_cache", priority=1)
    order = service.start(request, OPERATOR, W1, LEASE)
    reaper = ops(engine, LEASE + timedelta(seconds=1))
    for _ in range(2):
        assert reaper.requeue_expired() == 1
        queued = stored(engine, order)
        assert queued.state == OrderState.QUEUED
        assert queued.lease_generation == order.lease_generation
        restarted = service.start(request, OPERATOR, W1, LEASE)
        assert restarted.id == order.id
        assert restarted.lease_generation == order.lease_generation + 1
        order = restarted


def test_heartbeat_extends_the_holders_lease(engine: Engine) -> None:
    order = leased(engine)
    renewed = ops(engine, timedelta(minutes=4)).heartbeat(
        order.id, W1, LEASE, lease_generation=order.lease_generation
    )
    assert renewed.lease_expires_at == T0 + timedelta(minutes=9)
    assert renewed.lease_generation == order.lease_generation
    assert stored(engine, order) == renewed


@pytest.mark.parametrize(
    ("worker", "at"),
    [(W2, timedelta()), (W1, LEASE), (W1, LEASE + timedelta(seconds=1))],
    ids=["another worker", "at expiry", "after expiry"],
)
def test_heartbeat_is_refused(engine: Engine, worker: WorkerId, at: timedelta) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).heartbeat(order.id, worker, LEASE, lease_generation=order.lease_generation)
    assert stored(engine, order) == order


def test_heartbeat_refuses_an_order_that_is_not_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).heartbeat(order.id, W1, LEASE, lease_generation=1)


def test_unknown_orders_are_not_found(engine: Engine) -> None:
    service, missing = ops(engine), uuid4()
    with pytest.raises(NotFoundError):
        service.heartbeat(missing, W1, LEASE, lease_generation=1)
    with pytest.raises(NotFoundError):
        service.complete(missing, W1, JobResult.succeeded(), lease_generation=1)
    with pytest.raises(NotFoundError):
        service.approve(missing, OPERATOR)


@pytest.mark.parametrize("outcome", list(Outcome))
def test_complete_finishes_the_order_with_its_outcome(engine: Engine, outcome: Outcome) -> None:
    order = leased(engine)
    result = RESULTS[outcome]
    done = ops(engine, timedelta(minutes=2)).complete(
        order.id, W1, result, lease_generation=order.lease_generation
    )
    assert stored(engine, order) == done
    assert (done.state, done.reason) == (OrderState(outcome), result.reason)
    assert (done.lease_holder, done.lease_expires_at) == (None, None)
    assert (done.completed_by, done.lease_generation) == (W1, order.lease_generation)
    assert (done.started_at, done.finished_at) == (T0, T0 + timedelta(minutes=2))


def test_complete_retried_with_the_same_outcome_changes_nothing(engine: Engine) -> None:
    order = leased(engine)
    result = JobResult.succeeded()
    done = ops(engine).complete(order.id, W1, result, lease_generation=order.lease_generation)
    after_expiry = ops(engine, LEASE + timedelta(hours=1))
    replay = after_expiry.complete(order.id, W1, result, lease_generation=order.lease_generation)
    assert replay == done
    assert stored(engine, order) == done


def test_terminal_replay_requires_the_completing_worker_and_generation(engine: Engine) -> None:
    first = leased(engine)
    current = reclaim_at_same_clock(engine, first)
    result = JobResult.succeeded()
    service = ops(engine)
    done = service.complete(current.id, W1, result, lease_generation=current.lease_generation)
    for worker, generation in ((W2, current.lease_generation), (W1, first.lease_generation)):
        with pytest.raises(ConflictError):
            service.complete(current.id, worker, result, lease_generation=generation)
        assert stored(engine, current) == done


def test_complete_refuses_a_second_different_outcome(engine: Engine) -> None:
    order = leased(engine)
    generation = order.lease_generation
    ops(engine).complete(order.id, W1, JobResult.succeeded(), lease_generation=generation)
    with pytest.raises(ConflictError):
        ops(engine).complete(
            order.id, W1, JobResult.failed(OrderReason.RUNNER_CRASHED), lease_generation=generation
        )
    assert stored(engine, order).state == OrderState.SUCCEEDED


def test_complete_refuses_a_worker_that_does_not_hold_the_lease(engine: Engine) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(
            order.id, W2, JobResult.succeeded(), lease_generation=order.lease_generation
        )
    assert stored(engine, order).state == OrderState.LEASED


def test_complete_refuses_an_order_that_was_never_leased(engine: Engine) -> None:
    order = seeded(engine)
    with pytest.raises(ConflictError):
        ops(engine).complete(order.id, W1, JobResult.succeeded(), lease_generation=1)
    assert stored(engine, order).state == OrderState.QUEUED


@pytest.mark.parametrize("at", [LEASE, LEASE + timedelta(minutes=1)])
def test_complete_refuses_an_expired_lease_before_requeue(engine: Engine, at: timedelta) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).complete(
            order.id, W1, JobResult.succeeded(), lease_generation=order.lease_generation
        )
    assert stored(engine, order) == order


def test_complete_after_the_reaper_requeued_is_refused(engine: Engine) -> None:
    order = leased(engine)
    later = ops(engine, LEASE + timedelta(seconds=1))
    assert later.requeue_expired() == 1
    with pytest.raises(ConflictError):
        later.complete(order.id, W1, JobResult.succeeded(), lease_generation=order.lease_generation)


def test_same_worker_cannot_use_its_previous_grant_after_reclaim(engine: Engine) -> None:
    first = leased(engine)
    current = reclaim_at_same_clock(engine, first)
    service = ops(engine)
    service.save_progress(
        current.id, OrderProgress(step=2), worker=W1, lease_generation=current.lease_generation
    )
    before = stored(engine, current)
    with pytest.raises(ConflictError):
        service.heartbeat(first.id, W1, 2 * LEASE, lease_generation=first.lease_generation)
    assert stored(engine, current) == before
    with pytest.raises(ConflictError):
        service.complete(
            first.id, W1, JobResult.succeeded(), lease_generation=first.lease_generation
        )
    assert stored(engine, current) == before
    with pytest.raises(ConflictError):
        service.save_progress(
            first.id, OrderProgress(step=1), worker=W1, lease_generation=first.lease_generation
        )
    assert stored(engine, current) == before
    assert manifest(engine, current)["progress"]["step"] == 2


def test_approve_queues_an_order_awaiting_approval(engine: Engine) -> None:
    order = seeded(engine, state="awaiting_approval")
    approved = ops(engine).approve(order.id, OPERATOR)
    assert approved.state == stored(engine, order).state == OrderState.QUEUED


def test_approval_emits_one_actor_classified_transition(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    order = seeded(engine, state="awaiting_approval")
    assert order.id is not None
    logger = logging.getLogger("traust_core.v1.services.operations")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            ops(engine).approve(order.id, OPERATOR)
        finally:
            logger.removeHandler(caplog.handler)
    events = {
        id(record): record.getMessage()
        for record in caplog.records
        if record.name == logger.name and record.getMessage().startswith(f"order {order.id} ")
    }
    assert len(events) == 1
    assert "queued" in next(iter(events.values())) and "actor_kind=human" in next(
        iter(events.values())
    )


@pytest.mark.parametrize(
    "principal",
    [
        OPERATOR.model_copy(update={"verified_by": None}),
        OPERATOR.model_copy(update={"kind": ActorKind("machine")}),
    ],
    ids=["unverified-human", "machine"],
)
def test_approve_needs_a_verified_person_or_a_granted_serviceaccount(
    engine: Engine, principal: Principal
) -> None:
    order = seeded(engine, state="awaiting_approval")
    with pytest.raises(ForbiddenError, match="verified person"):
        ops(engine).approve(order.id, principal)
    assert stored(engine, order).state == "awaiting_approval"


SA = Principal(
    identity="system:serviceaccount:sci:sci",
    kind=ActorKind("machine"),
    display="sci platform",
    verified_by=IdentitySource.OIDC,
)


def test_approve_is_a_person_s_or_a_granted_serviceaccount_s_word(engine: Engine) -> None:
    """The authorization matrix: a verified person approves anything; a ServiceAccount only
    inside a `recording.start` grant covering the order's asset and repository — the same
    scope its recording authority names. The approval record carries the ServiceAccount's
    ref."""
    repository_id = seeded_repository(engine)
    order = seeded(
        engine, asset="full_audit", state="awaiting_approval", repository_id=repository_id
    )
    unscoped = scoped_ops(engine, (RecordingStartScope(principal=SA.ref, assets=("sci_scan",)),))
    for refused in (
        SA,
        SA.model_copy(update={"verified_by": None}),
        OPERATOR.model_copy(update={"kind": ActorKind("machine")}),
    ):
        with pytest.raises(ForbiddenError, match="verified person"):
            unscoped.approve(order.id, refused)
    assert stored(engine, order).state == "awaiting_approval"

    other_repository = seeded_repository(engine)
    scope_mismatch = scoped_ops(
        engine,
        (
            RecordingStartScope(
                principal=SA.ref, assets=("full_audit",), repository_ids=(other_repository,)
            ),
        ),
    )
    with pytest.raises(ForbiddenError, match="granted full_audit"):
        scope_mismatch.approve(order.id, SA)
    assert stored(engine, order).state == "awaiting_approval"

    granted = scoped_ops(
        engine,
        (
            RecordingStartScope(
                principal=SA.ref,
                assets=("full_audit", "diff_scan"),
                repository_ids=(repository_id,),
            ),
        ),
    )
    approved = granted.approve(order.id, SA)
    assert approved.state == stored(engine, order).state == OrderState.QUEUED
    assert manifest(engine, order)["approval"]["approver"] == SA.ref


@pytest.mark.parametrize("all_repositories", [False, True], ids=["listed", "estate-wide"])
def test_a_serviceaccount_does_not_approve_a_fleet_wide_order(
    engine: Engine, all_repositories: bool
) -> None:
    """A fleet-wide order (no repository) is a person's release: a grant scopes a
    ServiceAccount by registered repositories, and `None` names none — not even the
    estate-wide flag widens a scope past the fleet-wide boundary."""
    order = seeded(engine, asset="full_audit", state="awaiting_approval")
    assert order.repository_id is None
    granted = scoped_ops(
        engine,
        (
            RecordingStartScope(
                principal=SA.ref, assets=("full_audit",), all_repositories=all_repositories
            ),
        ),
    )
    with pytest.raises(ForbiddenError, match="granted full_audit"):
        granted.approve(order.id, SA)
    assert stored(engine, order).state == "awaiting_approval"


def test_an_estate_wide_scope_covers_every_repository(engine: Engine) -> None:
    """`all_repositories` widens a scope past its listed repository_ids — the platform's own
    identity, whose authority is the estate it runs: a repository the snapshot never listed
    is still covered, while the assets stay the gate (an unlisted asset is still refused)."""
    unlisted = seeded_repository(engine)  # in no scope's repository_ids
    order = seeded(engine, asset="diff_scan", state="awaiting_approval", repository_id=unlisted)
    estate = scoped_ops(
        engine,
        (
            RecordingStartScope(
                principal=SA.ref,
                assets=("full_audit", "diff_scan"),
                all_repositories=True,
            ),
        ),
    )
    approved = estate.approve(order.id, SA)
    assert approved.state == stored(engine, order).state == OrderState.QUEUED
    assert manifest(engine, order)["approval"]["approver"] == SA.ref

    other = seeded(
        engine, asset="threat_model_review", state="awaiting_approval", repository_id=unlisted
    )
    with pytest.raises(ForbiddenError, match="granted threat_model_review"):
        estate.approve(other.id, SA)
    assert stored(engine, other).state == "awaiting_approval"


def test_an_ungranted_caller_s_approve_probe_is_refused_before_the_order_is_read(
    engine: Engine,
) -> None:
    """No 404-vs-403 oracle on order existence: the caller's shape is checked before the
    order is read, so an ungranted or unverified ServiceAccount hears forbidden whether or
    not the order exists."""
    unscoped = scoped_ops(engine, ())
    for refused in (
        SA,
        SA.model_copy(update={"verified_by": None}),
        OPERATOR.model_copy(update={"kind": ActorKind("machine")}),
    ):
        with pytest.raises(ForbiddenError, match="verified person"):
            unscoped.approve(uuid4(), refused)


@pytest.mark.parametrize("state", ["planned", "queued", "withheld", "succeeded"])
def test_approve_refuses_an_order_not_awaiting_approval(engine: Engine, state: str) -> None:
    order = seeded(engine, state=state)
    with pytest.raises(ConflictError):
        ops(engine).approve(order.id, OPERATOR)
    assert stored(engine, order).state == state


def test_requeue_expired_returns_lapsed_leases_and_keeps_live_ones(engine: Engine) -> None:
    lapsed = leased(engine, W1)
    live = seeded(engine)
    ops(engine, LEASE / 2).claim(W2, LEASE, order_id=live.id)
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
    assert order.lease_generation == 0
    assert ops(engine).claim(W1, LEASE) is None


def test_plan_replay_does_not_update_or_log_unchanged_route(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    repo, service = seeded_repository(engine), ops(engine)
    request = OrderRequest(asset="diff_scan", priority=5, repository_id=repo, lane="diff-scan")
    first = service.plan(request, OPERATOR, [PACK])
    caplog.clear()
    logger = logging.getLogger("traust_core.v1.services.operations")
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.addHandler(caplog.handler)
        try:
            assert service.plan(request, OPERATOR, [PACK]) == first
        finally:
            logger.removeHandler(caplog.handler)
    assert stored(engine, first) == first
    events = [
        record
        for record in caplog.records
        if record.name == logger.name and " planned priority=" in record.getMessage()
    ]
    assert not events


def test_plan_re_ranks_the_planned_order_for_the_same_subject(engine: Engine) -> None:
    """The engine re-ranks what it planned itself, while the order is still planned."""
    repo, service = seeded_repository(engine), ops(engine)
    first = service.plan(OrderRequest(asset="diff_scan", priority=5, repository_id=repo), PLANNER)
    again = OrderRequest(asset="diff_scan", priority=1, repository_id=repo, lane="diff-scan")
    second = service.plan(again, PLANNER)
    assert second.id == first.id
    assert (stored(engine, first).priority, stored(engine, first).lane) == (1, "diff-scan")


def test_plan_leaves_a_persons_submitted_order_its_chosen_route(engine: Engine) -> None:
    """A submitted order is planned with the route its requester chose, and still names them
    as requester; a later engine tick (or an onboarding baseline) re-planning the subject
    must not overwrite that route."""
    repo, service = subject(engine), gated(engine)
    submitted = service.submit(
        OrderRequest(asset="diff_scan", priority=3, repository_id=repo, lane="diff-scan"), OPERATOR
    )
    assert (
        service.plan(
            OrderRequest(asset="diff_scan", priority=1, repository_id=repo, lane="deps-lane"),
            PLANNER,
        )
        == submitted
    )
    assert (stored(engine, submitted).priority, stored(engine, submitted).lane) == (3, "diff-scan")


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


def test_plan_refuses_a_door_only_asset(engine: Engine) -> None:
    """The door-only rule holds at every door that stores an order, not only submit and
    preflight: the engine's planning, and an onboarding baseline through it, reach the same
    refusal — only the scheduling door queues the asset."""
    repo = seeded_repository(engine)
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        ops(engine).plan(
            OrderRequest(asset="remediate_finding", priority=1, repository_id=repo), PLANNER
        )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.run_orders.search(asset="remediate_finding", limit=10) == []


def test_plan_refuses_an_order_for_an_unregistered_repository(engine: Engine) -> None:
    """Every order's subject is a registered repository: the table's foreign key refuses an
    unknown UUID at plan, so an order outside the inventory cannot exist to be approved —
    a `recording.start` grant, estate-wide or listed, enumerates registered repositories."""
    request = OrderRequest(asset="full_audit", priority=1, repository_id=uuid4())
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


def test_subjects_stopped_for_a_reason_leave_other_withheld_orders_out(engine: Engine) -> None:
    stale, over_budget = seeded_repository(engine), seeded_repository(engine)
    for repo, reason in ((stale, "upstream-stale"), (over_budget, "budget-over")):
        seeded(
            engine,
            asset="diff_scan",
            repository_id=repo,
            state="withheld",
            reason=reason,
            finished_at=T0,
        )
    service, asset, withheld = ops(engine), AssetName("diff_scan"), (OrderState.WITHHELD,)
    assert service.subjects(asset, withheld) == {stale, over_budget}
    assert service.subjects(asset, withheld, reason=OrderReason.UPSTREAM_STALE) == {stale}
    late = T0 + timedelta(seconds=1)
    assert service.subjects(asset, withheld, late, OrderReason.UPSTREAM_STALE) == set()


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
    first = ops(engine).plan(request, PLANNER, [PACK])
    newer = ConfigDigest(name="pack:security", digest="b" * 64)
    again = ops(engine).plan(request, PLANNER, [newer])
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
    generation = order.lease_generation
    first = ops(engine).save_progress(
        order.id, OrderProgress(step=1), worker=W1, lease_generation=generation
    )
    later = ops(engine, timedelta(minutes=2)).save_progress(
        order.id,
        OrderProgress(step=2, shards_done=("a", "b")),
        worker=W1,
        lease_generation=generation,
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
        ops(engine).save_progress(order.id, OrderProgress(step=1), worker=W1, lease_generation=1)
    assert stored(engine, order) == order


@pytest.mark.parametrize("worker,at", [(W2, timedelta()), (W1, LEASE)])
def test_save_progress_requires_the_live_holder(
    engine: Engine, worker: WorkerId, at: timedelta
) -> None:
    order = leased(engine)
    with pytest.raises(ConflictError):
        ops(engine, at).save_progress(
            order.id, OrderProgress(step=1), worker=worker, lease_generation=order.lease_generation
        )
    assert stored(engine, order) == order


def test_complete_records_degraded_keys(engine: Engine) -> None:
    order = leased(engine)
    result = JobResult.partly({"unreachable": 2, "db-stale": 1})
    ops(engine).complete(order.id, W1, result, lease_generation=order.lease_generation)
    assert manifest(engine, order)["degraded"] == {"unreachable": 2, "db-stale": 1}


def test_a_clean_complete_leaves_the_manifest(engine: Engine) -> None:
    order = leased(engine)
    done = ops(engine).complete(
        order.id, W1, JobResult.succeeded(), lease_generation=order.lease_generation
    )
    assert done.artifact_id is None


def test_a_manifest_moved_by_another_writer_is_a_conflict(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = leased(engine)
    service = ops(engine)
    real = service._stage_manifest

    def racing(prior: UUID | None, change: Any) -> Any:
        # another writer moves the manifest between staging and the order lock
        ops(engine).save_progress(
            order.id, OrderProgress(step=9), worker=W1, lease_generation=order.lease_generation
        )
        return real(prior, change)

    monkeypatch.setattr(service, "_stage_manifest", racing)

    def artifacts() -> int:
        with SqlTraustUnitOfWork(engine) as uow:
            count = sa.select(sa.func.count()).select_from(uow.artifacts.table)
            return int(uow.connection.scalar(count))

    before = artifacts()
    with pytest.raises(ConflictError):
        service.save_progress(
            order.id, OrderProgress(step=1), worker=W1, lease_generation=order.lease_generation
        )
    assert manifest(engine, order)["progress"]["step"] == 9
    # the refused move published nothing: only the racing writer's manifest is new
    assert artifacts() == before + 1


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


# preflight ----------------------------------------------------------------------------------------


def gated(engine: Engine, *budgets: Budget) -> OpsService:
    """An OpsService with the doors the policy checks need (inventory, spend with budgets) and
    the deployment's stage assets declared, so the ordering gate applies."""
    return _ops_with(
        engine,
        FixedClock(T0),
        spend=spend(engine, *budgets),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={"assessment": ("assessment",), "triage": ("triage",)},
    )


def subject(engine: Engine) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        # Onboarded, not merely registered: a default line, which is what a run works on.
        seed.repository_ref(repo, is_default=True)
        uow.commit()
    return repo.id


MACHINE = Principal(
    identity="runner-1",
    kind=ActorKind("machine"),
    display="runner",
    verified_by=IdentitySource.DATABASE,
)


def test_preflight_refuses_a_door_only_asset_as_submit_does(engine: Engine) -> None:
    """The courtesy check gives submit's answer: a door-only asset is refused by both."""
    repo = subject(engine)
    seeded(engine, asset="triage", repository_id=repo, state="succeeded")
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        gated(engine).preflight(
            PreflightRequest(asset="remediate_finding", repository_id=repo), OPERATOR
        )


def test_preflight_allows_a_stage_whose_prior_record_exists(engine: Engine) -> None:
    repo = subject(engine)
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    result = gated(engine).preflight(
        PreflightRequest(asset="triage", repository_id=repo, config_generation="g7"), OPERATOR
    )
    assert result.allowed is True
    assert (result.asset, result.repository_id, result.config_generation) == ("triage", repo, "g7")


def test_preflight_denies_an_unknown_subject(engine: Engine) -> None:
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).preflight(PreflightRequest(asset="triage", repository_id=uuid4()), OPERATOR)
    assert denied.value.deny_code == "subject_unknown"


def test_preflight_denies_a_caller_without_the_role(engine: Engine) -> None:
    repo = subject(engine)
    spent(engine, "50.00")
    with pytest.raises(PolicyDenied) as denied:
        gated(engine, audit_budget("advisory")).preflight(
            PreflightRequest(asset="triage", repository_id=repo, lane=AUDIT), MACHINE
        )
    assert denied.value.deny_code == "role_denied"


def test_a_caller_without_the_role_learns_nothing_else(engine: Engine) -> None:
    """A caller who may not ask for a run gets the role denial alone: no subject answer, no
    stage ordering, no lane figures — the other gates are not even evaluated."""
    with pytest.raises(PolicyDenied) as denied:
        gated(engine, audit_budget("advisory")).preflight(
            PreflightRequest(asset="triage", repository_id=uuid4(), lane=AUDIT), MACHINE
        )
    assert [i.code for i in denied.value.deny_issues] == ["role_denied"]
    assert "50" not in denied.value.deny_issues[0].detail


def test_preflight_denies_a_stage_whose_prior_record_is_missing(engine: Engine) -> None:
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).preflight(
            PreflightRequest(asset="triage", repository_id=subject(engine)), OPERATOR
        )
    assert [i.code for i in denied.value.deny_issues] == ["ordering_violated"]


def test_preflight_denies_an_exhausted_lane_budget(engine: Engine) -> None:
    repo = subject(engine)
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    spent(engine, "50.00")
    with pytest.raises(PolicyDenied) as denied:
        gated(engine, audit_budget("advisory")).preflight(
            PreflightRequest(asset="triage", repository_id=repo, lane=AUDIT), OPERATOR
        )
    assert denied.value.deny_code == "budget_exhausted"


def test_subject_checks_need_the_inventory_door(engine: Engine) -> None:
    with pytest.raises(ConfigError):
        ops(engine).preflight(PreflightRequest(asset="triage", repository_id=uuid4()), OPERATOR)


def test_submit_rejects_what_preflight_would_deny_without_preflight_being_called(
    engine: Engine,
) -> None:
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).submit(
            OrderRequest(asset="triage", priority=1, repository_id=subject(engine)), OPERATOR
        )
    assert denied.value.deny_code == "ordering_violated"


def test_submit_accepts_what_preflight_allowed(engine: Engine) -> None:
    repo = subject(engine)
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    order = gated(engine).submit(
        OrderRequest(asset="triage", priority=1, repository_id=repo), OPERATOR
    )
    assert order.state == OrderState.PLANNED


def test_the_gate_follows_the_configured_asset_names(engine: Engine) -> None:
    """A deployment whose assessments run as "audit" (not "assessment") still gates triage,
    and one whose assessments are not wired is not gated at all."""
    audit_gated = _ops_with(
        engine,
        FixedClock(T0),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={"assessment": ("audit",), "triage": ("triage",)},
    )
    repo = subject(engine)
    seeded(engine, asset="audit", repository_id=repo, state="succeeded")
    order = audit_gated.submit(
        OrderRequest(asset="triage", priority=1, repository_id=repo), OPERATOR
    )
    assert order.state == OrderState.PLANNED


def test_a_predecessor_that_did_not_run_does_not_unlock_the_next_stage(engine: Engine) -> None:
    """A failed, refused or withheld predecessor finished as an order, not as work: the gate
    wants a completed one."""
    repo = subject(engine)
    for unfinished in ("failed", "refused", "withheld"):
        seeded(engine, asset="assessment", repository_id=repo, state=unfinished)
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).submit(OrderRequest(asset="triage", priority=1, repository_id=repo), OPERATOR)
    assert denied.value.deny_code == "ordering_violated"


def test_a_gated_stage_cannot_be_submitted_without_a_subject(engine: Engine) -> None:
    """A subjectless order cannot show its predecessor ran for the subject, so it is refused
    rather than queued unverified."""
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).submit(OrderRequest(asset="triage", priority=1), OPERATOR)
    assert denied.value.deny_code == "ordering_violated"


def test_remediation_follows_triage_not_another_remediation_order(engine: Engine) -> None:
    """Remediation rides the triage allowlist but is its own stage: a completed assessment
    does not unlock it, a completed triage does, and its own orders never do."""
    remediating = _ops_with(
        engine,
        FixedClock(T0),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={
            "assessment": ("assessment",),
            "triage": ("triage", "remediate_finding"),
            "remediation": ("triage", "remediate_finding"),
        },
    )
    repo = subject(engine)
    with pytest.raises(PolicyDenied) as denied:
        remediating.submit(
            OrderRequest(asset="remediate_finding", priority=1, repository_id=repo), OPERATOR
        )
    assert denied.value.deny_code == "ordering_violated"
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    with pytest.raises(PolicyDenied):
        remediating.submit(
            OrderRequest(asset="remediate_finding", priority=1, repository_id=repo), OPERATOR
        )
    seeded(engine, asset="triage", repository_id=repo, state="succeeded")
    # past the ordering gate now: what refuses it is the door rule (the scheduling door owns it)
    with pytest.raises(ForbiddenError, match="POST /v1/remediations"):
        remediating.preflight(
            PreflightRequest(asset="remediate_finding", repository_id=repo), OPERATOR
        )


def test_verification_follows_remediation_not_ordinary_triage(engine: Engine) -> None:
    """Verification's prerequisite is remediation: only the native scheduling asset satisfies
    it — a completed ordinary triage order on the shared allowlist does not."""
    remediating = _ops_with(
        engine,
        FixedClock(T0),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={
            "assessment": ("assessment",),
            "triage": ("triage", "remediate_finding"),
            "remediation": ("triage", "remediate_finding"),
            "verification": ("verify",),
        },
    )
    repo = subject(engine)
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    seeded(engine, asset="triage", repository_id=repo, state="succeeded")
    with pytest.raises(PolicyDenied) as denied:
        remediating.submit(OrderRequest(asset="verify", priority=1, repository_id=repo), OPERATOR)
    assert denied.value.deny_code == "ordering_violated"
    seeded(engine, asset="remediate_finding", repository_id=repo, state="succeeded")
    order = remediating.submit(
        OrderRequest(asset="verify", priority=1, repository_id=repo), OPERATOR
    )
    assert order.state == OrderState.PLANNED


def test_verification_keeps_a_prerequisite_when_remediation_is_not_wired(engine: Engine) -> None:
    """A deployment without remediation on its allowlist falls back to ordinary triage for
    verification's prerequisite: a completed stage before it, never nothing (Qodo 392)."""
    unwired = _ops_with(
        engine,
        FixedClock(T0),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={
            "assessment": ("assessment",),
            "triage": ("triage",),
            "verification": ("verify",),
        },
    )
    repo = subject(engine)
    seeded(engine, asset="assessment", repository_id=repo, state="succeeded")
    with pytest.raises(PolicyDenied) as denied:
        unwired.submit(OrderRequest(asset="verify", priority=1, repository_id=repo), OPERATOR)
    assert denied.value.deny_code == "ordering_violated"
    seeded(engine, asset="triage", repository_id=repo, state="succeeded")
    order = unwired.submit(OrderRequest(asset="verify", priority=1, repository_id=repo), OPERATOR)
    assert order.state == OrderState.PLANNED


def test_an_asset_bound_to_two_kinds_outside_the_config_is_a_config_error(engine: Engine) -> None:
    """RecordingConfig refuses ambiguous bindings, so a service wired with the same asset on
    two kinds was built outside the config: refuse the run rather than guess its stage
    (Qodo 392) — the gate is never silently skipped."""
    ambiguous = _ops_with(
        engine,
        FixedClock(T0),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
        recording_assets={
            "assessment": ("audit",),
            "triage": ("audit", "triage"),
        },
    )
    repo = subject(engine)
    with pytest.raises(ConfigError, match="several record kinds"):
        ambiguous.submit(OrderRequest(asset="audit", priority=1, repository_id=repo), OPERATOR)


def test_a_registered_repository_without_an_imported_line_is_not_a_subject(engine: Engine) -> None:
    """Onboarding is an imported default line, not a registered row: a repository that was
    never imported has nothing for a run to work on, so the subject gate refuses it."""
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository(url=f"https://github.com/example/{uuid4()}")
        uow.commit()
    assert repo.id is not None
    with pytest.raises(PolicyDenied) as denied:
        gated(engine).submit(
            OrderRequest(asset="assessment", priority=1, repository_id=repo.id), OPERATOR
        )
    assert denied.value.deny_code == "subject_unknown"


@pytest.mark.parametrize(
    "occurred_at",
    [T0, T0 + timedelta(microseconds=123_456)],
    ids=["whole-second", "sub-millisecond"],
)
def test_fenced_expired_completion_persists_measured_spend_once_without_advancing_order(
    engine: Engine, caplog: pytest.LogCaptureFixture, occurred_at: datetime
) -> None:
    from decimal import Decimal

    from traust_core.v1.models.operations import ModelUsage
    from traust_core.v1.providers.model_catalog import ModelSpec, RegistryModelCatalog

    spec = ModelSpec(
        name="claude-test",
        provider="anthropic",
        tier="sonnet-class",
        price_per_mtok_in=Decimal("10"),
        price_per_mtok_out=Decimal("20"),
    )
    catalog = RegistryModelCatalog({"claude-test": spec}, {}, ("sonnet-class",), None)
    usage = (
        ModelUsage(
            provider="anthropic",
            model="claude-test",
            skill="triage",
            tokens_in=100_000,
            tokens_out=50_000,
            occurred_at=occurred_at,
        ),
    )
    order = leased(engine)
    assert order.id is not None
    uow = SqlTraustUnitOfWork(engine)
    late_clock = FixedClock(T0 + LEASE + timedelta(minutes=1))
    late_ops = OpsService(
        uow,
        late_clock,
        ArtifactPublisher(
            PublishSpecs(PublishSpec(RunManifestArtifact)),
            _stores.setdefault(engine, InMemoryObjectStore()),
            uow,
        ),
        spend=SpendService(uow, late_clock, (), models=catalog),
    )
    result = JobResult(outcome=Outcome.SUCCEEDED, usage=usage)
    with caplog.at_level("WARNING"), pytest.raises(ConflictError, match="lease expired"):
        late_ops.complete(order.id, W1, result, lease_generation=order.lease_generation)
    assert "fenced completion settled 1 spend events" in caplog.text
    assert stored(engine, order) == order
    with SqlTraustUnitOfWork(engine) as check:
        events = check.spend_events.list_for_order(order.id)
    assert len(events) == 1
    assert events[0].cost_usd == Decimal("2.0")
    # Retrying the same fenced completion must not duplicate spend events.
    with pytest.raises(ConflictError, match="lease expired"):
        late_ops.complete(order.id, W1, result, lease_generation=order.lease_generation)
    with SqlTraustUnitOfWork(engine) as check:
        assert len(check.spend_events.list_for_order(order.id)) == 1


def _late_ops(engine: Engine, uow: SqlTraustUnitOfWork) -> tuple[OpsService, RegistryModelCatalog]:
    from decimal import Decimal

    from traust_core.v1.providers.model_catalog import ModelSpec, RegistryModelCatalog

    spec = ModelSpec(
        name="claude-test",
        provider="anthropic",
        tier="sonnet-class",
        price_per_mtok_in=Decimal("10"),
        price_per_mtok_out=Decimal("20"),
    )
    catalog = RegistryModelCatalog({"claude-test": spec}, {}, ("sonnet-class",), None)
    late_clock = FixedClock(T0 + LEASE + timedelta(minutes=1))
    ops = OpsService(
        uow,
        late_clock,
        ArtifactPublisher(
            PublishSpecs(PublishSpec(RunManifestArtifact)),
            _stores.setdefault(engine, InMemoryObjectStore()),
            uow,
        ),
        spend=SpendService(uow, late_clock, (), models=catalog),
    )
    return ops, catalog


def _usage(at: datetime) -> tuple[ModelUsage, ...]:
    from traust_core.v1.models.operations import ModelUsage

    return (
        ModelUsage(
            provider="anthropic",
            model="claude-test",
            skill="triage",
            tokens_in=100_000,
            tokens_out=50_000,
            occurred_at=at,
        ),
    )


def test_distinct_fenced_spend_within_a_millisecond_is_two_events_where_the_store_keeps_it(
    engine: Engine,
) -> None:
    """The duplicate key compares at the store's precision: PostgreSQL keeps microseconds, so
    two distinct charges 500us apart are two events; SQLite keeps milliseconds, so it can't."""
    order = leased(engine)
    assert order.id is not None
    late_ops, _ = _late_ops(engine, SqlTraustUnitOfWork(engine))
    for at in (T0 + timedelta(microseconds=100), T0 + timedelta(microseconds=600)):
        result = JobResult(outcome=Outcome.SUCCEEDED, usage=_usage(at))
        with pytest.raises(ConflictError, match="lease expired"):
            late_ops.complete(order.id, W1, result, lease_generation=order.lease_generation)
    with SqlTraustUnitOfWork(engine) as check:
        events = check.spend_events.list_for_order(order.id)
    assert len(events) == (1 if engine.dialect.name == "sqlite" else 2)


def test_fenced_spend_rolled_back_by_its_owner_is_neither_kept_nor_logged(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Inside a caller's own transaction the settlement's commit is the caller's: when the
    re-raised ConflictError makes the owner roll back, no row stays and no 'settled' line logs."""
    order = leased(engine)
    assert order.id is not None
    uow = SqlTraustUnitOfWork(engine)
    late_ops, _ = _late_ops(engine, uow)
    result = JobResult(outcome=Outcome.SUCCEEDED, usage=_usage(T0))
    with caplog.at_level("WARNING"), uow:
        with pytest.raises(ConflictError, match="lease expired"):
            late_ops.complete(order.id, W1, result, lease_generation=order.lease_generation)
        uow.rollback()
    assert "fenced completion settled" not in caplog.text
    with SqlTraustUnitOfWork(engine) as check:
        assert check.spend_events.list_for_order(order.id) == []


@pytest.mark.parametrize("case", ["wrong-worker", "requeued", "superseded"])
def test_fenced_completion_writes_zero_spend_when_holder_cannot_be_verified(
    engine: Engine, caplog: pytest.LogCaptureFixture, case: str
) -> None:
    from decimal import Decimal

    from traust_core.v1.models.operations import ModelUsage
    from traust_core.v1.providers.model_catalog import ModelSpec, RegistryModelCatalog

    spec = ModelSpec(
        name="claude-test",
        provider="anthropic",
        tier="sonnet-class",
        price_per_mtok_in=Decimal("10"),
        price_per_mtok_out=Decimal("20"),
    )
    catalog = RegistryModelCatalog({"claude-test": spec}, {}, ("sonnet-class",), None)
    usage = (
        ModelUsage(
            provider="anthropic",
            model="claude-test",
            skill="triage",
            tokens_in=100_000,
            tokens_out=50_000,
            occurred_at=T0,
        ),
    )
    order = leased(engine)
    assert order.id is not None
    uow = SqlTraustUnitOfWork(engine)
    late_clock = FixedClock(T0 + LEASE + timedelta(minutes=1))
    late_ops = OpsService(
        uow,
        late_clock,
        ArtifactPublisher(
            PublishSpecs(PublishSpec(RunManifestArtifact)),
            _stores.setdefault(engine, InMemoryObjectStore()),
            uow,
        ),
        spend=SpendService(uow, late_clock, (), models=catalog),
    )
    caller = W2
    if case == "requeued":
        assert late_ops.requeue_expired() == 1
    elif case == "superseded":
        assert late_ops.requeue_expired() == 1
        reclaimed = late_ops.claim(W2, LEASE, order_id=order.id)
        assert reclaimed is not None and reclaimed.lease_generation == order.lease_generation + 1
        caller = W1
    with (
        caplog.at_level("WARNING", logger="traust_core.v1.services.operations"),
        pytest.raises(ConflictError),
    ):
        late_ops.complete(
            order.id,
            caller,
            JobResult(outcome=Outcome.SUCCEEDED, usage=usage),
            lease_generation=order.lease_generation,
        )
    with SqlTraustUnitOfWork(engine) as check:
        assert check.spend_events.list_for_order(order.id) == []
    assert str(order.id) in caplog.text
    assert "settled=1" in caplog.text


def test_fenced_completion_does_not_commit_orphan_manifest_row(engine: Engine) -> None:

    class _ExpiringClock(FixedClock):
        def __init__(self) -> None:
            super().__init__(T0)
            self._calls = 0

        def now(self) -> datetime:
            self._calls += 1
            # First check (phase 1) sees a live lease; second check (phase 2) sees expired.
            return T0 if self._calls == 1 else T0 + LEASE + timedelta(minutes=1)

    order = leased(engine)
    assert order.id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        before = uow.artifacts.latest_imported(RunManifestArtifact.schema)
    shared_uow = SqlTraustUnitOfWork(engine)
    shared_manifests = ArtifactPublisher(
        PublishSpecs(PublishSpec(RunManifestArtifact)),
        _stores.setdefault(engine, InMemoryObjectStore()),
        shared_uow,
    )
    service = OpsService(shared_uow, _ExpiringClock(), shared_manifests)
    with pytest.raises(ConflictError, match="lease expired"):
        service.complete(
            order.id,
            W1,
            JobResult.partly({"unreachable": 1}),
            lease_generation=order.lease_generation,
        )
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.artifacts.latest_imported(RunManifestArtifact.schema) == before


def test_ops_refuses_a_run_manifest_publisher_on_another_unit_of_work(engine: Engine) -> None:
    """The manifest is published inside the order transaction; a separate publisher would
    commit it on its own and could leave it attached to no order, so it is refused."""
    with pytest.raises(ConfigError, match="must share the ops unit of work"):
        OpsService(SqlTraustUnitOfWork(engine), FixedClock(T0), publisher(engine))


def test_a_refused_completion_leaves_no_unattached_run_manifest(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A completion refused after its manifest is staged (here: another writer moved the
    manifest before the order lock) publishes no run-manifest row: the row is written only
    inside the order transaction, which the refusal rolls back."""
    order = leased(engine)
    service = ops(engine)
    stage = service._stage_manifest

    def artifacts() -> int:
        with SqlTraustUnitOfWork(engine) as uow:
            count = sa.select(sa.func.count()).select_from(uow.artifacts.table)
            return int(uow.connection.scalar(count))

    def racing(prior: UUID | None, change: Any) -> Any:
        staged = stage(prior, change)
        ops(engine).save_progress(
            order.id, OrderProgress(step=9), worker=W1, lease_generation=order.lease_generation
        )
        return staged

    monkeypatch.setattr(service, "_stage_manifest", racing)
    before = None
    with pytest.raises(ConflictError, match="manifest changed"):
        before = artifacts()
        service.complete(
            order.id,
            W1,
            JobResult.partly({"unreachable": 1}),
            lease_generation=order.lease_generation,
        )
    # the racing writer's own manifest is the only new row
    assert before is not None and artifacts() == before + 1
