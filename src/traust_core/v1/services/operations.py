from __future__ import annotations

import json
import logging
from collections.abc import Callable, Collection, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import ConfigError, ConflictError, ValidationError
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Page, PageRequest, TimeBucket, TimeWindow
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    AssetName,
    AssetRequest,
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
    Refusal,
    Route,
    RunOrder,
    SchedulePlan,
    SpendAttribution,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendRollup,
    SpendSource,
    StaleItem,
    ThroughputPoint,
    WorkerId,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.provider_catalog import ProviderCatalog

log = logging.getLogger(__name__)

S = TypeVar("S", contravariant=True)
E = TypeVar("E", contravariant=True)
Change = Callable[[dict[str, Any]], dict[str, Any]]


class Materializer(Protocol):
    asset: AssetName

    def materialize(self, request: AssetRequest) -> JobResult: ...


class Router(Protocol[S, E]):
    def route(self, state: S, events: Sequence[E], refusals: Sequence[Refusal]) -> Route: ...


class OpsService:
    def __init__(self, uow: OpsUnitOfWork, clock: Clock, manifests: ArtifactPublisher) -> None:
        self._uow = uow
        self._clock = clock
        self._manifests = manifests
        self._config_manifests: dict[tuple[ConfigDigest, ...], UUID] = {}

    def submit(self, request: OrderRequest, principal: Principal) -> RunOrder:
        order = RunOrder(
            **request.model_dump(), state=OrderState.QUEUED, requested_by=principal.ref
        )
        with self._uow as uow:
            saved = uow.run_orders.add(order)
            uow.commit()
        log.info("order %s queued: %s by %s", saved.id, saved.asset, saved.requested_by)
        return saved

    def plan(
        self, request: OrderRequest, principal: Principal, config: Sequence[ConfigDigest] = ()
    ) -> RunOrder:
        """Store a routed request as planned, with the config in force (the pack version) in its
        run manifest; an open order for the same subject is re-ranked while still planned,
        otherwise returned unchanged."""
        manifest = {"artifact_id": self._config_manifest(tuple(config))} if config else {}
        with self._uow as uow:
            current = uow.run_orders.find_open(request.asset, request.repository_id)
            if current is None:
                saved = uow.run_orders.add(
                    RunOrder(
                        **request.model_dump(),
                        **manifest,
                        state=OrderState.PLANNED,
                        requested_by=principal.ref,
                    )
                )
            elif current.state == OrderState.PLANNED:
                route = request.model_dump(include={"priority", "lane", "rule", "event_source"})
                saved = uow.run_orders.update(current.model_copy(update={**route, **manifest}))
            else:
                return current
            uow.commit()
        log.info("order %s planned: %s priority %d", saved.id, saved.asset, saved.priority)
        return saved

    def admit(self, order_id: UUID, verdict: BudgetVerdict | None = None) -> RunOrder:
        return self._move(
            order_id, OrderState.PLANNED, {"state": OrderState.QUEUED}, _budget(verdict)
        )

    def withhold(
        self, order_id: UUID, reason: str, verdict: BudgetVerdict | None = None
    ) -> RunOrder:
        """Drop a planned order at admission (the budget guard); the next tick may plan it again."""
        update = {"state": OrderState.WITHHELD, "reason": reason, "finished_at": self._clock.now()}
        return self._move(order_id, OrderState.PLANNED, update, _budget(verdict))

    def request_approval(self, order_id: UUID) -> RunOrder:
        """Hold a planned order for a person (human-gated assets); `approve` queues it."""
        return self._move(order_id, OrderState.PLANNED, {"state": OrderState.AWAITING_APPROVAL})

    def subjects(
        self,
        asset: AssetName,
        states: Collection[OrderState],
        finished_after: datetime | None = None,
    ) -> set[UUID | None]:
        """Repositories (None = fleet-wide) with an order of `asset` in `states`, optionally
        finished after a time: the tick's open-order, freshness and re-route checks."""
        if not states:
            raise ValidationError(f"subjects of {asset} needs at least one state")
        with self._uow as uow:
            return uow.run_orders.subjects(asset, states, finished_after)

    def claim(self, worker: WorkerId, lease_for: timedelta) -> RunOrder | None:
        with self._uow as uow:
            order = uow.run_orders.claim(worker, self._clock.now(), lease_for)
            uow.commit()
        if order is not None:
            log.info("order %s leased to %s", order.id, worker)
        return order

    def heartbeat(self, order_id: UUID, worker: WorkerId, lease_for: timedelta) -> RunOrder:
        now = self._clock.now()
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.LEASED, worker)
            if order.lease_expires_at is None or order.lease_expires_at < now:
                raise ConflictError(f"order {order_id}: lease expired at {order.lease_expires_at}")
            saved = uow.run_orders.update(
                order.model_copy(update={"lease_expires_at": now + lease_for})
            )
            uow.commit()
        return saved

    def save_progress(self, order_id: UUID, progress: OrderProgress) -> UUID:
        """Record a leased order's progress in its run manifest; returns the manifest's id."""
        updated_at = self._clock.now().isoformat()
        entry = {**progress.model_dump(mode="json"), "updated_at": updated_at}
        saved = self._move(order_id, OrderState.LEASED, {}, lambda m: {**m, "progress": entry})
        assert saved.artifact_id is not None
        return saved.artifact_id

    def complete(self, order_id: UUID, worker: WorkerId, result: JobResult) -> RunOrder:
        """Finish the order; results link to it by `run_order_id`, written by their own domain.
        Degraded keys go to its run manifest."""
        outcome = OrderState(result.outcome)
        order = self.get(order_id)
        if order.state == outcome:
            return order  # a retried complete
        update = {
            "state": outcome,
            "reason": result.reason,
            "finished_at": self._clock.now(),
            "lease_holder": None,
            "lease_expires_at": None,
        }
        degraded = dict(result.degraded)
        change = (lambda m: {**m, "degraded": degraded}) if degraded else None
        saved = self._move(order_id, OrderState.LEASED, update, change, worker)
        if degraded:
            log.warning("order %s degraded: %s", saved.id, degraded)
        return saved

    def approve(self, order_id: UUID, principal: Principal) -> RunOrder:
        approval = {"approver": principal.ref, "approved_at": self._clock.now().isoformat()}
        saved = self._move(
            order_id,
            OrderState.AWAITING_APPROVAL,
            {"state": OrderState.QUEUED},
            lambda m: {**m, "approval": approval},
        )
        log.info("order %s approved by %s", saved.id, principal.ref)
        return saved

    def _move(
        self,
        order_id: UUID,
        from_state: OrderState,
        update: dict[str, object],
        change: Change | None = None,
        worker: WorkerId | None = None,
    ) -> RunOrder:
        """Move an order on; a manifest change is published first (no I/O inside the
        transaction) and lands with the move unless another writer moved the manifest."""
        if change is not None:
            prior = self.get(order_id)
            _require(prior, from_state, worker)
            update = {**update, "artifact_id": self._publish(prior.artifact_id, change)}
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, from_state, worker)
            if change is not None and order.artifact_id != prior.artifact_id:
                raise ConflictError(f"order {order_id}: run manifest changed while writing")
            saved = uow.run_orders.update(order.model_copy(update=update))
            uow.commit()
        log.info("order %s %s", saved.id, saved.state)
        return saved

    def _publish(self, prior: UUID | None, change: Change) -> UUID:
        current = (
            {"artifact": RunManifestArtifact.name}
            if prior is None
            else json.loads(self._manifests.get(prior).payload)
        )
        manifest = RunManifestArtifact.from_document(change(current))
        return self._manifests.publish_artifact(manifest).artifact_id

    def _config_manifest(self, config: tuple[ConfigDigest, ...]) -> UUID:
        # A planned order's manifest is its config alone; one artifact serves every such order.
        if config not in self._config_manifests:
            entries = [c.model_dump(mode="json", exclude_none=True) for c in config]
            self._config_manifests[config] = self._publish(None, lambda m: {**m, "config": entries})
        return self._config_manifests[config]

    def requeue_expired(self) -> int:
        with self._uow as uow:
            count = uow.run_orders.requeue_expired(self._clock.now())
            uow.commit()
        if count:
            log.warning("%d expired leases requeued", count)
        return count

    def schedule(self, plan: SchedulePlan) -> list[RunOrder]:
        raise NotImplementedError("stub: replaces refresh_dashboards.build_stages")

    def get(self, order_id: UUID) -> RunOrder:
        with self._uow as uow:
            return uow.run_orders.get(order_id)

    def list(self, filter: OrderFilter, page: PageRequest) -> Page[RunOrder]:
        after = page.position()
        if not (filter.states or filter.repository_id or filter.run_batch_id):
            raise ValidationError("list needs states, a repository_id or a run_batch_id (indexed)")
        with self._uow as uow:
            rows = uow.run_orders.search(**filter.model_dump(), limit=page.limit + 1, after=after)
        return Page.of(rows, page.limit, lambda o: (o.created_at, o.id))

    def timeline(self, filter: OrderFilter, bucket: TimeBucket) -> list[ThroughputPoint]:
        raise NotImplementedError("stub: replaces metrics/history.py, collect_harness_metrics")


def _budget(verdict: BudgetVerdict | None) -> Change | None:
    if verdict is None:
        return None
    entry = verdict.model_dump(mode="json")
    return lambda m: {**m, "budget": entry}


def _require(order: RunOrder, state: OrderState, worker: WorkerId | None = None) -> None:
    if order.state != state:
        raise ConflictError(f"order {order.id} is {order.state}, not {state}")
    if worker is not None and order.lease_holder != worker:
        raise ConflictError(f"order {order.id} is leased to {order.lease_holder}, not {worker}")


class SpendService:
    def __init__(self, uow: OpsUnitOfWork, clock: Clock, budgets: Sequence[Budget]) -> None:
        self._uow = uow
        self._clock = clock
        self._budgets = {b.lane: b for b in budgets}
        if len(self._budgets) != len(budgets):
            raise ConfigError(f"more than one budget per lane: {[b.lane for b in budgets]}")

    def record(self, event: SpendEvent) -> SpendEvent:
        # NEED(model-registry): check provider and model against ModelCatalog once it lands.
        with self._uow as uow:
            order = None if event.run_order_id is None else uow.run_orders.get(event.run_order_id)
            saved = uow.spend_events.add(event.model_copy(update={"lane": order and order.lane}))
            uow.commit()
        log.info(
            "spend %s recorded: %s/%s $%s", saved.id, saved.provider, saved.model, saved.cost_usd
        )
        return saved

    def collect(self, source: SpendSource, window: TimeWindow) -> int:
        raise NotImplementedError("stub: replaces metrics/collect_spend.py")

    def attribute(self, window: TimeWindow) -> SpendAttribution:
        """Spend tied to an order vs spend no order claims; the two always sum to the total."""
        return SpendAttribution(
            window=window,
            attributed_usd=self._total(SpendFilter(window=window, attributed=True)),
            unattributed_usd=self._total(SpendFilter(window=window, attributed=False)),
        )

    def check_budget(self, lane: LaneName, estimate: Decimal | None) -> BudgetVerdict:
        """Judge month-to-date lane spend plus `estimate` (None = unknown cost); never withholds."""
        spent = self._total(SpendFilter(window=TimeWindow.month_of(self._clock.now()), lane=lane))
        budget = self._budgets.get(lane)
        verdict = (
            budget.verdict(spent, estimate)
            if budget is not None
            else BudgetVerdict(
                lane=lane, status=BudgetStatus.NO_BUDGET, spent_usd=spent, estimate_usd=estimate
            )
        )
        log.log(
            logging.WARNING if verdict.status is BudgetStatus.OVER else logging.INFO,
            "budget %s for lane %s (%s): spent $%s + estimate %s of %s",
            verdict.status,
            lane,
            verdict.enforcement,
            spent,
            estimate,
            verdict.budget_usd,
        )
        return verdict

    def summary(self, filter: SpendFilter, group_by: SpendDimension) -> list[SpendRollup]:
        with self._uow as uow:
            return uow.spend_events.sum_by(filter, group_by)

    def _total(self, filter: SpendFilter) -> Decimal:
        with self._uow as uow:
            rollups = uow.spend_events.sum_by(filter)
        return rollups[0].cost_usd if rollups else Decimal(0)


class FreshnessQuery:
    def __init__(self, providers: ProviderCatalog, feeds: Sequence[FeedProvider]) -> None:
        self._providers = providers
        self._feeds = feeds

    def stale(self) -> list[StaleItem]:
        raise NotImplementedError("stub: replaces cli/check_drift.py")
