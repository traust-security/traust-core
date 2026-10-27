from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Sequence
from datetime import date, datetime, timedelta
from decimal import Decimal
from statistics import median
from typing import Any, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Page, PageRequest, TimeBucket, TimeWindow
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    FEED_ORDER_STATES,
    FINISHED_ORDER_STATES,
    SPEND_UNPRICED,
    AssetName,
    AssetRequest,
    Budget,
    BudgetStatus,
    BudgetVerdict,
    ConfigDigest,
    DegradedKey,
    FeedEvent,
    Freshness,
    JobResult,
    LaneCost,
    LaneName,
    ModelName,
    ModelUsage,
    OrderFilter,
    OrderManifest,
    OrderProgress,
    OrderReason,
    OrderRequest,
    OrderState,
    Refusal,
    RescanEventSource,
    Route,
    RunOrder,
    SchedulePlan,
    SpendAttribution,
    SpendBreakdown,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendRollup,
    SpendSource,
    StaleItem,
    ThroughputPoint,
    TokenUsage,
    UsageDimension,
    UsageRollup,
    WorkerId,
    WorkLane,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.providers.model_catalog import ModelCatalog, ModelSpec
from traust_core.v1.providers.tools import DatabaseStatus
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import PortfolioService
from traust_core.v1.services.provider_catalog import ProviderBinding, ProviderCatalog

log = logging.getLogger(__name__)

S = TypeVar("S", contravariant=True)
E = TypeVar("E", contravariant=True)
Change = Callable[[dict[str, Any]], dict[str, Any]]


def _classifiers(
    *, lane: object = None, event_source: object = None, reason: object = None
) -> None:
    for enum, value in ((WorkLane, lane), (RescanEventSource, event_source), (OrderReason, reason)):
        if value is not None:
            try:
                enum(value)
            except (TypeError, ValueError) as error:
                raise ValidationError(f"{enum.__name__}: unregistered value {value!r}") from error


class Materializer(Protocol):
    asset: AssetName

    def materialize(self, request: AssetRequest) -> JobResult: ...


class Router(Protocol[S, E]):
    """A pack's routing policy: the subject's routes, first the decision table's (its lane may be
    None), then any additive lanes; the engine plans one order per route with a lane."""

    def route(
        self, state: S, events: Sequence[E], refusals: Sequence[Refusal]
    ) -> tuple[Route, ...]: ...


class OpsService:
    def __init__(
        self,
        uow: OpsUnitOfWork,
        clock: Clock,
        manifests: ArtifactPublisher,
        *,
        degraded_keys: Callable[[], Collection[str]] = tuple,
        spend: SpendService | None = None,
    ) -> None:
        self._uow = uow
        self._clock = clock
        self._manifests = manifests
        self._config_manifests: dict[tuple[ConfigDigest, ...], UUID] = {}
        self._degraded_keys = degraded_keys
        self._spend = spend or SpendService(uow, clock, ())

    def submit(self, request: OrderRequest, principal: Principal) -> RunOrder:
        _classifiers(lane=request.lane, event_source=request.event_source)
        order = RunOrder(
            **request.model_dump(), state=OrderState.QUEUED, requested_by=principal.ref
        )
        with self._uow as uow:
            saved = uow.run_orders.add(order)
            uow.commit()
        log.info("order %s queued actor_kind=%s", saved.id, principal.kind)
        return saved

    def plan(
        self, request: OrderRequest, principal: Principal, config: Sequence[ConfigDigest] = ()
    ) -> RunOrder:
        """Store a routed request as planned, with the config in force (the pack version) in its
        run manifest; an open order for the same subject is re-ranked while still planned,
        otherwise returned unchanged."""
        _classifiers(lane=request.lane, event_source=request.event_source)
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
        log.info(
            "order %s planned priority=%d actor_kind=%s", saved.id, saved.priority, principal.kind
        )
        return saved

    def admit(self, order_id: UUID, verdict: BudgetVerdict | None = None) -> RunOrder:
        return self._move(
            order_id, OrderState.PLANNED, {"state": OrderState.QUEUED}, _budget(verdict)
        )

    def withhold(
        self, order_id: UUID, reason: str, verdict: BudgetVerdict | None = None
    ) -> RunOrder:
        """Drop a planned order (the budget guard, a stale upstream); the next tick may plan it
        again."""
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
        reason: OrderReason | None = None,
    ) -> set[UUID | None]:
        """Repositories (None = fleet-wide) with an order of `asset` in `states`, optionally
        finished after a time or stopped for a reason: the tick's open-order, freshness, re-route
        and stale-stop checks."""
        if not states:
            raise ValidationError(f"subjects of {asset} needs at least one state")
        with self._uow as uow:
            return uow.run_orders.subjects(asset, states, finished_after, reason)

    def claim(
        self,
        worker: WorkerId,
        lease_for: timedelta,
        assets: Collection[AssetName] | None = None,
    ) -> RunOrder | None:
        """Lease the next queued order; a runner that makes only some assets names them, and an
        empty `assets` claims nothing."""
        if assets is not None and not assets:
            return None
        with self._uow as uow:
            order = uow.run_orders.claim(worker, self._clock.now(), lease_for, assets)
            uow.commit()
        if order is not None:
            log.info("order %s leased", order.id)
        return order

    def start(
        self, request: OrderRequest, principal: Principal, worker: WorkerId, lease_for: timedelta
    ) -> RunOrder:
        """A run its runner has already begun (by hand, or a cron job beside the engine), leased to
        `worker`: the subject's planned or queued order is taken over, else a new one is stored."""
        _classifiers(lane=request.lane, event_source=request.event_source)
        now = self._clock.now()
        lease = {
            "state": OrderState.LEASED,
            "lease_holder": worker,
            "lease_expires_at": now + lease_for,
            "started_at": now,
        }
        with self._uow as uow:
            current = uow.run_orders.find_open(request.asset, request.repository_id)
            if current is None:
                order = RunOrder(**request.model_dump(), **lease, requested_by=principal.ref)
                saved = uow.run_orders.add(order)
            else:
                assert current.id is not None
                current = uow.run_orders.get_for_update(current.id)
                if current.state not in (OrderState.PLANNED, OrderState.QUEUED):
                    raise ConflictError(
                        f"order {current.id}: {current.asset} is already {current.state}"
                    )
                saved = uow.run_orders.update(current.model_copy(update=lease))
            uow.commit()
        log.info("order %s started actor_kind=%s", saved.id, principal.kind)
        return saved

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
        """Finish the order and settle its measured usage as its spend, in one transaction; degraded
        keys and unpriced usage (`spend-unpriced`) go to its run manifest."""
        outcome = OrderState(result.outcome)
        order = self.get(order_id)
        if order.state == outcome:
            return order  # a retried complete
        spend, unpriced = self._spend.settlement(order_id, result.usage)
        update = {
            "state": outcome,
            "reason": result.reason,
            "finished_at": self._clock.now(),
            "lease_holder": None,
            "lease_expires_at": None,
        }
        degraded = dict(result.degraded)
        gaps = {SPEND_UNPRICED: len(unpriced)} if unpriced else {}
        change = (lambda m: self._completion(m, degraded, gaps)) if degraded or gaps else None
        saved = self._move(order_id, OrderState.LEASED, update, change, worker, spend)
        if degraded:
            log.warning("order %s degraded in %d categories", saved.id, len(degraded))
        if unpriced:
            log.warning("order %s: %s count=%d", saved.id, SPEND_UNPRICED, len(unpriced))
        return saved

    def _completion(
        self, manifest: dict[str, Any], degraded: dict[str, int], gaps: dict[str, int]
    ) -> dict[str, Any]:
        registered = set(self._degraded_keys())
        for key in degraded:
            if key not in registered:
                try:
                    DegradedKey(key)
                except (TypeError, ValueError) as error:
                    raise ValidationError(f"unregistered degraded key {key!r}") from error
        return {**manifest, "degraded": {**degraded, **gaps}}

    def approve(self, order_id: UUID, principal: Principal) -> RunOrder:
        """Queue an order awaiting approval; only a verified person approves, never a machine."""
        if not principal.is_verified_human():
            raise ForbiddenError(
                f"order {order_id}: approval needs a verified human, not {principal.ref}"
            )
        approval = {"approver": principal.ref, "approved_at": self._clock.now().isoformat()}
        saved = self._move(
            order_id,
            OrderState.AWAITING_APPROVAL,
            {"state": OrderState.QUEUED},
            lambda m: {**m, "approval": approval},
        )
        log.info("order %s approved actor_kind=%s", saved.id, principal.kind)
        return saved

    def _move(
        self,
        order_id: UUID,
        from_state: OrderState,
        update: dict[str, object],
        change: Change | None = None,
        worker: WorkerId | None = None,
        spend: Sequence[SpendEvent] = (),
    ) -> RunOrder:
        """Move an order on, with its spend (in its lane); a manifest change is published first (no
        I/O inside the transaction) and lands unless another writer moved the manifest."""
        if change is not None:
            prior = self.get(order_id)
            _require(prior, from_state, worker)
            _classifiers(reason=update.get("reason"))
            update = {**update, "artifact_id": self._publish(prior.artifact_id, change)}
        with self._uow as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, from_state, worker)
            if change is None:
                _classifiers(reason=update.get("reason"))
            if change is not None and order.artifact_id != prior.artifact_id:
                raise ConflictError(f"order {order_id}: run manifest changed while writing")
            saved = uow.run_orders.update(order.model_copy(update=update))
            for event in spend:
                uow.spend_events.add(event.model_copy(update={"lane": order.lane}))
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

    def schedule(self, plan: SchedulePlan, principal: Principal) -> list[RunOrder]:
        """Queue one order per asset, in one transaction; an asset with an open order for the
        same subject keeps it, so a re-run queues nothing twice."""
        if len(set(plan.assets)) != len(plan.assets):
            raise ValidationError(f"schedule names an asset twice: {list(plan.assets)}")
        _classifiers(lane=plan.lane)
        route = plan.model_dump(exclude={"assets"})
        with self._uow as uow:
            orders = [
                uow.run_orders.find_open(asset, plan.repository_id)
                or uow.run_orders.add(
                    RunOrder(
                        **route, asset=asset, state=OrderState.QUEUED, requested_by=principal.ref
                    )
                )
                for asset in plan.assets
            ]
            uow.commit()
        log.info("scheduled %d orders actor_kind=%s", len(orders), principal.kind)
        return orders

    def get(self, order_id: UUID) -> RunOrder:
        with self._uow as uow:
            return uow.run_orders.get(order_id)

    def manifest(self, order_id: UUID) -> OrderManifest:
        """The config an order was planned with and its approval, from its run manifest."""
        artifact_id = self.get(order_id).artifact_id
        if artifact_id is None:
            return OrderManifest()
        doc = json.loads(self._manifests.get(artifact_id).payload)
        return OrderManifest.model_validate({k: doc[k] for k in ("config", "approval") if k in doc})

    def list(self, filter: OrderFilter, page: PageRequest) -> Page[RunOrder]:
        after = page.position()
        if not (filter.states or filter.repository_id or filter.run_batch_id):
            raise ValidationError("list needs states, a repository_id or a run_batch_id (indexed)")
        if filter.window is not None:
            raise ValidationError("list pages by created_at; a window bounds a timeline")
        query = filter.model_dump(exclude={"window"})
        with self._uow as uow:
            rows = uow.run_orders.search(**query, limit=page.limit + 1, after=after)
        return Page.of(rows, page.limit, lambda o: (o.created_at, o.id))

    def feed_after(self, after: tuple[datetime, UUID] | None, limit: int) -> list[RunOrder]:
        """Orders that reached a `FEED_ORDER_STATES` state after a feed position, oldest change
        first (the ops feed's half)."""
        with self._uow as uow:
            return uow.run_orders.feed_after(after, FEED_ORDER_STATES, limit)

    def last_routed(self) -> datetime | None:
        """When the router last planned a new order; None when it never has."""
        with self._uow as uow:
            return uow.run_orders.last_routed()

    def timeline(self, filter: OrderFilter, bucket: TimeBucket) -> list[ThroughputPoint]:
        """An asset's finished orders per bucket over the window, by outcome: derived from the
        orders themselves, never a stored snapshot. Every bucket in the window has a point."""
        if filter.asset is None or filter.window is None:
            raise ValidationError("timeline needs an asset and a window (indexed, bounded)")
        if unfinished := set(filter.states) - set(FINISHED_ORDER_STATES):
            raise ValidationError(f"timeline counts finished orders, not {sorted(unfinished)}")
        states = filter.states or FINISHED_ORDER_STATES
        window = filter.window
        with self._uow as uow:
            finished = uow.run_orders.finished_between(
                filter.asset,
                states,
                window.start,
                window.end,
                repository_id=filter.repository_id,
                run_batch_id=filter.run_batch_id,
            )
        counts: defaultdict[datetime, Counter[OrderState]] = defaultdict(Counter)
        for state, at in finished:
            counts[bucket.window_of(at).start][state] += 1
        points = []
        current = bucket.window_of(window.start)
        while current.start < window.end:
            tally = counts[current.start]
            points.append(
                ThroughputPoint(bucket=current.start, finished={s: tally[s] for s in states})
            )
            current = bucket.window_of(current.end)
        return points


def _spec(models: ModelCatalog, name: ModelName) -> ModelSpec | None:
    try:
        return models.resolve(name)
    except NotFoundError:
        return None


def _priced(spec: ModelSpec | None) -> bool:
    return spec is not None and None not in (spec.price_per_mtok_in, spec.price_per_mtok_out)


def _over_long_prompt(spec: ModelSpec | None, u: ModelUsage) -> bool:
    lp = spec.long_prompt if spec else None
    return lp is not None and u.tokens_in + u.cache_read + u.cache_creation > lp.above_tokens


def _tokens(usages: Sequence[ModelUsage]) -> TokenUsage:
    return TokenUsage(
        tokens_in=sum(u.tokens_in for u in usages),
        tokens_out=sum(u.tokens_out for u in usages),
        cache_read=sum(u.cache_read for u in usages),
        cache_creation=sum(u.cache_creation for u in usages),
    )


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


class SpendViews:
    """Usage in a spend source a caller holds, priced at list rates; nothing is recorded, so no
    store is opened."""

    def __init__(self, models: ModelCatalog | None) -> None:
        self._models = models

    def usage_summary(
        self, source: SpendSource, window: TimeWindow, group_by: Collection[UsageDimension]
    ) -> list[UsageRollup]:
        """A source's usage inside the window (today's partial day included) summed per group, in
        key order, priced per request at list rates; nothing is recorded."""
        models = self.require_models(f"summarise {source.name}")
        groups: defaultdict[tuple[date | None, str | None, str | None], list[ModelUsage]] = (
            defaultdict(list)
        )
        for u in source.usages:
            if window.start <= u.occurred_at < window.end:
                day = TimeBucket.DAY.window_of(u.occurred_at).start.date()
                groups[
                    day if UsageDimension.DAY in group_by else None,
                    u.skill if UsageDimension.SKILL in group_by else None,
                    u.model if UsageDimension.MODEL in group_by else None,
                ].append(u)
        specs = {m: _spec(models, m) for m in {u.model for u in source.usages}}
        return [
            self._usage_rollup(key, usages, specs)
            for key, usages in sorted(
                groups.items(),
                key=lambda kv: (kv[0][0] or date.min, kv[0][1] or "", kv[0][2] or ""),
            )
        ]

    def _usage_rollup(
        self,
        key: tuple[date | None, str | None, str | None],
        usages: list[ModelUsage],
        specs: dict[ModelName, ModelSpec | None],
    ) -> UsageRollup:
        priced = [u for u in usages if _priced(specs[u.model])]
        long = [u for u in usages if _over_long_prompt(specs[u.model], u)]
        day, skill, model = key
        return UsageRollup(
            day=day,
            skill=skill,
            model=model,
            tokens=_tokens(usages),
            long_prompt=_tokens(long) if long else None,
            messages=len(usages),
            sessions=len({u.session for u in usages if u.session is not None}),
            cost_usd=sum((self.price(u) for u in priced), Decimal(0)) if priced else None,
            unpriced=tuple(sorted({u.model for u in usages} - {u.model for u in priced})),
        )

    @property
    def models(self) -> ModelCatalog | None:
        return self._models

    def require_models(self, what: str) -> ModelCatalog:
        if self._models is None:
            raise ConfigError(
                f"{what}: pricing needs the model registry (Context.register_model_catalog)"
            )
        return self._models

    def price(self, usage: ModelUsage) -> Decimal:
        return self.require_models("price").cost(usage.model, _tokens([usage]))


class SpendService:
    def __init__(
        self,
        uow: OpsUnitOfWork,
        clock: Clock,
        budgets: Sequence[Budget],
        models: ModelCatalog | None = None,
    ) -> None:
        self._uow = uow
        self._clock = clock
        self._views = SpendViews(models)
        self._budgets = {b.lane: b for b in budgets}
        if len(self._budgets) != len(budgets):
            raise ConfigError(f"more than one budget per lane: {[b.lane for b in budgets]}")

    def record(self, event: SpendEvent) -> SpendEvent:
        # NEED(model-registry): check provider and model against ModelCatalog once it lands.
        with self._uow as uow:
            order = None if event.run_order_id is None else uow.run_orders.get(event.run_order_id)
            saved = uow.spend_events.add(event.model_copy(update={"lane": order and order.lane}))
            uow.commit()
        log.info("spend %s recorded cost_usd=%s", saved.id, saved.cost_usd)
        return saved

    def collect(self, source: SpendSource, window: TimeWindow) -> int:
        """Record a source's usage as one event per UTC day, provider, model and skill, priced per
        request; only whole days inside the window that have ended. Re-collecting adds nothing:
        a recorded (day, provider, model, skill) is skipped, and so is a whole (day, provider,
        model) once recorded without a skill, so attributing it later can't count it twice.
        Returns the events written."""
        self._views.require_models(f"collect {source.name}")
        now = self._clock.now()
        days: defaultdict[tuple[datetime, str, str, str | None], list[ModelUsage]] = defaultdict(
            list
        )
        for usage in source.usages:
            day = TimeBucket.DAY.window_of(usage.occurred_at)
            if window.start <= day.start and day.end <= min(window.end, now):
                days[day.start, usage.provider, usage.model, usage.skill].append(usage)
        if not days:
            return 0
        with self._uow as uow:
            held = {
                (e.occurred_at, e.provider, e.model, e.skill)
                for e in uow.spend_events.list_between(window.start, window.end)
                if e.run_order_id is None
            }
            fresh = [
                SpendEvent(
                    provider=provider,
                    model=model,
                    skill=skill,
                    tokens_in=sum(u.tokens_in for u in usages),
                    tokens_out=sum(u.tokens_out for u in usages),
                    cost_usd=sum((self._views.price(u) for u in usages), Decimal(0)),
                    occurred_at=day,
                )
                for (day, provider, model, skill), usages in sorted(
                    days.items(), key=lambda kv: (*kv[0][:3], kv[0][3] or "")
                )
                if (day, provider, model, skill) not in held
                and (day, provider, model, None) not in held
            ]
            for event in fresh:
                uow.spend_events.add(event)
            uow.commit()
        log.info("collected %d spend events", len(fresh))
        return len(fresh)

    def usage_summary(
        self, source: SpendSource, window: TimeWindow, group_by: Collection[UsageDimension]
    ) -> list[UsageRollup]:
        return self._views.usage_summary(source, window, group_by)

    def settlement(
        self, run_order_id: UUID, usage: Sequence[ModelUsage]
    ) -> tuple[list[SpendEvent], dict[str, str]]:
        """An order's measured usage as one priced event per provider, model and skill, and why
        each model that could not be priced wasn't (never priced at $0, never dropped quietly)."""
        groups: defaultdict[tuple[str, str, str | None], list[ModelUsage]] = defaultdict(list)
        for u in usage:
            groups[u.provider, u.model, u.skill].append(u)
        events, unpriced = [], {}
        for (provider, model, skill), usages in groups.items():
            try:
                if self._views.models is None:
                    raise ConfigError("no model registry (Context.register_model_catalog)")
                cost = sum((self._views.price(u) for u in usages), Decimal(0))
            except (ConfigError, NotFoundError) as e:
                unpriced[model] = str(e)
                continue
            events.append(
                SpendEvent(
                    run_order_id=run_order_id,
                    provider=provider,
                    model=model,
                    skill=skill,
                    tokens_in=sum(u.tokens_in for u in usages),
                    tokens_out=sum(u.tokens_out for u in usages),
                    cost_usd=cost,
                    occurred_at=max(u.occurred_at for u in usages),
                )
            )
        return events, unpriced

    def lane_costs(self, window: TimeWindow) -> list[LaneCost]:
        """Each lane's median settled cost per order over the window, from the spend recorded
        against its orders (orders with no recorded spend don't count)."""
        with self._uow as uow:
            rows = uow.spend_events.order_costs(window.start, window.end)
        lanes: defaultdict[str, list[tuple[int, Decimal]]] = defaultdict(list)
        for lane, events, cost in rows:
            lanes[lane].append((events, cost))
        return [
            LaneCost(
                lane=LaneName(lane),
                orders=len(orders),
                events=sum(e for e, _ in orders),
                median_usd=median(c for _, c in orders),
            )
            for lane, orders in sorted(lanes.items())
        ]

    def attribute(self, window: TimeWindow) -> SpendAttribution:
        """Spend tied to an order vs spend no order claims; the two always sum to the total."""
        return SpendAttribution(
            window=window,
            attributed_usd=self._total(SpendFilter(window=window, attributed=True)),
            unattributed_usd=self._total(SpendFilter(window=window, attributed=False)),
        )

    def attribute_by(self, filter: SpendFilter, by: SpendDimension) -> SpendBreakdown:
        """Spend per skill (or per lane, from the run order it was recorded against), with what
        no skill or lane claims kept apart as `unattributed`."""
        if by not in (SpendDimension.SKILL, SpendDimension.LANE):
            raise ValidationError(f"spend is attributed by skill or lane, not {by}")
        with self._uow as uow:
            grouped = uow.spend_events.sum_by(filter, by)
            total = uow.spend_events.sum_by(filter)
        none = SpendRollup(events=0, tokens_in=0, tokens_out=0, cost_usd=Decimal(0))
        return SpendBreakdown(
            filter=filter,
            by=by,
            rows=tuple(r for r in grouped if r.key is not None),
            unattributed=next((r for r in grouped if r.key is None), none),
            total=total[0] if total else none,
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


class FeedQuery:
    """Composite read for consumers: orders that stopped or finished, new assessments and recorded
    releases, in one cursor order over `run_order (updated_at, id)`, `assessment (created_at, id)`
    and `release (created_at, id)`."""

    def __init__(
        self, ops: OpsService, assessments: AssessmentService, portfolio: PortfolioService
    ) -> None:
        self._ops = ops
        self._assessments = assessments
        self._portfolio = portfolio

    def list(self, page: PageRequest) -> Page[FeedEvent]:
        """The changes after `page.cursor`, oldest first; a consumer resumes from the last event's
        `cursor`. A later change to an order is a new event."""
        # NEED(feed: overdue): a subject past freshness.fail usually still has an open, failing or
        # withheld order, so a stop row for it would collide with `find_open`; it stays in the
        # engine's TickReport and logs.
        after, fetch = page.position(), page.limit + 1
        events = sorted(
            [
                *(FeedEvent(order=o) for o in self._ops.feed_after(after, fetch)),
                *(FeedEvent(assessment=a) for a in self._assessments.feed_after(after, fetch)),
                *(FeedEvent(release=r) for r in self._portfolio.release_feed_after(after, fetch)),
            ],
            key=lambda e: e.position,
        )
        return Page.of(events, page.limit, lambda e: e.position)


class FeedStatuses(Protocol):
    def feed_statuses(self) -> list[FeedStatus]: ...


class FreshnessQuery:
    """Composite read for drift-watch: feed snapshot age, provider readiness, tool databases."""

    def __init__(self, providers: ProviderCatalog, feeds: FeedStatuses, clock: Clock) -> None:
        self._providers = providers
        self._feeds = feeds
        self._clock = clock

    def stale(self) -> list[StaleItem]:
        """Every checked item with its status, worst first; all fresh means nothing is stale."""
        now = self._clock.now()
        items = [
            *(_feed_item(s, now) for s in self._feeds.feed_statuses()),
            *(_provider_item(b) for b in self._providers.readiness(None)),
            *self._database_items(now),
        ]
        order = list(Freshness)
        return sorted(items, key=lambda i: (order.index(i.status), i.item))

    def _database_items(self, now: datetime) -> list[StaleItem]:
        try:
            databases = self._providers.databases()
        except ConfigError as e:
            return [StaleItem(item="tool-databases", status=Freshness.UNAVAILABLE, detail=str(e))]
        return [_database_item(db, now) for db in databases]


def _feed_item(status: FeedStatus, now: datetime) -> StaleItem:
    item, refresh = f"feeds:{status.name}", f"fetch feed {status.name}"
    if status.fetched_at is None:
        return StaleItem(
            item=item, status=Freshness.PENDING, detail="never fetched", refresh=refresh
        )
    stale = status.stale(now)
    detail = (
        f"retrieved {status.fetched_at.date().isoformat()} ({_hours(now - status.fetched_at)}h "
        f"ago; threshold {_hours(status.max_age)}h)"
    )
    if status.last_error:
        detail += f"; last error: {status.last_error}"
    return StaleItem(
        item=item,
        status=Freshness.STALE if stale else Freshness.FRESH,
        detail=detail,
        refresh=refresh if stale else None,
    )


def _provider_item(binding: ProviderBinding) -> StaleItem:
    c = binding.capability
    detail = " ".join(d for d in (binding.version, binding.readiness.detail) if d)
    status = Freshness.FRESH if binding.readiness.ready else Freshness.UNAVAILABLE
    return StaleItem(item=f"{c.kind}:{c.name}", status=status, detail=detail)


def _database_item(db: DatabaseStatus, now: datetime) -> StaleItem:
    item, refresh = f"database:{db.tool}", f"fetch the {db.tool} database"
    if not db.exists:
        return StaleItem(item=item, status=Freshness.PENDING, detail="not fetched", refresh=refresh)
    built = "build time unknown" if db.built_at is None else f"built {db.built_at.date()}"
    limit = "" if db.max_age is None else f" (max age {_hours(db.max_age)}h)"
    stale = db.stale(now)
    return StaleItem(
        item=item,
        status=Freshness.STALE if stale else Freshness.FRESH,
        detail=built + limit,
        refresh=refresh if stale else None,
    )


def _hours(delta: timedelta) -> int:
    return round(delta.total_seconds() / 3600)
