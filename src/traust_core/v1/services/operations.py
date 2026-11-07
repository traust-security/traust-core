from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from decimal import Decimal
from statistics import median
from typing import Any, Final, Protocol, TypeVar
from uuid import UUID

from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import Page, PageRequest, Provenance, TimeBucket, TimeWindow
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    FEED_ORDER_STATES,
    FINISHED_ORDER_STATES,
    REMEDIATE_FINDING,
    SPEND_UNPRICED,
    WITHHOLDING_ENFORCEMENT,
    AssetName,
    AssetRequest,
    Budget,
    BudgetStatus,
    BudgetVerdict,
    ConfigDigest,
    DegradedKey,
    DenyCode,
    DenyIssue,
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
    PreflightRequest,
    PreflightResult,
    RecordingStartScope,
    RecordKind,
    Refusal,
    RescanEventSource,
    Route,
    RunOrder,
    SchedulePlan,
    SessionRecord,
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
from traust_core.v1.models.vocabulary import (
    ActorKind,
    AssessmentKind,
    SourceType,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.feeds import FeedStatus
from traust_core.v1.providers.model_catalog import ModelCatalog, ModelSpec
from traust_core.v1.providers.tools import DatabaseStatus
from traust_core.v1.repositories.traust_ops import OpsUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, AssessmentLog
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import Inventory, PortfolioService
from traust_core.v1.services.provider_catalog import ProviderBinding, ProviderCatalog

log = logging.getLogger(__name__)

_RECORDING_SOURCES: Final[Mapping[RecordKind, SourceType]] = {
    RecordKind.ASSESSMENT: SourceType.VULN_SCAN_REPORT,
    RecordKind.TRIAGE: SourceType.TRIAGE_REPORT,
    RecordKind.VALIDATION: SourceType.VALIDATION_REPORT,
    RecordKind.VERIFICATION: SourceType.VERIFICATION_REPORT,
    # NEED(contracts: remediation source type): contracts' source-type has no remediation
    # value; the remediation report records under its triage source until one lands.
    RecordKind.REMEDIATION: SourceType.TRIAGE_REPORT,
}

# A stage may run only after its predecessor left a completed order for the subject. Stages
# are record kinds and the deployment's recording config names each kind's assets, so the gate
# follows the configured names (one deployment's assessments run as "audit", another's as
# "assessment"). Remediation orders ride the triage allowlist until contracts grows a
# recording.remediation section; its predecessor is the triage stage minus the remediation asset
# itself, and verification needs remediation completed — only REMEDIATE_FINDING satisfies it,
# not the allowlist's ordinary triage names. A predecessor the deployment does not wire is not
# required: the gate enforces what the config declares. Remediation's plan-level gate is a
# disposition, which lives on the findings service behind OpsService (a wiring cycle), so a
# finished triage order is its record until that door is reachable.
_PRIOR_RECORD_KIND: Final[Mapping[RecordKind, RecordKind]] = {
    RecordKind.TRIAGE: RecordKind.ASSESSMENT,
    RecordKind.REMEDIATION: RecordKind.TRIAGE,
    RecordKind.VALIDATION: RecordKind.TRIAGE,
    RecordKind.VERIFICATION: RecordKind.REMEDIATION,
}

# Ordering counts a predecessor that actually ran. FINISHED_ORDER_STATES also covers refused,
# withheld and failed orders (they finished as orders, not as work); a failed assessment must
# not unlock triage.
_COMPLETED_ORDER_STATES: Final[tuple[OrderState, ...]] = (
    OrderState.SUCCEEDED,
    OrderState.DEGRADED,
)

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


class PolicyDenied(ForbiddenError):
    """A policy gate refused the action; every issue carries a deny code the envelope shows."""

    def __init__(self, issues: Sequence[DenyIssue]) -> None:
        super().__init__("; ".join(f"{issue.code}: {issue.detail}" for issue in issues))
        self.deny_issues = tuple(issues)

    @property
    def deny_code(self) -> DenyCode:
        return self.deny_issues[0].code


class OpsService:
    def __init__(
        self,
        uow: OpsUnitOfWork,
        clock: Clock,
        manifests: ArtifactPublisher,
        *,
        degraded_keys: Callable[[], Collection[str]] = tuple,
        spend: SpendService | None = None,
        recording_assets: Mapping[RecordKind | str, Collection[str]] | None = None,
        recording_starts: Sequence[RecordingStartScope] = (),
        inventory: Inventory | None = None,
        assessments: AssessmentLog | None = None,
    ) -> None:
        self._uow = uow
        self._clock = clock
        self._manifests = manifests
        self._config_manifests: dict[tuple[ConfigDigest, ...], UUID] = {}
        self._degraded_keys = degraded_keys
        self._spend = spend or SpendService(uow, clock, ())
        # The context hands config sections as plain strings; an unknown kind is a typo in
        # the wiring, refused here rather than silently ungating a stage.
        self._recording_assets = {
            RecordKind(kind): frozenset(assets) for kind, assets in (recording_assets or {}).items()
        }
        self._recording_starts = tuple(recording_starts)
        self._inventory = inventory
        self._assessments = assessments

    def submit(
        self, request: OrderRequest, principal: Principal, config: Sequence[ConfigDigest] = ()
    ) -> RunOrder:
        """Queue an order directly, with the config it must run under in its run manifest."""
        issues = self._policy_issues(
            asset=request.asset,
            repository_id=request.repository_id,
            lane=request.lane,
            principal=principal,
        )
        if issues:
            raise PolicyDenied(issues)
        _classifiers(lane=request.lane, event_source=request.event_source)
        self._check_work_item(request)
        order = RunOrder(
            **request.model_dump(),
            **self._config_manifest(tuple(config)),
            state=OrderState.QUEUED,
            requested_by=principal.ref,
        )
        with self._uow as uow:
            saved = uow.run_orders.add(order)
            uow.commit()
        self._uow.after_commit(
            lambda: log.info(
                "order %s queued actor_kind=%s",
                saved.id,
                principal.kind,
                extra={"order_id": str(saved.id), "actor_kind": str(principal.kind)},
            )
        )
        return saved

    def _check_work_item(self, request: OrderRequest) -> None:
        """An order names a remediation work item on its own repository, or none: the runner
        prepares the item the order names."""
        if request.work_item_id is None:
            return
        if self._inventory is None or self._assessments is None:
            raise ConfigError(
                "an order naming a work item requires inventory reads (Context wires them)"
            )
        found = self._assessments.list_by_ids({request.work_item_id})
        if (
            not found
            or found[0].kind != AssessmentKind.REMEDIATION
            or (
                self._inventory.get_ref(found[0].repository_ref_id).repository_id
                != request.repository_id
            )
        ):
            raise ValidationError(
                f"work item {request.work_item_id} is not a remediation work item of "
                f"repository {request.repository_id}"
            )

    def preflight(self, request: PreflightRequest, principal: Principal) -> PreflightResult:
        """May this stage run on this subject now: fail-fast courtesy; submit re-verifies."""
        issues = self._policy_issues(
            asset=request.asset,
            repository_id=request.repository_id,
            lane=request.lane,
            principal=principal,
        )
        if issues:
            raise PolicyDenied(issues)
        return PreflightResult(
            allowed=True,
            asset=request.asset,
            repository_id=request.repository_id,
            config_generation=request.config_generation,
            lane=request.lane,
        )

    def _policy_issues(
        self,
        *,
        asset: AssetName,
        repository_id: UUID | None,
        lane: LaneName | None,
        principal: Principal,
    ) -> tuple[DenyIssue, ...]:
        """The gates preflight reports and submit enforces: one code path, called from both."""
        if not self._may_request(asset, repository_id, principal):
            # A caller who may not ask learns nothing else about the subject, its stages or
            # the lane's spend: the role denial is the whole answer.
            return (
                DenyIssue(
                    code=DenyCode.ROLE_DENIED,
                    detail="asking for a run is a person's, or a machine granted it in "
                    "recording.start",
                ),
            )
        issues: list[DenyIssue] = []
        if repository_id is not None:
            issues.extend(self._subject_issues(repository_id))
        issues.extend(self._ordering_issues(asset, repository_id))
        if lane is not None:
            verdict = self._spend.check_budget(lane, None)
            if (
                verdict.status is BudgetStatus.OVER
                and verdict.enforcement in WITHHOLDING_ENFORCEMENT
            ):
                # No estimate exists before the run, so the gate is measured spend alone
                # (BudgetVerdict.binding also needs the estimate; a preflight cannot have one).
                # The figures stay server-side: a denial names the lane, never the amounts.
                issues.append(
                    DenyIssue(
                        code=DenyCode.BUDGET_EXHAUSTED,
                        detail=f"lane {lane} is over its monthly budget",
                    )
                )
        return tuple(issues)

    def _subject_issues(self, repository_id: UUID) -> tuple[DenyIssue, ...]:
        """The subject gate, shared by every door that starts a run: the repository must be
        registered and onboarded (an imported default line — registered alone is not a
        subject, for preflight, submit and recording start alike)."""
        if self._inventory is None:
            raise ConfigError("subject checks need the inventory door")
        try:
            self._inventory.get_repository(repository_id)
        except NotFoundError:
            return (
                DenyIssue(code=DenyCode.SUBJECT_UNKNOWN, detail=f"no repository {repository_id}"),
            )
        if self._inventory.default_line(repository_id) is None:
            return (
                DenyIssue(
                    code=DenyCode.SUBJECT_UNKNOWN,
                    detail=f"repository {repository_id} has no imported default line",
                ),
            )
        return ()

    def _may_request(
        self, asset: AssetName, repository_id: UUID | None, principal: Principal
    ) -> bool:
        """Who may ask for a run: a verified person, or a verified machine within a
        `recording.start` grant for this asset and repository. `authorize_request` enforces this
        rule; the policy gates report it as a typed issue — one rule, two doors."""
        return principal.is_verified_human() or (
            principal.kind == ActorKind.MACHINE
            and principal.verified_by is not None
            and repository_id is not None
            and self._in_start_scope(principal, asset, repository_id)
        )

    def _ordering_issues(self, asset: AssetName, repository_id: UUID | None) -> Iterator[DenyIssue]:
        """The stage-ordering gate, from the deployment's recording config: a gated asset needs
        its predecessor's completed order on the very subject. A subjectless order cannot show
        one, so it is refused rather than queued unverified."""
        kind = self._stage_of(asset)
        if kind is None:
            return
        prior = _PRIOR_RECORD_KIND.get(kind)
        if prior is None:
            return
        prior_assets = self._recording_assets.get(prior, frozenset())
        if prior is RecordKind.REMEDIATION:
            # Verification follows remediation specifically: only the native scheduling
            # asset unlocks it, never the triage allowlist's ordinary names. A deployment
            # that wires no remediation asset leaves that alias empty, so verification's
            # prerequisite falls back to ordinary triage: a completed stage before it,
            # never nothing (Qodo 392).
            remediation = prior_assets & {REMEDIATE_FINDING}
            prior_assets = (
                remediation
                if remediation
                else self._recording_assets.get(RecordKind.TRIAGE, frozenset())
                - {REMEDIATE_FINDING}
            )
        elif kind is RecordKind.REMEDIATION:
            # Remediation rides the triage allowlist; its predecessor is triage's work,
            # not another remediation order.
            prior_assets = prior_assets - {REMEDIATE_FINDING}
        if not prior_assets:
            return  # the deployment wires no such stage: nothing to require
        if repository_id is None:
            yield DenyIssue(
                code=DenyCode.ORDERING_VIOLATED,
                detail=f"{asset} needs a repository: its {prior} prerequisite is per-subject",
            )
            return
        with self._uow as uow:
            completed = uow.run_orders.subject_has_order(
                tuple(prior_assets), repository_id, _COMPLETED_ORDER_STATES
            )
        if not completed:
            yield DenyIssue(
                code=DenyCode.ORDERING_VIOLATED,
                detail=f"{asset} needs a completed {prior} order for the subject first",
            )

    def _stage_of(self, asset: AssetName) -> RecordKind | None:
        """The one record kind an asset runs as, or None when ungated. The context copies the
        triage allowlist into a remediation key (contracts has no recording.remediation
        section yet), so that alias cannot disambiguate a name: REMEDIATE_FINDING is the only
        remediation asset, every other name resolves among the primary kinds, and an asset on
        several of those is ambiguous. RecordingConfig refuses such bindings, so more than one
        answer here means the service was wired outside the config: refuse the run rather
        than guess its stage."""
        if asset == REMEDIATE_FINDING:
            return RecordKind.REMEDIATION
        kinds = [
            RecordKind(k)
            for k, assets in self._recording_assets.items()
            if k != RecordKind.REMEDIATION and asset in assets
        ]
        if len(kinds) > 1:
            raise ConfigError(f"asset {asset} is bound to several record kinds")
        return kinds[0] if kinds else None

    def plan(
        self, request: OrderRequest, principal: Principal, config: Sequence[ConfigDigest] = ()
    ) -> RunOrder:
        """Store a routed request as planned, with the config in force (the pack version) in its
        run manifest; an open order for the same subject is re-ranked while still planned,
        otherwise returned unchanged."""
        _classifiers(lane=request.lane, event_source=request.event_source)
        self._check_work_item(request)
        manifest = self._config_manifest(tuple(config))
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
                update = {**route, **manifest}
                if all(getattr(current, field) == value for field, value in update.items()):
                    return current
                saved = uow.run_orders.update(current.model_copy(update=update))
            else:
                return current
            uow.commit()
        self._uow.after_commit(
            lambda: log.info(
                "order %s planned priority=%d actor_kind=%s",
                saved.id,
                saved.priority,
                principal.kind,
                extra={"order_id": str(saved.id), "actor_kind": str(principal.kind)},
            )
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
        *,
        order_id: UUID | None = None,
    ) -> RunOrder | None:
        """Lease the next queued order, or only the selected queued ID; an empty `assets`
        claims nothing."""
        if assets is not None and not assets:
            return None
        with self._uow as uow:
            # Claiming sweeps: an order whose lease expired returns to the
            # queue here, in the same transaction, so a deployed server
            # needs no separate reaper loop for a dead runner's orders.
            expired = uow.run_orders.requeue_expired(self._clock.now())
            order = uow.run_orders.claim(
                worker, self._clock.now(), lease_for, assets, order_id=order_id
            )
            uow.commit()
        if expired:
            log.warning("%d expired leases requeued by claim", expired)
        if order is not None:
            self._uow.after_commit(
                lambda: log.info("order %s leased", order.id, extra={"order_id": str(order.id)})
            )
        return order

    def start(
        self, request: OrderRequest, principal: Principal, worker: WorkerId, lease_for: timedelta
    ) -> RunOrder:
        """A run its runner has already begun (by hand, or a cron job beside the engine), leased to
        `worker`: the subject's planned or queued order is taken over, else a new one is stored."""
        _classifiers(lane=request.lane, event_source=request.event_source)
        self._check_work_item(request)
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
                if request.work_item_id not in (None, current.work_item_id):
                    raise ConflictError(
                        f"order {current.id} runs work item {current.work_item_id}, not "
                        f"{request.work_item_id}"
                    )
                saved = uow.run_orders.update(current.model_copy(update=lease))
            assert saved.id is not None
            saved = uow.run_orders.get(saved.id)
            uow.commit()
        self._uow.after_commit(
            lambda: log.info(
                "order %s started actor_kind=%s",
                saved.id,
                principal.kind,
                extra={"order_id": str(saved.id), "actor_kind": str(principal.kind)},
            )
        )
        return saved

    def start_recording(
        self, request: OrderRequest, principal: Principal, lease_for: timedelta
    ) -> RunOrder:
        """Start an explicitly dispatched recording run within the machine's server-owned scope."""
        principal = Principal.model_validate(dict(principal))
        if principal.kind != ActorKind.MACHINE or principal.verified_by is None:
            raise ForbiddenError("recording start requires a verified machine identity")
        if not timedelta(0) < lease_for <= timedelta(days=1):
            raise ValidationError("recording start lease must be positive and at most one day")
        if not any(
            request.asset in assets
            for kind, assets in self._recording_assets.items()
            if kind in _RECORDING_SOURCES
        ):
            raise ForbiddenError("recording start asset is not authorized for report recording")
        if request.repository_id is None or not self._in_start_scope(
            principal, request.asset, request.repository_id
        ):
            raise ForbiddenError("recording start is outside the machine's asset/repository scope")
        if self._inventory is None:
            raise ConfigError("recording start requires inventory reads (Context wires them)")
        if issues := (*self._subject_issues(request.repository_id),):
            # The subject gate submit and preflight enforce; a recording start is a run, so
            # a registered-but-never-imported repository cannot lease one either.
            raise PolicyDenied(issues)
        if issues := tuple(self._ordering_issues(request.asset, request.repository_id)):
            # The same stage ordering submit and preflight enforce; a recording start is a run.
            raise PolicyDenied(issues)
        return self.start(request, principal, WorkerId(principal.ref), lease_for)

    def authorize_request(
        self, asset: AssetName, repository_id: UUID, principal: Principal
    ) -> None:
        """Who may ask for a run outside routing: a verified person (as for a direct order), or a
        verified machine within a `recording.start` grant for this asset and repository (the
        deployment's explicit machine scope; default deny)."""
        if not self._may_request(asset, repository_id, principal):
            raise ForbiddenError(
                f"not allowed to ask for {asset} on repository {repository_id}: a verified "
                "person, or a machine granted it in recording.start, may"
            )

    def _in_start_scope(self, principal: Principal, asset: AssetName, repository_id: UUID) -> bool:
        return any(
            scope.principal == principal.ref
            and asset in scope.assets
            and repository_id in scope.repository_ids
            for scope in self._recording_starts
        )

    def heartbeat(self, order_id: UUID, worker: WorkerId, lease_for: timedelta) -> RunOrder:
        now = self._clock.now()
        with self._uow.write() as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.LEASED, worker)
            if order.lease_expires_at is None or order.lease_expires_at < now:
                raise ConflictError(f"order {order_id}: lease expired at {order.lease_expires_at}")
            saved = uow.run_orders.update(
                order.model_copy(update={"lease_expires_at": now + lease_for})
            )
            uow.commit()
        return saved

    @contextmanager
    def recording(
        self,
        order_id: UUID,
        principal: Principal,
        kind: RecordKind,
        repository_id: UUID,
        provenance: Provenance,
    ) -> Iterator[RunOrder]:
        """Authorize and serialize one leased runner's report with its domain writes."""
        principal = Principal.model_validate(dict(principal))
        if principal.kind != ActorKind.MACHINE or principal.verified_by is None:
            raise ForbiddenError("recording requires a verified machine identity")
        with self._uow.write() as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.LEASED)
            if order.lease_holder != principal.ref:
                raise ForbiddenError(f"order {order_id}: recording lease belongs to another runner")
            self._require_lease(order, repository_id)
            if order.asset not in self._recording_assets.get(kind, ()):
                raise ForbiddenError(
                    f"order {order_id}: asset is not authorized for {kind} recording"
                )
            if provenance.run_id != order_id:
                raise ValidationError("recording provenance.run_id must equal run_order_id")
            if provenance.source != _RECORDING_SOURCES.get(kind):
                raise ValidationError("recording provenance source does not match the report kind")
            yield order
            if order.lease_expires_at <= self._clock.now():
                raise ConflictError(f"order {order_id}: recording lease expired before commit")
            uow.commit()

    @contextmanager
    def bound(self, order_id: UUID, repository_id: UUID) -> Iterator[RunOrder]:
        """Serialize writes bound to a leased order with its lease, as `recording` does for a
        runner's report: the order is locked, leased, unexpired and scoped to `repository_id`
        from the check through the commit of the caller's writes, which commit here."""
        with self._uow.write() as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, OrderState.LEASED)
            self._require_lease(order, repository_id)
            yield order
            assert order.lease_expires_at is not None
            if order.lease_expires_at <= self._clock.now():
                raise ConflictError(f"order {order_id}: recording lease expired before commit")
            uow.commit()

    def _require_lease(self, order: RunOrder, repository_id: UUID) -> None:
        """A leased order's lease is live and its scope is this one repository (a fleet-wide
        order's scope is no repository's)."""
        if order.lease_expires_at is None or order.lease_expires_at <= self._clock.now():
            raise ConflictError(f"order {order.id}: recording lease expired")
        if order.repository_id is None or order.repository_id != repository_id:
            raise ForbiddenError(f"order {order.id}: report repository is outside its scope")

    def save_progress(self, order_id: UUID, progress: OrderProgress) -> UUID:
        """Record a leased order's progress in its run manifest; returns the manifest's id."""
        updated_at = self._clock.now().isoformat()
        entry = {**progress.model_dump(mode="json"), "updated_at": updated_at}
        saved = self._move(order_id, OrderState.LEASED, {}, lambda m: {**m, "progress": entry})
        assert saved.artifact_id is not None
        return saved.artifact_id

    def record_session(self, order_id: UUID, worker: WorkerId, session: SessionRecord) -> UUID:
        """Append runner-computed session evidence under its current lease."""
        if not worker:
            raise ValidationError("record_session requires the lease holder")
        entry = session.model_dump(mode="json")

        def append(manifest: dict[str, Any]) -> dict[str, Any]:
            sessions = manifest.get("sessions", [])
            if entry in sessions:
                return manifest
            if session.executor_session is not None and any(
                prior["executor_session"] == session.executor_session for prior in sessions
            ):
                raise ConflictError(f"order {order_id}: executor session evidence changed")
            return {**manifest, "sessions": [*sessions, entry]}

        saved = self._move(order_id, OrderState.LEASED, {}, append, worker, live_lease=True)
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
            self._uow.after_commit(
                lambda: log.warning(
                    "order %s degraded in %d categories",
                    saved.id,
                    len(degraded),
                    extra={"order_id": str(saved.id)},
                )
            )
        if unpriced:
            self._uow.after_commit(
                lambda: log.warning(
                    "order %s: %s count=%d",
                    saved.id,
                    SPEND_UNPRICED,
                    len(unpriced),
                    extra={"order_id": str(saved.id)},
                )
            )
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
            actor_kind=principal.kind,
        )
        return saved

    def _move(
        self,
        order_id: UUID,
        from_state: OrderState,
        update: dict[str, object],
        change: Change | None = None,
        worker: WorkerId | None = None,
        spend: Sequence[SpendEvent] = (),
        actor_kind: ActorKind | None = None,
        live_lease: bool = False,
    ) -> RunOrder:
        """Move an order on, with its spend (in its lane); a manifest change is published first (no
        I/O inside the transaction) and lands unless another writer moved the manifest."""
        if change is not None:
            prior = self.get(order_id)
            _require(prior, from_state, worker, self._clock.now() if live_lease else None)
            _classifiers(reason=update.get("reason"))
            update = {**update, "artifact_id": self._publish(prior.artifact_id, change)}
        with self._uow.write() as uow:
            order = uow.run_orders.get_for_update(order_id)
            _require(order, from_state, worker, self._clock.now() if live_lease else None)
            if change is None:
                _classifiers(reason=update.get("reason"))
            if change is not None and order.artifact_id != prior.artifact_id:
                raise ConflictError(f"order {order_id}: run manifest changed while writing")
            saved = uow.run_orders.update(order.model_copy(update=update))
            for event in spend:
                uow.spend_events.add(event.model_copy(update={"lane": order.lane}))
            if live_lease:
                _require(order, from_state, worker, self._clock.now())
            uow.commit()
        if actor_kind is None:
            self._uow.after_commit(
                lambda: log.info(
                    "order %s %s", saved.id, saved.state, extra={"order_id": str(saved.id)}
                )
            )
        else:
            self._uow.after_commit(
                lambda: log.info(
                    "order %s %s actor_kind=%s",
                    saved.id,
                    saved.state,
                    actor_kind,
                    extra={"order_id": str(saved.id), "actor_kind": str(actor_kind)},
                )
            )
        return saved

    def _publish(self, prior: UUID | None, change: Change) -> UUID:
        current = (
            {"artifact": RunManifestArtifact.name}
            if prior is None
            else json.loads(self._manifests.get(prior).payload)
        )
        manifest = RunManifestArtifact.from_document(change(current))
        return self._manifests.publish_artifact(manifest).artifact_id

    def _config_manifest(self, config: tuple[ConfigDigest, ...]) -> dict[str, UUID]:
        # A new order's manifest is its config alone; one artifact serves every such order.
        if not config:
            return {}
        if config not in self._config_manifests:
            entries = [c.model_dump(mode="json", exclude_none=True) for c in config]
            self._config_manifests[config] = self._publish(None, lambda m: {**m, "config": entries})
        return {"artifact_id": self._config_manifests[config]}

    def requeue_expired(self) -> int:
        with self._uow as uow:
            count = uow.run_orders.requeue_expired(self._clock.now())
            uow.commit()
        if count:
            self._uow.after_commit(lambda: log.warning("%d expired leases requeued", count))
        return count

    def schedule(self, plan: SchedulePlan, principal: Principal) -> list[RunOrder]:
        """Queue one order per asset, in one transaction; an asset with an open order for the
        same subject keeps it, so a re-run queues nothing twice."""
        if len(set(plan.assets)) != len(plan.assets):
            raise ValidationError(f"schedule names an asset twice: {list(plan.assets)}")
        _classifiers(lane=plan.lane)
        route = plan.model_dump(exclude={"assets"})
        with self._uow as uow:
            orders = []
            added = 0
            for asset in plan.assets:
                existing = uow.run_orders.find_open(asset, plan.repository_id)
                if existing is not None:
                    orders.append(existing)
                    continue
                orders.append(
                    uow.run_orders.add(
                        RunOrder(
                            **route,
                            asset=asset,
                            state=OrderState.QUEUED,
                            requested_by=principal.ref,
                        )
                    )
                )
                added += 1
            uow.commit()
        if added:
            self._uow.after_commit(
                lambda: log.info("scheduled %d orders actor_kind=%s", added, principal.kind)
            )
        return orders

    def get(self, order_id: UUID) -> RunOrder:
        with self._uow as uow:
            return uow.run_orders.get(order_id)

    def order_for_work_item(self, work_item_id: UUID) -> RunOrder | None:
        """The order running a work item, if any (remediate_finding orders name theirs)."""
        with self._uow as uow:
            return uow.run_orders.find_by_work_item(work_item_id)

    def work_item_orders(
        self, asset: AssetName, repository_id: UUID | None = None
    ) -> list[RunOrder]:
        """Every order of `asset` that names a work item (an asset that runs one named item —
        remediate_finding's scheduled efforts), optionally one repository's; oldest first."""
        orders: list[RunOrder] = []
        after = None
        with self._uow as uow:
            while True:
                batch = uow.run_orders.search(
                    asset=str(asset),
                    repository_id=repository_id,
                    work_item=True,
                    limit=500,
                    after=after,
                )
                orders.extend(batch)
                if len(batch) < 500:
                    return orders
                after = (batch[-1].created_at, batch[-1].id)  # type: ignore[assignment]

    def manifest(self, order_id: UUID) -> OrderManifest:
        """The config an order was planned with and its approval, from its run manifest."""
        artifact_id = self.get(order_id).artifact_id
        if artifact_id is None:
            return OrderManifest()
        doc = json.loads(self._manifests.get(artifact_id).payload)
        return OrderManifest.model_validate(
            {k: doc[k] for k in ("config", "approval", "sessions") if k in doc}
        )

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


def _require(
    order: RunOrder, state: OrderState, worker: WorkerId | None = None, at: datetime | None = None
) -> None:
    if order.state != state:
        raise ConflictError(f"order {order.id} is {order.state}, not {state}")
    if worker is not None and order.lease_holder != worker:
        raise ConflictError(f"order {order.id} is leased to {order.lease_holder}, not {worker}")
    if at is not None and (order.lease_expires_at is None or order.lease_expires_at <= at):
        raise ConflictError(f"order {order.id}: lease expired")


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
        self._uow.after_commit(
            lambda: log.info("spend %s recorded cost_usd=%s", saved.id, saved.cost_usd)
        )
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
        if fresh:
            self._uow.after_commit(lambda: log.info("collected %d spend events", len(fresh)))
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
