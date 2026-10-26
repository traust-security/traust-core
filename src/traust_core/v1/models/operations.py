from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, NewType
from uuid import UUID

from pydantic import Field

from traust_core.v1 import contracts
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.base import AppendOnly, Dto, Entity, Model
from traust_core.v1.models.common import Cursor, Sha256, TimeWindow, encode_cursor
from traust_core.v1.models.vocabulary import BudgetEnforcement

AssetName = NewType("AssetName", str)
WorkerId = NewType("WorkerId", str)
LaneName = NewType("LaneName", str)
ProviderName = NewType("ProviderName", str)
ModelName = NewType("ModelName", str)
SkillName = NewType("SkillName", str)


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    REFUSED = "refused"
    FAILED = "failed"


class JobResult(Model):
    outcome: Outcome
    degraded: Mapping[str, int] = Field(default_factory=dict)
    reason: str | None = None
    written: tuple[str, ...] = ()

    @classmethod
    def succeeded(cls, written: tuple[str, ...] = ()) -> JobResult:
        return cls(outcome=Outcome.SUCCEEDED, written=written)

    @classmethod
    def partly(cls, degraded: Mapping[str, int], written: tuple[str, ...] = ()) -> JobResult:
        if not degraded:
            return cls.succeeded(written)
        return cls(outcome=Outcome.DEGRADED, degraded=dict(degraded), written=written)

    @classmethod
    def refused(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.REFUSED, reason=reason)

    @classmethod
    def failed(cls, reason: str) -> JobResult:
        return cls(outcome=Outcome.FAILED, reason=reason)


class AssetRequest(Dto):
    asset: AssetName
    run_id: str
    partition: str | None = None
    params: Mapping[str, str] = Field(default_factory=dict)


class Refusal(Dto):
    subject: str
    lane: LaneName
    reason: str | None = None


class Route(Dto):
    lane: LaneName | None
    priority: int
    reason: str


if TYPE_CHECKING:
    OrderState = StrEnum
    OrderReason = StrEnum
    WorkLane = StrEnum
    RescanEventSource = StrEnum
    DegradedKey = StrEnum
else:
    OrderState = contracts.enum("run-order-state")
    OrderReason = contracts.enum("run-order-reason")
    WorkLane = contracts.enum("work-lane")
    RescanEventSource = contracts.enum("rescan-event-source")
    DegradedKey = contracts.enum("degraded-key")


OPEN_ORDER_STATES = (
    OrderState.PLANNED,
    OrderState.AWAITING_APPROVAL,
    OrderState.QUEUED,
    OrderState.LEASED,
)


class OrderRequest(Model):
    """What admission puts on the queue: one asset for one partition, routed or not."""

    asset: AssetName
    priority: int
    repository_id: UUID | None = None
    run_batch_id: UUID | None = None
    lane: LaneName | None = None
    rule: str | None = None
    event_source: str | None = None


# Shapes land with their implementation slice.
class OrderProgress(Model):
    """Where a running order has got to (steps done, shards done), so a re-lease resumes."""

    step: int | None = Field(default=None, ge=0)
    shards_done: tuple[str, ...] = ()


class ConfigDigest(Model):
    """A config document in force when an order was planned; `pack:<name>` is the pack version."""

    name: str
    digest: Sha256
    artifact_id: UUID | None = None


class SchedulePlan(Model):
    """Assets to run now, one queued order each (a dashboard refresh: one order per view)."""

    assets: tuple[AssetName, ...] = Field(min_length=1)
    priority: int
    repository_id: UUID | None = None
    run_batch_id: UUID | None = None
    lane: LaneName | None = None


class OrderFilter(Model):
    """`window` bounds a timeline by finished_at; `list` pages by created_at and refuses it."""

    states: tuple[OrderState, ...] = ()
    asset: AssetName | None = None
    repository_id: UUID | None = None
    run_batch_id: UUID | None = None
    window: TimeWindow | None = None


FINISHED_ORDER_STATES = (
    OrderState.SUCCEEDED,
    OrderState.DEGRADED,
    OrderState.REFUSED,
    OrderState.WITHHELD,
    OrderState.FAILED,
)


class ThroughputPoint(Model):
    """Orders finished within one bucket, by outcome (every outcome in scope, zero-filled)."""

    bucket: datetime
    finished: Mapping[OrderState, int]

    @property
    def total(self) -> int:
        return sum(self.finished.values())


class ModelUsage(Model):
    """One model request's token usage, and the skill running then, as a transcript reader
    parsed them."""

    provider: ProviderName
    model: ModelName
    occurred_at: datetime
    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    cache_read: int = Field(default=0, ge=0)
    cache_creation: int = Field(default=0, ge=0)
    skill: SkillName | None = None


# NEED(traust: transcript reader): traust parses Claude Code session transcripts into usages;
# core reads no files.
class SpendSource(Model):
    """Parsed model usage from one source (e.g. a workstation's session transcripts)."""

    name: str
    usages: tuple[ModelUsage, ...] = ()


class SpendDimension(StrEnum):
    MONTH = "month"
    LANE = "lane"
    PROVIDER = "provider"
    MODEL = "model"
    SKILL = "skill"
    REPOSITORY = "repository"  # of the run order the spend was recorded against


class SpendFilter(Model):
    window: TimeWindow
    lane: LaneName | None = None
    attributed: bool | None = None


class SpendRollup(Model):
    """Spend summed over one group; key is None for spend without that dimension (no lane)."""

    key: str | None = None
    events: int
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal


class SpendBreakdown(Model):
    """Spend split by skill or lane: a row per key, `unattributed` (no key, always present) and
    the ungrouped `total` they must sum to."""

    filter: SpendFilter
    by: SpendDimension
    rows: tuple[SpendRollup, ...]
    unattributed: SpendRollup
    total: SpendRollup

    @property
    def lossless(self) -> bool:
        """The split drops and invents nothing: rows plus unattributed equal the total."""
        parts = (*self.rows, self.unattributed)
        return all(
            sum(getattr(r, f) for r in parts) == getattr(self.total, f)
            for f in ("events", "tokens_in", "tokens_out", "cost_usd")
        )


class SpendAttribution(Model):
    window: TimeWindow
    attributed_usd: Decimal
    unattributed_usd: Decimal

    @property
    def total_usd(self) -> Decimal:
        return self.attributed_usd + self.unattributed_usd


class Invoice(Model):
    """A month's billed amount, the spend view's estimates are reconciled against."""

    period: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
    amount_usd: Decimal
    note: str = ""


class BudgetStatus(StrEnum):
    WITHIN = "within"
    OVER = "over"
    NO_BUDGET = "no_budget"


class BudgetVerdict(Model):
    """One lane's month-to-date spend plus an estimate, judged against its budget."""

    lane: LaneName
    status: BudgetStatus
    enforcement: BudgetEnforcement | None = None
    spent_usd: Decimal
    estimate_usd: Decimal | None
    budget_usd: Decimal | None = None

    @property
    def binding(self) -> bool:
        """Admission may withhold: over, enforcing, and the cost is known."""
        return (
            self.status is BudgetStatus.OVER
            and self.enforcement in (BudgetEnforcement.ADVISORY, BudgetEnforcement.ENFORCED)
            and self.estimate_usd is not None
        )


class Freshness(StrEnum):
    """Worst first: the order a drift report leads with."""

    STALE = "stale"
    UNAVAILABLE = "unavailable"
    PENDING = "pending"
    FRESH = "fresh"


class StaleItem(Model):
    """One checked input: fresh, stale, never produced yet (pending) or not checkable."""

    item: str
    status: Freshness
    detail: str = ""
    refresh: str | None = None


class RunBatch(Entity):
    """4a · a tranche: one per (kind, period), e.g. drain_tranche / 2026-W31."""

    kind: str
    period: str


class RunOrder(Entity):
    """4a · one unit of work; queued, leased by a worker, finished with an outcome."""

    run_batch_id: UUID | None = None
    repository_id: UUID | None = None
    artifact_id: UUID | None = None
    rule: str | None = None
    event_source: str | None = None
    asset: str
    lane: str | None = None
    state: OrderState
    priority: int
    reason: str | None = None
    requested_by: str
    lease_holder: str | None = None
    lease_expires_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


FEED_ORDER_STATES = (*FINISHED_ORDER_STATES, OrderState.AWAITING_APPROVAL)


class FeedEvent(Model):
    """One change on the ops feed: an order reaching a `FEED_ORDER_STATES` state (with its
    reason), or a new assessment. Exactly one is set."""

    order: RunOrder | None = None
    assessment: Assessment | None = None

    @property
    def position(self) -> tuple[datetime, UUID]:
        """The feed's order: when it changed, then id."""
        if self.order is not None:
            at, record_id = self.order.updated_at, self.order.id
        else:
            assert self.assessment is not None
            at, record_id = self.assessment.created_at, self.assessment.id
        assert at is not None and record_id is not None
        return at, record_id

    @property
    def cursor(self) -> Cursor:
        """Where the feed resumes after this event."""
        return encode_cursor(*self.position)


class SpendEvent(AppendOnly):
    run_order_id: UUID | None = None
    provider: str
    model: str
    skill: str | None = None
    lane: str | None = None
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    occurred_at: datetime


class FeedSnapshot(AppendOnly):
    run_order_id: UUID | None = None
    artifact_id: UUID
    feed: str
    retrieved_at: datetime


class AssessmentInput(AppendOnly):
    """Which feed snapshot an assessment used."""

    assessment_id: UUID
    feed_snapshot_id: UUID


class Budget(Model):
    lane: LaneName
    monthly_usd: Decimal
    enforcement: BudgetEnforcement

    def verdict(self, spent: Decimal, estimate: Decimal | None) -> BudgetVerdict:
        # Unknown cost is judged on measured spend alone, and `binding` stays false.
        projected = spent if estimate is None else spent + estimate
        return BudgetVerdict(
            lane=self.lane,
            status=BudgetStatus.OVER if projected > self.monthly_usd else BudgetStatus.WITHIN,
            enforcement=self.enforcement,
            spent_usd=spent,
            estimate_usd=estimate,
            budget_usd=self.monthly_usd,
        )
