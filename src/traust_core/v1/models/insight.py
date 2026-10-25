from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from pydantic import Field, SerializeAsAny

from traust_core.v1.models.assessment import Coverage, Population, Threat
from traust_core.v1.models.base import Model
from traust_core.v1.models.code_facts import LanguageCount
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.compliance import ComplianceRollup, DocVariance
from traust_core.v1.models.dependencies import ExposureRollup
from traust_core.v1.models.findings import Decision, FindingSeriesPoint, FindingView, ReviewCase
from traust_core.v1.models.operations import SpendAttribution, SpendRollup, ThroughputPoint
from traust_core.v1.models.pqc import PqcRollup
from traust_core.v1.models.vocabulary import (
    RemediationStatus,
    RiskRatingBand,
    Severity,
    SlaClockStart,
)


class ViewName(StrEnum):
    FINDINGS_ROLLUP = "findings-rollup"
    FINDINGS_TREND = "findings-trend"
    COVERAGE = "coverage"
    LOC = "loc"
    ATTACK_COVERAGE = "attack-coverage"
    THREAT_REGISTER = "threat-register"
    EXPOSURE = "exposure"
    VALIDATION_FUZZ = "validation-fuzz"
    PQC = "pqc"
    COMPLIANCE = "compliance"
    PROGRAM = "program"
    EXECUTIVE_SUMMARY = "executive-summary"
    REVIEW_CARD = "review-card"
    TRIAGE = "triage"
    SARIF = "sarif"
    OSCAL = "oscal"
    SLA = "sla"
    REMEDIATION_INDEX = "remediation-index"
    FRESHNESS = "freshness"


# Each view's model is a contracts JSON schema (I4); shapes land with the view's slice.
class ViewModel(Model): ...


class ViewFilter(Model):
    """Scope (products, teams), the point in time, and for series a window and bucket;
    `artifact_id` names the document a single-item view renders."""

    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
    as_of: datetime | None = None
    window: TimeWindow | None = None
    bucket: TimeBucket = TimeBucket.MONTH
    artifact_id: UUID | None = None


class SeverityCounts(Model):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.informational


class FindingTally(Model):
    """Disposition-aware counts: only `open` is exposure; the rest say why a finding isn't."""

    open: SeverityCounts = SeverityCounts()
    hardening: int = 0
    resolved: int = 0
    risk_accepted: int = 0
    false_positive: int = 0
    execution_proven: int = 0
    unverified: int = 0


class RepositoryRollup(Model):
    repository_id: UUID
    repository_url: str
    tally: FindingTally
    hardening_categories: Mapping[str, int] = Field(default_factory=dict)


class ProductRollup(Model):
    product_id: UUID
    slug: str
    name: str
    repositories: int
    tally: FindingTally


class TopFinding(Model):
    finding_id: UUID
    repository_url: str
    title: str
    severity: Severity
    cvss_score: Decimal | None = None
    execution_proven: bool = False
    sla_due: datetime | None = None


class FindingsRollup(ViewModel):
    """Open findings by severity per repository and product; distinct findings in `total`."""

    as_of: datetime | None = None
    total: FindingTally
    products: tuple[ProductRollup, ...] = ()
    repositories: tuple[RepositoryRollup, ...] = ()
    top: tuple[TopFinding, ...] = ()


class FindingsTrend(ViewModel):
    """The scope's findings bucket by bucket, summed over its repositories."""

    as_of: datetime
    repositories: int
    points: tuple[FindingSeriesPoint, ...] = ()


class ProgramMetrics(ViewModel):
    """What the program spent and ran over a window: spend rollups and per-asset throughput."""

    window: TimeWindow
    bucket: TimeBucket
    spend: SpendAttribution
    by_month: tuple[SpendRollup, ...] = ()
    by_model: tuple[SpendRollup, ...] = ()
    by_lane: tuple[SpendRollup, ...] = ()
    by_skill: tuple[SpendRollup, ...] = ()
    throughput: Mapping[str, tuple[ThroughputPoint, ...]] = Field(default_factory=dict)


class TriageDocument(ViewModel):
    """A stored triage document, rendered as the triage report."""

    artifact_id: UUID
    payload: str


class PqcScope(Model):
    """One product's (None = every commit's) latest PQC readiness, by bucket and provenance."""

    product_id: UUID | None = None
    by_bucket: tuple[PqcRollup, ...] = ()
    by_provenance: tuple[PqcRollup, ...] = ()


class PqcDashboard(ViewModel):
    scopes: tuple[PqcScope, ...] = ()


class ExposureDashboard(ViewModel):
    """Dependency exposure from the latest impact analyses, by advisory, product and verdict."""

    by_advisory: tuple[ExposureRollup, ...] = ()
    by_product: tuple[ExposureRollup, ...] = ()
    by_classification: tuple[ExposureRollup, ...] = ()


class ComplianceDashboard(ViewModel):
    by_framework: tuple[ComplianceRollup, ...] = ()
    by_scope: tuple[ComplianceRollup, ...] = ()


class CoverageDashboard(ViewModel):
    """What the scope's repositories had assessed by `as_of`, and what their audits missed."""

    repositories: int
    population: Population
    gaps: Coverage


class RankedThreat(Model):
    """A threat with the band it ranks by: its stated OWASP severity, else the legacy crosswalk."""

    threat: Threat
    band: RiskRatingBand | None = None
    crosswalked: bool = False


class QuickWin(Model):
    """A class-closing XS/S mitigation covering unmitigated high or critical threats."""

    repository_id: UUID
    mitigation: str
    effort: str
    covers: tuple[str, ...]
    band: RiskRatingBand


class ThreatRegister(ViewModel):
    """The scope's threats from each repository's latest threat model as of `as_of`, ranked."""

    as_of: datetime
    repository_urls: Mapping[UUID, str]
    models: int
    threats: tuple[RankedThreat, ...] = ()
    quick_wins: tuple[QuickWin, ...] = ()
    open_variances: tuple[DocVariance, ...] = ()


class RepositoryLoc(Model):
    """A repository's measured lines at its default-branch commit; `unmeasured` says why not."""

    repository_id: UUID
    repository_url: str
    code: int = 0  # code lines, documentation languages excluded
    total: int = 0
    primary: str | None = None
    languages: tuple[LanguageCount, ...] = ()
    unmeasured: str | None = None


class LanguageTotal(Model):
    name: str
    code: int
    repositories: int
    documentation: bool


class LocDashboard(ViewModel):
    """Lines of code the scope's repositories hold, by language and repository, largest first."""

    code: int
    total: int
    languages: tuple[LanguageTotal, ...] = ()
    repositories: tuple[RepositoryLoc, ...] = ()


class RemediationRow(Model):
    """One work item: its product (None when no product is named), where its fix lives once
    reported, and where it stands."""

    product: str | None = None
    repository_url: str
    work_item_id: UUID
    status: RemediationStatus
    findings: int
    fork_url: str | None = None
    fix_branch: str | None = None
    tracker: str | None = None


class RemediationIndex(ViewModel):
    """Work items of the scope's repositories per product, oldest first, counted by status."""

    rows: tuple[RemediationRow, ...] = ()
    by_status: Mapping[str, int] = Field(default_factory=dict)


class LanguageSeverity(Model):
    """Open findings of the repositories whose primary language this is."""

    language: str
    repositories: int
    open: SeverityCounts


class LeastPrivilege(Model):
    """Declared-privilege posture from the latest priv-profiles; posture, never finding counts."""

    profiles: int
    privileged: int
    scc_requesting: int
    wildcard_repositories: int
    wildcard_rules: int
    flags: Mapping[str, int] = Field(default_factory=dict)


class ExecutiveSummary(ViewModel):
    """The leadership roll-up; `exposure` is fleet-wide, None for a product or team scope."""

    rollup: FindingsRollup
    credential_leaks: tuple[TopFinding, ...] = ()
    themes: Mapping[str, int] = Field(default_factory=dict)
    hardening_themes: Mapping[str, int] = Field(default_factory=dict)
    languages: tuple[LanguageSeverity, ...] = ()
    privileges: LeastPrivilege
    exposure: tuple[ExposureRollup, ...] | None = None


class ReviewCard(Model):
    """One case waiting on a person, with its finding and the false-positive call it weighs."""

    case: ReviewCase
    finding: FindingView
    refutation: Decision | None = None


class ReviewCards(ViewModel):
    """The scope's review queue as countersign cards, oldest first."""

    cards: tuple[ReviewCard, ...] = ()


class SlaTarget(Model):
    resolve_days: int | None
    acknowledge_days: int | None = None


class SlaCvssFloor(Model):
    threshold: Decimal
    resolve_days: int


class SlaProfile(Model):
    """Resolve clocks per severity: null days = tracked, never overdue; an absent severity is
    outside the profile unless the CVSS floor catches it."""

    default: bool = False
    description: str | None = None
    slas: Mapping[Severity, SlaTarget]
    cvss_floor_days: SlaCvssFloor | None = None


class SlaPolicySource(Model):
    name: str
    url: str | None = None
    retrieved: date
    note: str | None = None


class SlaPolicy(Model):
    """The contracts `sla-policy` document: SLAs are policy data, never code."""

    policy_name: str
    source: SlaPolicySource
    severity_mapping: Mapping[str, Severity]
    clock_start: SlaClockStart = SlaClockStart("first_routed_or_filed")
    profiles: Mapping[str, SlaProfile]


class SlaClockBasis(StrEnum):
    FILED = "filed"
    FIRST_EVENT = "first_event"
    AUDIT_DATE = "audit_date"


class SlaCounts(Model):
    """Every in-scope finding lands in one count; unclocked and out-of-scope are shown, never
    dropped."""

    open_in_sla: int = 0
    open_overdue: int = 0
    open_no_sla: int = 0
    unclocked: int = 0
    accepted: int = 0
    resolved_met: int = 0
    resolved_breached: int = 0
    resolved_unclocked: int = 0
    out_of_profile_scope: int = 0


class SlaTeamRow(Model):
    team: str
    overdue: int
    critical: int
    worst_days: int


class SlaEscalation(Model):
    finding_id: UUID
    repository_url: str
    severity: Severity
    title: str
    teams: tuple[str, ...]
    due: datetime
    days_overdue: int
    clock_basis: SlaClockBasis


class SlaProfileView(Model):
    profile: str
    description: str | None = None
    counts: SlaCounts
    resolved_compliance_pct: float | None = None
    median_days_to_resolve: Mapping[Severity, int] = Field(default_factory=dict)
    overdue_by_severity: Mapping[Severity, int] = Field(default_factory=dict)
    teams: tuple[SlaTeamRow, ...] = ()
    escalations: tuple[SlaEscalation, ...] = ()


class SlaDashboard(ViewModel):
    """Owner-response clocks over the scope's findings, one block per policy profile (the
    default first): different clocks over the same findings."""

    policy_name: str
    source: SlaPolicySource
    clock_start: SlaClockStart
    as_of: datetime
    profiles: tuple[SlaProfileView, ...]


class RenderedView(Model):
    """A view built and rendered; nothing is stored, the caller writes `<stem>.md/.html/.json`."""

    view: ViewName
    stem: str
    model: SerializeAsAny[ViewModel]
    markdown: str
    html: str


class RefreshResult(Model):
    """Each view rendered, and why each other view failed."""

    rendered: Mapping[ViewName, RenderedView] = Field(default_factory=dict)
    failed: Mapping[ViewName, str] = Field(default_factory=dict)
