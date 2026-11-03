from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import ConfigDict, Field, JsonValue, SerializeAsAny, computed_field

from traust_core.v1.models.assessment import (
    AttackScenario,
    Coverage,
    Population,
    TenantBoundary,
    Threat,
)
from traust_core.v1.models.base import Model
from traust_core.v1.models.code_facts import LanguageCount
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.compliance import ComplianceRollup, DocVariance
from traust_core.v1.models.dependencies import ExposureRollup
from traust_core.v1.models.detection_quality import Scorecard
from traust_core.v1.models.findings import (
    Decision,
    FindingRollup,
    FindingSeriesPoint,
    FindingView,
    Label,
    Occurrence,
    ReviewCase,
)
from traust_core.v1.models.harness_metadata import HarnessMetadata
from traust_core.v1.models.operations import SpendAttribution, SpendRollup, ThroughputPoint
from traust_core.v1.models.pqc import PqcCampaign, PqcReadiness, PqcRollup, PqcSite, PqcVendorClaim
from traust_core.v1.models.product_definitions import ProductContact, ProductResolution
from traust_core.v1.models.validation import ValidationRollup
from traust_core.v1.models.vocabulary import (
    IsolationDimension,
    OwnershipClass,
    RemediationStatus,
    RiskRatingBand,
    ScannerSeverity,
    Severity,
    SlaClockStart,
    ValidationVerdict,
)


class ViewName(StrEnum):
    FINDINGS_ROLLUP = "findings-rollup"
    CONTAINER_FINDINGS = "container-findings"
    INSECURE_PATTERNS = "insecure-patterns"
    FINDINGS_TREND = "findings-trend"
    COVERAGE = "coverage"
    LOC = "loc"
    ATTACK_COVERAGE = "attack-coverage"
    THREAT_REGISTER = "threat-register"
    EXPOSURE = "exposure"
    VALIDATION_FUZZ = "validation-fuzz"
    PQC = "pqc"
    PQC_PORTFOLIO = "pqc-portfolio"
    PQC_VENDORS = "pqc-vendors"
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
    DEPENDENCY_REACH = "dependency-reach"
    PRIVILEGES = "privileges"
    SCOREBOARD = "scoreboard"
    CENSUS = "census"
    SPEND = "spend"
    REPOSITORY_GRAPH = "repository-graph"
    CROWN_JEWEL_DRAFT = "crown-jewel-draft"
    IAC_CENSUS = "iac-census"
    ORGANIZATION_INDEX = "organization-index"


# Each view's model is a contracts JSON schema (I4); shapes land with the view's slice.
class ViewModel(Model): ...


class ExecutivePanel(StrEnum):
    ATTACK = "attack"
    PQC = "pqc"
    ISOLATION = "isolation"
    IAC = "iac"


class ViewFilter(Model):
    """Scope (products, teams, category labels), the point in time, and for series a window and
    bucket; `artifact_id` names the document a single-item view renders."""

    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
    # category-label values (free text until the weakness classification lands); when set,
    # findings without one of these categories are out of scope
    categories: tuple[str, ...] = ()
    as_of: datetime | None = None
    window: TimeWindow | None = None
    bucket: TimeBucket = TimeBucket.MONTH
    artifact_id: UUID | None = None
    executive_panels: tuple[ExecutivePanel, ...] = ()
    by_segment: bool = False
    exclude_segments: tuple[str, ...] = ("ansible",)
    crown_jewel_tier1_size: int = Field(default=20, ge=1, le=100)
    assessment_id: UUID | None = None
    report_stem: str | None = None
    compare_as_of: datetime | None = None
    first_party_divisor: Decimal | None = Field(default=None, gt=0, allow_inf_nan=False)
    reprice_spend: bool = False
    workstation_spend: bool = False


class SeverityCounts(Model):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    unrated: int = 0

    @property
    def total(self) -> int:
        return (
            self.critical + self.high + self.medium + self.low + self.informational + self.unrated
        )


class FindingTally(Model):
    """Disposition-aware counts: only `open` is exposure; the rest say why a finding isn't."""

    open: SeverityCounts = SeverityCounts()
    hardening: int = 0
    resolved: int = 0
    risk_accepted: int = 0
    false_positive: int = 0
    execution_proven: int = 0
    unverified: int = 0
    decided: int = 0  # findings with at least one decision
    remediated: SeverityCounts = SeverityCounts()  # the resolved, by severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tracked(self) -> int:
        """The findings that aren't false positives."""
        return self.open.total + self.hardening + self.resolved + self.risk_accepted


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
    severity: Severity | None
    cvss_score: Decimal | None = None
    execution_proven: bool = False
    sla_due: datetime | None = None


class CvssScoreSource(StrEnum):
    OCCURRENCE = "occurrence"
    ORIGINAL_REPORT = "original_report"


class SeverityCvssMismatch(Model):
    finding_id: UUID
    repository_url: str
    title: str
    category: str | None = None
    severity: Severity
    cvss_score: Decimal
    score_source: CvssScoreSource
    assessment_id: UUID
    occurrence_id: UUID | None = None
    cvss_band: Severity
    bands_below: int
    scored_informational: bool
    documented: bool
    rationale: str


class SeverityCvssMismatches(Model):
    documented: int = 0
    undocumented: int = 0
    details: tuple[SeverityCvssMismatch, ...] = ()


class ContainerReport(Model):
    assessment_id: UUID
    repository_ref_id: UUID
    occurred_at: datetime
    image: str
    title: str


class ContainerFinding(Model):
    view: FindingView
    occurrences: tuple[Occurrence, ...]
    history: tuple[Decision, ...] = ()


class ContainerFindings(ViewModel):
    as_of: datetime | None = None
    repository_id: UUID
    repository_url: str
    report_stem: str
    image_repository: str
    reports: tuple[ContainerReport, ...]
    findings: tuple[ContainerFinding, ...]
    total: FindingTally


class FindingsRollup(ViewModel):
    """Open findings by severity per repository and product; distinct findings in `total`."""

    as_of: datetime | None = None
    total: FindingTally
    products: tuple[ProductRollup, ...] = ()
    repositories: tuple[RepositoryRollup, ...] = ()
    top: tuple[TopFinding, ...] = ()
    categories: tuple[FindingRollup, ...] = ()  # per `category` label, largest first
    attack_scenarios: tuple[AttackScenario, ...] = ()  # a product or team scope's, verbatim
    severity_cvss_mismatches: SeverityCvssMismatches = SeverityCvssMismatches()


class PatternExample(Model):
    repository_url: str
    path: str
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None


class InsecurePattern(Model):
    """Findings sharing a primary CWE: occurrences are distinct (repository, path) pairs."""

    cwe: str
    name: str | None = None
    asvs_name: str | None = None
    fix: str | None = None
    co_cwes: tuple[str, ...] = ()
    asvs: str | None = None
    repositories: int
    repository_urls: tuple[str, ...] = ()
    occurrences: int
    severities: SeverityCounts
    examples: tuple[PatternExample, ...] = ()


class InsecurePatternCut(Model):
    """One corpus ownership class's patterns, ranked by repositories then occurrences;
    `without_cwe` counts the findings that carry no CWE and so fit no pattern."""

    ownership: OwnershipClass | None = None
    repositories_in_scope: int = 0
    total_findings: int = 0
    code_findings: int = 0
    excluded_non_code: int = 0
    false_positives: int = 0
    without_cwe: int = 0
    patterns: tuple[InsecurePattern, ...] = ()


class PatternPopulation(Model):
    roots: tuple[str, ...] = ()
    repositories: int = 0
    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
    categories: tuple[str, ...] = ()


class PatternTrend(Model):
    compared_at: datetime
    code_findings: int
    previous_code_findings: int
    distinct_cwes: int
    previous_distinct_cwes: int


class InsecurePatterns(ViewModel):
    """Current findings (false positives dropped) grouped by primary CWE per ownership class."""

    as_of: datetime | None = None
    population: PatternPopulation = Field(default_factory=PatternPopulation)
    trends: Mapping[str, PatternTrend] = Field(default_factory=dict)
    cuts: tuple[InsecurePatternCut, ...] = ()


class FindingsTrendPoint(FindingSeriesPoint):
    """A bucket summed over the scope: of the repositories reported by its end, how many had a
    decision recorded (ledger coverage)."""

    reported: int = 0
    dispositioned: int = 0

    owasp_open: Mapping[RiskRatingBand, int] = Field(default_factory=dict)
    owasp_unrated: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def owasp_high_plus_pct(self) -> float | None:
        """High/Critical share of open findings; unknown if any vector is unavailable."""
        total = sum(self.owasp_open.values())
        if self.owasp_unrated or not total:
            return None
        high = sum(self.owasp_open.get(RiskRatingBand(band), 0) for band in ("high", "critical"))
        return round(100 * high / total, 1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fp_rate(self) -> float:
        """False positives as a share (%) of the decisions recorded within the bucket."""
        return round(100 * self.false_positives / self.decisions, 1) if self.decisions else 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def coverage(self) -> float:
        return round(100 * self.dispositioned / self.reported, 1) if self.reported else 0.0


class TrendDirection(Model):
    """A metric's last bucket against the mean of up to three before it; within the dead band
    it is flat, else improving or worsening by the metric's good direction."""

    metric: str
    last: float
    baseline: float | None = None
    change_pct: float | None = None  # None when flat on one bucket or rising from zero
    rising: bool | None = None  # None when flat
    worsening: bool = False


class AcceptedRisk(Model):
    """An accepted finding on the standing register: unfixed, unmitigated, and who accepted it."""

    finding_id: UUID
    repository_url: str
    title: str
    severity: Severity
    cvss_score: Decimal | None = None
    accepted_at: datetime | None = None
    accepted_by: str | None = None
    rationale: str | None = None


class TrendCohortKind(StrEnum):
    HEAD = "HEAD"
    BRANCH = "branch"
    UNKNOWN = "unknown"


class TrendCohort(Model):
    ownership: OwnershipClass | None = None
    cohort: TrendCohortKind
    reported: int
    dispositioned: int

    @computed_field  # type: ignore[prop-decorator]
    @property
    def coverage(self) -> float | None:
        return round(100 * self.dispositioned / self.reported, 1) if self.reported else None


class TrendOwnershipCut(Model):
    ownership: OwnershipClass | None = None
    repositories: int
    reported: int
    dispositioned: int
    open: int
    open_critical: int
    open_high: int
    risk_index: float | None


class TrendExposure(Model):
    findings: int = 0
    risk_index: float | None = 0.0


class TrendAssurance(Model):
    claimed: TrendExposure = TrendExposure()
    verified: TrendExposure = TrendExposure()
    proven: TrendExposure = TrendExposure()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def triage_compression_risk(self) -> float | None:
        raw, static = self.claimed.risk_index, self.verified.risk_index
        return None if raw is None or static is None else round(raw - static, 1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def validation_gap_risk(self) -> float | None:
        static, proven = self.verified.risk_index, self.proven.risk_index
        return None if static is None or proven is None else round(static - proven, 1)


class TrendFpOverride(Model):
    finding_id: UUID
    repository_url: str
    asserted_by: str | None = None
    asserted_at: datetime
    proven_at: datetime


class TrendBlastRadius(Model):
    repository_url: str
    component: str
    confirmed_open: int
    hardening_open: int


class FindingsTrend(ViewModel):
    """The scope's findings bucket by bucket, summed over its repositories, each metric's
    direction, and the accepted-risk register standing at `as_of`."""

    as_of: datetime
    repositories: int
    points: tuple[FindingsTrendPoint, ...] = ()
    directions: tuple[TrendDirection, ...] = ()
    accepted: tuple[AcceptedRisk, ...] = ()
    cohorts: tuple[TrendCohort, ...] = ()
    ownership_cuts: tuple[TrendOwnershipCut, ...] = ()
    assurance: TrendAssurance = TrendAssurance()
    fp_overrides: tuple[TrendFpOverride, ...] = ()
    blast_radius: tuple[TrendBlastRadius, ...] = ()


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


class OscalAssessmentResults(ViewModel):
    """A recorded compliance assessment as OSCAL; the JSON model is the OSCAL document itself."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )

    assessment_results: dict[str, Any] = Field(alias="assessment-results")


class PqcScope(Model):
    """One product's (None = every commit's) latest PQC readiness, by bucket and provenance."""

    product_id: UUID | None = None
    campaign: PqcCampaign
    by_bucket: tuple[PqcRollup, ...] = ()
    by_provenance: tuple[PqcRollup, ...] = ()


class PqcDashboard(ViewModel):
    scopes: tuple[PqcScope, ...] = ()


class PqcRepositoryRow(Model):
    repository_url: str
    readiness: PqcReadiness


class PqcSiteRow(Model):
    repository_url: str
    site: PqcSite


class PqcPackageUse(Model):
    """A crypto package of the scope's manifest SBOMs and the repositories pulling it in."""

    package: str
    provider: str | None = None
    repositories: int


class PqcProductRow(Model):
    product: str
    repositories: int
    not_ready: int
    hndl_priority: int
    clock_2030: int
    worst_url: str | None = None
    worst_overall: float | None = None


class PqcPortfolioScope(Model):
    """One product's (None = every commit's) ranked PQC worklists, worst first."""

    product_id: UUID | None = None
    campaign: PqcCampaign
    repositories: tuple[PqcRepositoryRow, ...] = ()
    sites: tuple[PqcSiteRow, ...] = ()
    packages: tuple[PqcPackageUse, ...] = ()
    without_sbom: int = 0


class PqcPortfolio(ViewModel):
    scopes: tuple[PqcPortfolioScope, ...] = ()
    products: tuple[PqcProductRow, ...] = ()


class PqcVendorRow(Model):
    """A vendor's latest claim and the repositories whose manifests hold its packages (None:
    it names no package, reached through a provider, toolchain or service)."""

    claim: PqcVendorClaim
    repositories: int | None = None


class PqcVendorRoadmap(ViewModel):
    """The latest vendor claims worst first, with fleet counts derived from the default-branch
    manifests (`unmeasured` repositories have none) and the blocked-external repositories."""

    claims_artifact_id: UUID
    version: int
    updated: date
    vendors: tuple[PqcVendorRow, ...] = ()
    repositories: int
    unmeasured: int
    blocked_external: tuple[str, ...] = ()


class ExposureDashboard(ViewModel):
    """Dependency exposure from the latest impact analyses, by advisory, product and verdict."""

    by_advisory: tuple[ExposureRollup, ...] = ()
    by_product: tuple[ExposureRollup, ...] = ()
    by_classification: tuple[ExposureRollup, ...] = ()


class EcosystemReach(Model):
    ecosystem: str
    repositories: int
    packages: int


class PackageReach(Model):
    """A package and its blast radius: the repositories whose manifests hold it."""

    ecosystem: str
    name: str
    repositories: int


class DependencyReach(ViewModel):
    """What the scope's default-branch manifests hold: per ecosystem, the most shared packages,
    and how many repositories have no manifest SBOM to read."""

    repositories: int
    unmeasured: int
    ecosystems: tuple[EcosystemReach, ...] = ()
    shared: tuple[PackageReach, ...] = ()


class PrivilegeRow(Model):
    """One repository's latest priv-profile as the least-privilege rollup reads it."""

    repository: str
    assessment_id: UUID
    workloads: int
    privileged_workloads: int | None = None
    rbac_rules: int
    wildcard_rules: int | None = None
    scc_requests: tuple[str, ...] = ()
    privileged_sccs: tuple[str | None, ...] = ()
    flags: Mapping[str, int] = Field(default_factory=dict)
    containers: int | None = None
    privileged_containers: int | None = None
    run_as_non_root_containers: int | None = None
    namespaces: tuple[str, ...] = ()
    install_modes: tuple[str, ...] = ()
    kubebuilder_markers: int | None = None
    surplus: int | None = None
    distinct_rule_triples: int
    distinct_cluster_triples: int


class PrivilegesRollup(ViewModel):
    """Operator least privilege: the scope's latest priv-profiles as of `as_of`, ranked by tier-2
    surplus, then wildcard rules, then privileged workloads."""

    as_of: datetime | None = None
    rows: tuple[PrivilegeRow, ...] = ()


class FuzzPatternObservation(Model):
    name: str
    tested: bool
    vulnerable: bool | None
    reference: str | None = None
    advisory: str | None = None


class FuzzPatternRow(Model):
    name: str
    tested: int
    vulnerable: int
    unresolved: int
    references: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()

    @computed_field
    @property
    def hit_rate(self) -> float | None:
        return self.vulnerable / self.tested if self.tested and not self.unresolved else None


class FuzzBatchRow(Model):
    batch: str
    targets: int
    harnesses: int
    crashers: int


class FuzzCampaignBatch(Model):
    batch: str
    targets: int | None
    fuzz_functions: int | None
    bugs: int | None


class FuzzCampaignBug(Model):
    num: int
    target: str
    title: str
    cvss: str | None = None
    cwe: str | None = None
    advisory: str | None = None
    method: str | None = None
    narrative: str | None = None
    references: tuple[str, ...] = ()


class FuzzCampaignPattern(Model):
    name: str
    tested: int
    vulnerable: int
    rate: str | None = None
    advisory: str | None = None
    references: tuple[str, ...] = ()

    @computed_field
    @property
    def hit_rate(self) -> float | None:
        return self.vulnerable / self.tested if self.tested else None


class FuzzCampaignSnapshot(Model):
    """Supplied historical facts and verbatim analyst text, never execution evidence."""

    artifact: Literal["fuzz-campaign"]
    artifact_id: UUID | None = None
    campaign_id: str
    generated: date
    repositories: tuple[str, ...]
    source_references: tuple[str, ...]
    narrative: str | None = None
    harness_version: str | None = None
    manifest_generated: date | None = None
    duration: Mapping[str, date] | None = None
    totals: Mapping[str, int | float | str | None] | None = None
    batches: tuple[FuzzCampaignBatch, ...] = ()
    bugs: tuple[FuzzCampaignBug, ...] = ()
    patterns: tuple[FuzzCampaignPattern, ...] = ()
    remediation_priority: str | None = None
    negative_controls: str | None = None
    advisory_files: tuple[str, ...] = ()


class FuzzHarnessRow(Model):
    """A recorded harness execution, without treating failures or missing measurements as clean."""

    name: str
    engine: str
    path: str
    package: str | None = None
    duration_seconds: int
    execs: int | None = None
    corpus_entries: int | None = None
    outcome: str


class FuzzTargetRow(Model):
    """One recorded target run: harnesses, crashers, coverage and gaps."""

    repository: str
    target: str
    language: str
    assessment_id: UUID
    occurred_at: datetime
    repository_ref_id: UUID
    run_order_id: UUID | None = None
    module: str | None = None
    harnesses: tuple[FuzzHarnessRow, ...] = ()
    batch: str | None = None
    patterns: tuple[FuzzPatternObservation, ...] = ()
    engines: tuple[str, ...]
    outcomes: Mapping[str, int]  # harnesses per run outcome (clean, crashed, failed, not_run)
    execs: int | None = None  # None when no harness reported executions
    crashers: int
    lines_covered: int | None = None  # None: coverage not measured
    lines_total: int | None = None
    coverage_tool: str | None = None
    edges_covered: int | None = None
    edges_total: int | None = None
    gaps: int


class FuzzCrasherRow(Model):
    """A crasher a target's latest run recorded, as the producer proposed it."""

    repository: str
    target: str
    harness: str
    crasher: str
    assessment_id: UUID
    title: str
    crash_class: str
    severity: ScannerSeverity
    cvss: float | None = None
    cvss_vector: str | None = None
    cwes: tuple[str, ...] = ()
    reproducer_sha256: str
    reproducer_uri: str | None = None
    reproducer_path: str | None = None
    location_path: str | None = None
    location_lines: str | None = None
    location_description: str | None = None
    stack_hash: str | None = None
    stack_frames: int | None = None
    sanitizer: str | None = None
    narrative: str | None = None
    narrative_references: tuple[str, ...] = ()
    fix: str | None = None
    priority: str | None = None
    negative_control_references: tuple[str, ...] = ()
    confirms_finding_id: UUID | None = None


class FuzzGapRow(Model):
    """A surface a target's latest run left unfuzzed, and why."""

    repository: str
    target: str
    surface: str
    reason: str
    harness: str | None = None
    note: str | None = None


class ValidationCheckRow(Model):
    repository: str
    assessment_id: UUID
    artifact_id: UUID
    occurred_at: datetime
    target_environment: str | None = None
    source_report: str
    source_id: str
    finding_id: UUID
    title: str | None = None
    claimed_severity: ScannerSeverity | None = None
    declared_verdict: ValidationVerdict
    verdict: ValidationVerdict
    evidence_grade: str | None = None
    soundness_flag: str | None = None
    rationale: str | None = None
    observed_impact: str | None = None
    deviation_from_claim: str | None = None
    not_attempted_reason: str | None = None
    steps: int
    attempted_steps: int
    confirmed_steps: int


class ValidationChainStep(Model):
    step_id: str
    finding_ref: str | None = None
    adapter: str
    verb: str
    verdict: ValidationVerdict
    observed: str | None = None
    scope_reason: str | None = None
    soundness_flag: str | None = None
    evidence_refs: tuple[str, ...] = ()


class ValidationChainRow(Model):
    repositories: tuple[str, ...]
    artifact_ids: tuple[UUID, ...]
    run_id: UUID
    occurred_at: datetime
    target_environment: str | None = None
    chain_id: str
    name: str
    entry_point: str
    terminal_asset: str
    verdict: ValidationVerdict
    observed: bool
    exclusion: str | None = None
    techniques: tuple[str, ...] = ()
    narrative: str | None = None
    steps: tuple[ValidationChainStep, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confirmed_steps(self) -> int:
        return sum(s.verdict == ValidationVerdict.CONFIRMED for s in self.steps)


class ValidationSeverityRow(Model):
    claimed_severity: ScannerSeverity | None = None
    checks: int
    by_verdict: Mapping[ValidationVerdict, int]
    attempted_by_verdict: Mapping[ValidationVerdict, int] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempted(self) -> int:
        return sum(self.attempted_by_verdict.values())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict_share(self) -> Mapping[ValidationVerdict, float | None]:
        return {
            verdict: round(100 * self.attempted_by_verdict.get(verdict, 0) / self.attempted, 1)
            if self.attempted
            else None
            for verdict in ValidationVerdict
        }


class ValidationTargetChecks(Model):
    repository: str
    target_environment: str | None = None
    total: int
    attempted: int
    confirmed: int


class ValidationFuzz(ViewModel):
    """The fuzz campaign: each target's latest recorded run as of `as_of`, its crashers ranked
    by CVSS then proposed severity, and the surfaces left unfuzzed; and each repository's
    validated findings by latest verdict (key: the repository URL), most confirmed first."""

    as_of: datetime | None = None
    targets: tuple[FuzzTargetRow, ...] = ()
    crashers: tuple[FuzzCrasherRow, ...] = ()
    gaps: tuple[FuzzGapRow, ...] = ()
    runs: tuple[FuzzTargetRow, ...] = ()
    batches: tuple[FuzzBatchRow, ...] = ()
    patterns: tuple[FuzzPatternRow, ...] = ()
    campaign: FuzzCampaignSnapshot | None = None
    validation: tuple[ValidationRollup, ...] = ()
    repositories: int = 0
    checks: tuple[ValidationCheckRow, ...] = ()
    chains: tuple[ValidationChainRow, ...] = ()
    claimed_severity: tuple[ValidationSeverityRow, ...] = ()
    target_checks: tuple[ValidationTargetChecks, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def attempted_checks(self) -> int:
        return sum(c.declared_verdict != ValidationVerdict.NOT_ATTEMPTED for c in self.checks)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def check_coverage(self) -> float | None:
        return round(100 * self.attempted_checks / len(self.checks), 1) if self.checks else None


class CensusCut(Model):
    """One corpus ownership class's work and distinct vulnerabilities; `ownership` None holds
    the repositories no product with a registered ownership ships."""

    ownership: OwnershipClass | None = None
    products: int = 0
    repositories: int = 0
    audited: int = 0  # repositories with a default-line secure-code audit
    audits: int = 0  # default-line secure-code audits (work performed)
    branch_audits: int = 0
    distinct: SeverityCounts = SeverityCounts()
    open: SeverityCounts = SeverityCounts()
    occurrences: int = 0  # how often default-line assessments reported the distinct ones
    hardening: int = 0
    false_positives: int = 0
    dispositioned: int = 0  # distinct vulnerabilities with a decision recorded
    branch_confirmed: int = 0  # distinct vulnerabilities a branch re-audit also reported
    branch_only: int = 0  # vulnerabilities only branch re-audits reported


class CensusProduct(Model):
    product_id: UUID
    slug: str
    name: str
    ownership: OwnershipClass | None = None
    business_unit: str | None = None
    repositories: int = 0


class CensusLayer(Model):
    """Findings of a unit kept out of the distinct-vulnerability headline (declared IaC,
    container images): counted, never folded in."""

    findings: SeverityCounts = SeverityCounts()
    false_positives: int = 0


class Census(ViewModel):
    """The denominator authority: per corpus ownership class, distinct vulnerabilities (one per
    finding, default line only) over the scope's repositories as of `as_of`."""

    as_of: datetime
    repositories: int
    reported: int
    dispositioned: int
    never_assessed: int
    cuts: tuple[CensusCut, ...] = ()
    products: tuple[CensusProduct, ...] = ()
    cloud_config: CensusLayer = CensusLayer()
    container: CensusLayer = CensusLayer()
    unregistered: tuple[str, ...] = ()  # repository URLs no ownership-registered product ships


class ComplianceTeamControls(Model):
    team_id: UUID | None = None
    team: str
    repositories: int
    findings: int
    without_control_refs: int
    control_refs: Mapping[str, int] = Field(default_factory=dict)


class ComplianceTrendPoint(Model):
    assessed_at: datetime
    by_framework: tuple[ComplianceRollup, ...] = ()


class Scoreboard(ViewModel):
    """The leadership scoreboard: headline numbers read off the executive summary, findings
    trend and threat register as of `as_of`, plus the findings filed in Jira."""

    as_of: datetime
    repositories: int
    reported: int
    dispositioned: int
    open: SeverityCounts
    repositories_with_critical: int
    repositories_with_high: int
    credential_leaks: int
    resolved: int
    risk_accepted: int
    false_positives: int
    hardening: int
    execution_proven: int
    themes: Mapping[str, int] = Field(default_factory=dict)
    trend: FindingsTrendPoint | None = None  # the latest bucket
    threat_models: int
    threats: int
    open_threats: int
    filed: int
    validation: ValidationFuzz
    census: Census
    patterns: InsecurePatterns
    recall: tuple[Scorecard, ...] | None = None
    recall_unavailable: str | None = None
    maturity: HarnessMetadata | None = None


class ComplianceDashboard(ViewModel):
    as_of: datetime
    repositories: int
    reported: int
    dispositioned: int
    by_team: tuple[ComplianceTeamControls, ...] = ()
    history: tuple[ComplianceTrendPoint, ...] = ()
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
    """A class-closing xs/s mitigation covering unmitigated high or critical threats."""

    repository_id: UUID
    mitigation: str
    effort: str
    covers: tuple[str, ...]
    band: RiskRatingBand
    blocked_external: bool | None = None


class RankedBoundary(Model):
    """A tenant boundary with what ranks it: its failed and partial dimensions (weighing 2
    and 1) and the open threats it tags."""

    boundary: TenantBoundary
    weakness: int
    failed: tuple[IsolationDimension, ...] = ()
    partial: tuple[IsolationDimension, ...] = ()
    open_threats: tuple[Label, ...] = ()


class ThreatOwnershipCut(Model):
    ownership: OwnershipClass | None = None
    repositories: int
    models: int
    threats: int
    open: int
    open_critical: int


class ThreatRegister(ViewModel):
    """The scope's threats from each repository's latest threat model as of `as_of`, ranked."""

    as_of: datetime
    repository_urls: Mapping[UUID, str]
    models: int
    threats: tuple[RankedThreat, ...] = ()
    quick_wins: tuple[QuickWin, ...] = ()
    tenant_boundaries: tuple[RankedBoundary, ...] = ()  # weakest first
    open_variances: tuple[DocVariance, ...] = ()
    ownership: tuple[ThreatOwnershipCut, ...] = ()


class TechniqueCoverage(Model):
    """A technique's distinct modeled, weakness-derived, observed and attempted evidence."""

    technique_id: str
    name: str
    tactics: tuple[str, ...] = ()
    modeled: int = 0
    derived: int = 0
    observed: int = 0
    attempted: int = 0
    score: int  # 3 observed, 2 modeled, 1 weakness-derived, 0 attempted only


class AttackCoverage(ViewModel):
    """ATT&CK evidence as of a cutoff, retaining observed and attempted validation chains
    independently from modeled threats and weakness-derived candidates."""

    as_of: datetime
    attack_version: str
    mapping_version: str
    attribution: str
    repositories: int
    threat_models: int
    threats_with_techniques: int
    findings_mapped: int
    techniques: tuple[TechniqueCoverage, ...] = ()  # highest score first, then id
    validation_reports: int = 0
    validation_chains: int = 0
    dropped: Mapping[str, int] = Field(default_factory=dict)  # cited ids not live in the release
    navigator_layer: Mapping[str, Any] = Field(default_factory=dict)  # ATT&CK Navigator 4.5


class RepositoryLoc(Model):
    """A repository's measured lines at its default-branch commit; `unmeasured` says why not."""

    repository_id: UUID
    repository_url: str
    repository_ref_id: UUID | None = None
    code_delta: int | None = None
    total_delta: int | None = None
    code: int | None = None  # documentation languages excluded; None means not measured
    total: int | None = None
    primary: str | None = None
    languages: tuple[LanguageCount, ...] = ()
    unmeasured: str | None = None
    corpus_trees: tuple[str, ...] = ()


class LanguageTotal(Model):
    name: str
    code: int
    repositories: int
    documentation: bool


class LocComparison(Model):
    as_of: datetime
    code: int
    total: int
    measured_repositories: int
    comparable_repositories: int
    code_delta: int
    total_delta: int


class LocBucket(Model):
    tree: str | None
    repositories: int
    measured: int
    code: int
    total: int


class LocDashboard(ViewModel):
    """Lines of code the scope's repositories hold, by language and repository, largest first."""

    code: int
    as_of: datetime | None = None
    first_party_divisor: Decimal | None = None
    first_party_estimate: Decimal | None = None
    comparison: LocComparison | None = None
    total: int
    reported: int = 0  # repositories with findings reported, for the population block
    dispositioned: int = 0  # of those, with a decision recorded
    languages: tuple[LanguageTotal, ...] = ()
    repositories: tuple[RepositoryLoc, ...] = ()
    corpus_buckets: tuple[LocBucket, ...] = ()


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
    surplus_scored: int = 0
    wildcard_rules: int
    flags: Mapping[str, int] = Field(default_factory=dict)


class AdvisoryAccountability(Model):
    advisory: str
    findings: int
    filed: int
    resolved: int
    commits: int | None = None
    exposed: int | None = None
    affected: int | None = None


class SegmentSeverity(Model):
    segment: str
    mapped: bool = True
    repositories: int
    tally: FindingTally


class ExecutiveSegments(Model):
    rows: tuple[SegmentSeverity, ...] = ()
    priority: tuple[str, ...] = ()
    overlapping: tuple[str, ...] = ()
    unmapped: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    excluded_segments: tuple[str, ...] = ()


class IsolationReviewRow(Model):
    repository: str
    assessment_id: UUID
    service: str
    posture: str
    interfaces: int
    gaps: int
    dimensions: Mapping[str, int] = Field(default_factory=dict)


class IsolationSummary(Model):
    reviews: tuple[IsolationReviewRow, ...] = ()
    threat_register: ThreatRegister


class DeclaredIacTarget(Model):
    repository: str
    assessment_id: UUID
    target: str
    unsuppressed: int
    suppressed: int
    needs_review: int
    ledgered: int
    severities: SeverityCounts


class DeclaredIac(Model):
    repositories: int
    assessments: int
    findings: CensusLayer
    targets: tuple[DeclaredIacTarget, ...] = ()


class ExecutiveSummary(ViewModel):
    """The leadership roll-up; `exposure` is fleet-wide, None for a product or team scope."""

    rollup: FindingsRollup
    credential_leaks: tuple[TopFinding, ...] = ()
    themes: Mapping[str, int] = Field(default_factory=dict)
    hardening_themes: Mapping[str, int] = Field(default_factory=dict)
    languages: tuple[LanguageSeverity, ...] = ()
    privileges: LeastPrivilege
    exposure: tuple[ExposureRollup, ...] | None = None
    accountability: tuple[AdvisoryAccountability, ...] = ()
    top_surplus: tuple[PrivilegeRow, ...] = ()
    segments: ExecutiveSegments | None = None
    attack: AttackCoverage | None = None
    pqc: PqcPortfolio | None = None
    pqc_unavailable: str | None = None
    isolation: IsolationSummary | None = None
    iac: DeclaredIac | None = None


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
    severity: Severity | None
    title: str
    teams: tuple[str, ...]
    due: datetime
    days_overdue: int
    clock_basis: SlaClockBasis
    accountable_contacts: tuple[ProductContact, ...] = ()


class SlaProfileView(Model):
    profile: str
    description: str | None = None
    counts: SlaCounts
    resolved_compliance_pct: float | None = None
    median_days_to_resolve: Mapping[ScannerSeverity, int] = Field(default_factory=dict)
    overdue_by_severity: Mapping[ScannerSeverity, int] = Field(default_factory=dict)
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
    contacts: ProductResolution | None = None


class RenderedView(Model):
    """A view built and rendered; nothing is stored, the caller writes `<stem>.md/.html/.json`."""

    view: ViewName
    stem: str
    model: SerializeAsAny[ViewModel]
    markdown: str
    html: str
    csv: str | None = None  # the view's export table, when it has one
    graphviz: str | None = None
    gexf: str | None = None


class ReportSnapshotDocument(Model):
    """An as-reported bundle; exports remain text rather than today's view-model schema."""

    format_version: Literal[1] = 1
    view: ViewName
    generated_at: datetime
    core_version: str
    methodology_note: str = Field(min_length=1)
    scope_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    filter: Mapping[str, JsonValue]
    previous_artifact_id: UUID | None = None
    previous_digest: str | None = None
    stem: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=120)
    model_json: str
    markdown: str
    html: str
    csv: str | None = None


class ReportSnapshot(Model):
    artifact_id: UUID
    digest: str
    recorded_at: datetime
    document: ReportSnapshotDocument


class ReportHistory(ViewModel):
    snapshots: tuple[ReportSnapshot, ...] = ()


class ReportComparisonTarget(StrEnum):
    PREVIOUS = "previous"
    RECOMPUTED = "recomputed"
    CURRENT = "current"


class ReportChange(Model):
    path: str
    before: JsonValue = None
    after: JsonValue = None
    before_present: bool = True
    after_present: bool = True
    delta: Decimal | None = None


class ReportComparison(ViewModel):
    baseline_artifact_id: UUID
    baseline_digest: str
    compared_artifact_id: UUID | None = None
    compared_digest: str | None = None
    target: ReportComparisonTarget
    compared_at: datetime
    baseline_methodology_note: str
    compared_methodology_note: str
    changes: tuple[ReportChange, ...] = ()


class RefreshResult(Model):
    """Each view rendered, and why each other view failed."""

    rendered: Mapping[ViewName, RenderedView] = Field(default_factory=dict)
    failed: Mapping[ViewName, str] = Field(default_factory=dict)
