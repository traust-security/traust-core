from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Iterable, Sequence
from datetime import UTC, date, datetime, time
from decimal import Decimal
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConfigError, NotFoundError, TraustError, ValidationError
from traust_core.v1.models.artifacts import CloudConfigAuditArtifact, ReportArtifact, TriageArtifact
from traust_core.v1.models.assessment import (
    AssessmentFilter,
    AssessmentKind,
    AttackCatalog,
    TenantBoundary,
    Threat,
    ThreatFilter,
)
from traust_core.v1.models.common import every_item
from traust_core.v1.models.compliance import (
    ComplianceDimension,
    ComplianceFilter,
    ComplianceRollup,
    DocVarianceDisposition,
    DocVarianceFilter,
)
from traust_core.v1.models.corpus import CorpusRegistry
from traust_core.v1.models.dependencies import (
    ExposureDimension,
    ExposureFilter,
    ExposureRollup,
    NoManifestSbomError,
    malicious_id,
    package_name,
)
from traust_core.v1.models.findings import (
    FindingClock,
    FindingDimension,
    FindingFilter,
    FindingSeriesPoint,
    FindingState,
    FindingView,
    Location,
    Occurrence,
    ReviewCaseKind,
    ReviewFilter,
)
from traust_core.v1.models.insight import (
    AcceptedRisk,
    AttackCoverage,
    Census,
    CensusCut,
    CensusLayer,
    CensusProduct,
    ComplianceDashboard,
    CoverageDashboard,
    DependencyReach,
    EcosystemReach,
    ExecutiveSummary,
    ExposureDashboard,
    FindingsRollup,
    FindingsTrend,
    FindingsTrendPoint,
    FindingTally,
    FuzzCrasherRow,
    FuzzGapRow,
    FuzzTargetRow,
    LanguageSeverity,
    LanguageTotal,
    LeastPrivilege,
    LocDashboard,
    OscalAssessmentResults,
    PackageReach,
    PqcDashboard,
    PqcPackageUse,
    PqcPortfolio,
    PqcPortfolioScope,
    PqcProductRow,
    PqcRepositoryRow,
    PqcScope,
    PqcSiteRow,
    PqcVendorRoadmap,
    PqcVendorRow,
    PrivilegeRow,
    PrivilegesRollup,
    ProductRollup,
    ProgramMetrics,
    QuickWin,
    RankedBoundary,
    RankedThreat,
    RefreshResult,
    RemediationIndex,
    RemediationRow,
    RenderedView,
    RepositoryLoc,
    RepositoryRollup,
    ReviewCard,
    ReviewCards,
    Scoreboard,
    SeverityCounts,
    SlaCounts,
    SlaDashboard,
    SlaEscalation,
    SlaPolicy,
    SlaProfile,
    SlaProfileView,
    SlaTeamRow,
    TechniqueCoverage,
    ThreatRegister,
    TopFinding,
    TrendDirection,
    TriageDocument,
    ValidationFuzz,
    ViewFilter,
    ViewModel,
    ViewName,
)
from traust_core.v1.models.inventory import Product, Repository, RepositoryFilter, default_line
from traust_core.v1.models.operations import (
    FINISHED_ORDER_STATES,
    AssetName,
    OrderFilter,
    SpendDimension,
    SpendFilter,
)
from traust_core.v1.models.pqc import (
    PqcClockItem,
    PqcDimension,
    PqcFilter,
    PqcReadiness,
    PqcSiteKind,
    PqcVendorClaim,
)
from traust_core.v1.models.remediation import WorkItem, WorkItemFilter
from traust_core.v1.models.validation import ValidationDimension, ValidationFilter
from traust_core.v1.models.vocabulary import (
    DispositionAssurance,
    DispositionResolution,
    Ecosystem,
    MitigationEffort,
    OwnershipClass,
    PqcReadinessBucket,
    PqcVendorStatus,
    RiskRatingBand,
    ScannerSeverity,
    Severity,
    SlaClockStart,
    ValidationVerdict,
    Validity,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.rendering import (
    HtmlRenderer,
    MarkdownRenderer,
    Report,
    Section,
    Table,
    csv_table,
    inline,
)
from traust_core.v1.services.findings.rating import CvssFloor, RatingConfig, RatingPolicy, SlaConfig
from traust_core.v1.services.provider_catalog import core_version

if TYPE_CHECKING:
    from traust_core.v1.services.artifact_publishing import ArtifactPublisher
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.code_facts import CodeFactsService
    from traust_core.v1.services.compliance import ComplianceService
    from traust_core.v1.services.exposure import ExposureService
    from traust_core.v1.services.findings import FindingService
    from traust_core.v1.services.operations import OpsService, SpendService
    from traust_core.v1.services.portfolio import PortfolioService
    from traust_core.v1.services.pqc import PqcService
    from traust_core.v1.services.remediation import RemediationService
    from traust_core.v1.services.validation import ValidationService

log = logging.getLogger(__name__)


class View(Protocol):
    name: ViewName

    def build(self, filter: ViewFilter) -> ViewModel: ...

    def report(self, model: Any, generated_at: datetime) -> Report: ...


class InsightService:
    """Dashboards are derived views: built on demand and rendered, never stored."""

    def __init__(self, views: Sequence[View], clock: Clock) -> None:
        self._views = {v.name: v for v in views}
        self._clock = clock

    def build(self, view: ViewName, filter: ViewFilter) -> ViewModel:
        return self._view(view).build(filter)

    def report(self, view: ViewName, filter: ViewFilter) -> Report:
        """The view as a report for a person (markdown, html)."""
        found = self._view(view)
        return found.report(found.build(filter), filter.as_of or self._clock.now())

    def publish(self, view: ViewName, filter: ViewFilter) -> RenderedView:
        """The view's model and its markdown and html renders; core writes no files."""
        found = self._view(view)
        model = found.build(filter)
        report = found.report(model, filter.as_of or self._clock.now())
        export = getattr(found, "export", None)
        return RenderedView(
            view=view,
            stem=_stem(report.title),
            model=model,
            markdown=MarkdownRenderer().render(report).decode(),
            html=HtmlRenderer().render(report).decode(),
            csv=None if export is None else csv_table(export(model)),
        )

    def refresh(self, views: Sequence[ViewName] | None, filter: ViewFilter) -> RefreshResult:
        """Render each view (all registered, bar single-item renders, when None); a view that
        fails doesn't stop the rest.
        A ConfigError is the deployment's, not one view's, so it stops the refresh."""
        names = (
            [n for n, v in self._views.items() if not getattr(v, "per_item", False)]
            if views is None
            else list(dict.fromkeys(views))
        )
        for name in names:
            self._view(name)
        rendered: dict[ViewName, RenderedView] = {}
        failed: dict[ViewName, str] = {}
        for name in names:
            try:
                rendered[name] = self.publish(name, filter)
            except ConfigError:
                raise
            except TraustError as e:
                log.warning("view %s not refreshed: %s", name, e)
                failed[name] = f"{type(e).__name__}: {e}"
        return RefreshResult(rendered=rendered, failed=failed)

    def _view(self, name: ViewName) -> View:
        try:
            return self._views[name]
        except KeyError:
            known = ", ".join(sorted(self._views)) or "none"
            raise ValidationError(
                f"view {name.value!r} is not built; built views: {known}"
            ) from None


class FindingsRollupView:
    """Disposition-aware open findings by severity, per repository and product (team report)."""

    name = ViewName.FINDINGS_ROLLUP

    def __init__(
        self, findings: FindingService, portfolio: PortfolioService, assessment: AssessmentService
    ) -> None:
        self._findings = findings
        self._portfolio = portfolio
        self._assessment = assessment

    def build(self, filter: ViewFilter) -> FindingsRollup:
        rollup = _rollup(filter.as_of, *_scoped_findings(self._findings, self._portfolio, filter))
        if not (filter.product_ids or filter.team_ids):
            return rollup
        scenarios = self._assessment.attack_scenarios(
            [r.repository_id for r in rollup.repositories], filter.as_of
        )
        return rollup.model_copy(update={"attack_scenarios": tuple(scenarios)})

    def report(self, model: FindingsRollup, generated_at: datetime) -> Report:
        t = model.total
        summary = (
            f"{t.open.total} open: {_severities(t.open)}. "
            f"{t.execution_proven} execution-proven, {t.unverified} unverified (no verdict yet). "
            f"Not counted as open: {t.false_positive} false positives, {t.resolved} resolved, "
            f"{t.risk_accepted} risk accepted, {t.hardening} hardening."
        )
        if model.as_of is not None:
            summary += f"\n\nAs of {model.as_of.isoformat()}."
        unrated = bool(t.open.unrated)
        severity_columns = (
            "critical",
            "high",
            "medium",
            "low",
            "info",
            *(("unrated",) if unrated else ()),
            "total",
        )
        sections = [Section(heading="Summary", body=summary)]
        if model.products:
            sections.append(
                Section(
                    heading="By product",
                    body="A finding in a repository several products ship counts under each.",
                    table=Table(
                        columns=("product", "repositories", *severity_columns),
                        rows=tuple(
                            (p.name, str(p.repositories), *_counts(p.tally.open, unrated=unrated))
                            for p in model.products
                        ),
                    ),
                )
            )
        sections += [
            Section(
                heading="By repository",
                body="" if model.repositories else "_No repositories in scope._",
                table=Table(
                    columns=("repository", *severity_columns, "hardening", "resolved"),
                    rows=tuple(
                        (
                            r.repository_url,
                            *_counts(r.tally.open, unrated=unrated),
                            str(r.tally.hardening),
                            str(r.tally.resolved),
                        )
                        for r in model.repositories
                    ),
                )
                if model.repositories
                else None,
            ),
            Section(
                heading="Critical and high findings",
                body="" if model.top else "_None open._",
                table=Table(
                    columns=("repository", "finding", "severity", "cvss", "proven", "sla due"),
                    rows=tuple(_top_row(f) for f in model.top),
                )
                if model.top
                else None,
            ),
        ]
        backlog = [r for r in model.repositories if r.tally.hardening]
        sections.append(
            Section(
                heading="Hardening backlog",
                body="Defense-in-depth and benchmark gaps with no demonstrated exploit path: "
                "posture debt, filed as regular engineering work, not as security defects."
                + ("" if backlog else "\n\n_None._"),
                table=Table(
                    columns=("repository", "hardening", "categories"),
                    rows=tuple(
                        (
                            r.repository_url,
                            str(r.tally.hardening),
                            ", ".join(f"{c} {n}" for c, n in r.hardening_categories.items()),
                        )
                        for r in backlog
                    ),
                )
                if backlog
                else None,
            )
        )
        urls = {r.repository_id: r.repository_url for r in model.repositories}
        sections += [
            Section(
                heading=f"Attack scenarios: {urls[a.repository_id]} {a.label}"
                + (f", {inline(a.threat)}" if a.threat else ""),
                body="\n\n".join(f"> {inline(step)}" for step in a.steps)
                + f"\n\n_From the repository's latest threat model ({a.label})._",
            )
            for a in model.attack_scenarios
        ]
        title = "Findings rollup" + (
            f": {', '.join(p.name for p in model.products)}" if model.products else ""
        )
        return Report(title=title, generated_at=generated_at, sections=tuple(sections))


def _scoped_findings(
    findings: FindingService, portfolio: PortfolioService, filter: ViewFilter
) -> tuple[list[Product], dict[Any, set[UUID]], list[Repository], dict[UUID, list[FindingView]]]:
    """The scope (`_scope`) and each repository's findings as of the filter's point in time."""
    products, shipped, repositories = _scope(portfolio, filter)
    views = {
        r.id: findings.all(FindingFilter(repository_id=r.id, as_of=filter.as_of))  # type: ignore[arg-type]
        for r in repositories
    }
    return products, shipped, repositories, views  # type: ignore[return-value]


def _rollup(
    as_of: datetime | None,
    products: list[Product],
    shipped: dict[Any, set[UUID]],
    repositories: list[Repository],
    views: dict[UUID, list[FindingView]],
) -> FindingsRollup:
    urls = {r.id: r.url for r in repositories}
    everything = [v for found in views.values() for v in found]
    return FindingsRollup(
        as_of=as_of,
        total=_tally(everything),
        products=tuple(
            ProductRollup(
                product_id=p.id,  # type: ignore[arg-type]
                slug=p.slug,
                name=p.name,
                repositories=len(shipped[p.id]),
                tally=_tally(v for r in shipped[p.id] for v in views[r]),
            )
            for p in sorted(products, key=lambda p: p.slug)
        ),
        repositories=tuple(
            RepositoryRollup(
                repository_id=r.id,  # type: ignore[arg-type]
                repository_url=r.url,
                tally=_tally(views[r.id]),
                hardening_categories=dict(
                    sorted(Counter(_category(v) for v in views[r.id] if _is(v, _HARDENING)).items())
                ),
            )
            for r in repositories
        ),
        top=tuple(
            sorted(
                (
                    _top(v, urls[v.finding.repository_id])
                    for v in everything
                    if _is(v, _OPEN) and str(v.effective_severity) in _TOP
                ),
                key=lambda t: (_severity_rank(t.severity), -(t.cvss_score or -1), t.repository_url),
            )
        ),
    )


def _scope(
    portfolio: PortfolioService, filter: ViewFilter
) -> tuple[list[Product], dict[Any, set[UUID]], list[Repository]]:
    """The filter's products, the repositories each ships, and every repository in scope (all
    of them when no product or team is named), by URL."""
    products = [portfolio.get_product(p) for p in dict.fromkeys(filter.product_ids)]
    shipped = {
        p.id: {r.repository_id for r in portfolio.list_product_refs(p.id)}  # type: ignore[arg-type]
        for p in products
    }
    if not (filter.product_ids or filter.team_ids):
        repositories = list(every_item(lambda page: portfolio.list_repositories(_ALL, page)))
    else:
        wanted = {r for repos in shipped.values() for r in repos} | {
            r
            for t in dict.fromkeys(filter.team_ids)
            for r in portfolio.list_owned_repositories(t, filter.as_of)
        }
        repositories = [portfolio.get_repository(r) for r in wanted]
    return products, shipped, sorted(repositories, key=lambda r: r.url)


_ALL = RepositoryFilter()
_NOT_SLUG = re.compile(r"[^a-z0-9]+")


def _stem(title: str) -> str:
    return _NOT_SLUG.sub("-", title.lower()).strip("-")[:120] or "view"


_OPEN, _HARDENING = FindingState.OPEN, FindingState.HARDENING
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_TOP = ("critical", "high")


def _severity_rank(severity: Severity | None) -> int:
    return len(_RANK) if severity is None else _RANK[severity]


def _is(view: FindingView, state: FindingState) -> bool:
    return view.state() is state


def _top(view: FindingView, repository_url: str) -> TopFinding:
    return TopFinding(
        finding_id=view.finding.id,  # type: ignore[arg-type]
        repository_url=repository_url,
        title=view.finding.title,
        severity=view.effective_severity,
        cvss_score=view.occurrence.cvss_score if view.occurrence else None,
        execution_proven=_proven(view),
        sla_due=view.sla_due,
    )


def _proven(view: FindingView) -> bool:
    return view.disposition is not None and (
        view.disposition.assurance == DispositionAssurance.EXECUTION_PROVEN
    )


def _tally(views: Iterable[FindingView]) -> FindingTally:
    buckets: Counter[FindingState] = Counter()
    severities: Counter[str] = Counter()
    remediated: Counter[str] = Counter()
    proven = unverified = decided = 0
    for v in views:
        bucket = v.state()
        buckets[bucket] += 1
        decided += v.disposition is not None
        if bucket == FindingState.RESOLVED:
            remediated[str(v.effective_severity)] += 1
        if bucket == _OPEN:
            severities[
                str(
                    ScannerSeverity.UNRATED
                    if v.effective_severity is None
                    else v.effective_severity
                )
            ] += 1
            proven += _proven(v)
            unverified += v.disposition is None or (
                v.disposition.assurance == DispositionAssurance.CLAIMED
            )
    return FindingTally(
        open=SeverityCounts(**severities),
        hardening=buckets[_HARDENING],
        resolved=buckets[FindingState.RESOLVED],
        risk_accepted=buckets[FindingState.ACCEPTED],
        false_positive=buckets[FindingState.FALSE_POSITIVE],
        execution_proven=proven,
        unverified=unverified,
        decided=decided,
        remediated=SeverityCounts(**remediated),
    )


def _counts(c: SeverityCounts, *, unrated: bool = False) -> tuple[str, ...]:
    return tuple(
        map(
            str,
            (
                c.critical,
                c.high,
                c.medium,
                c.low,
                c.informational,
                *((c.unrated,) if unrated else ()),
                c.total,
            ),
        )
    )


def _severities(c: SeverityCounts) -> str:
    return ", ".join(
        f"{n} {s}"
        for s, n in (
            ("critical", c.critical),
            ("high", c.high),
            ("medium", c.medium),
            ("low", c.low),
            ("informational", c.informational),
            ("unrated", c.unrated),
        )
        if n or s != "unrated"
    )


# Unbuilt views: each names the dashboard it replaces and the stubbed door it waits on.
class _StubView:
    name: ViewName
    replaces = ""

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError(f"stub: replaces {self.replaces}")


class FindingsTrendView:
    """The scope's findings over time: each repository's series replayed to `as_of` (else now)
    and summed per bucket, each metric's direction, and the accepted-risk register; MTTR is
    weighted by each repository's resolutions."""

    name = ViewName.FINDINGS_TREND

    def __init__(self, findings: FindingService, portfolio: PortfolioService, clock: Clock) -> None:
        self._findings = findings
        self._portfolio = portfolio
        self._clock = clock

    def build(self, filter: ViewFilter) -> FindingsTrend:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories = _scope(self._portfolio, filter)
        by_bucket: defaultdict[datetime, list[FindingSeriesPoint]] = defaultdict(list)
        dispositioned: Counter[datetime] = Counter()
        accepted: list[AcceptedRisk] = []
        for r in repositories:
            query = FindingFilter(repository_id=r.id, as_of=as_of)  # type: ignore[arg-type]
            decided = 0
            for point in self._findings.timeline(query, filter.bucket):
                decided += point.decisions
                by_bucket[point.bucket].append(point)
                dispositioned[point.bucket] += decided > 0
            accepted += self._accepted(r, query)
        window = filter.window
        points = tuple(
            _summed(bucket, points, dispositioned[bucket])
            for bucket, points in sorted(by_bucket.items())
            if window is None or window.start <= bucket < window.end
        )
        return FindingsTrend(
            as_of=as_of,
            repositories=len(repositories),
            points=points,
            directions=tuple(
                _direction(metric, [float(read(p)) for p in points], good_down)
                for metric, read, good_down in _TREND_METRICS
            )
            if points
            else (),
            accepted=tuple(
                sorted(accepted, key=lambda a: (_RANK[str(a.severity)], -(a.cvss_score or -1)))
            ),
        )

    def _accepted(self, repository: Repository, query: FindingFilter) -> list[AcceptedRisk]:
        """The repository's accepted findings, each with its latest risk acceptance."""
        views = [v for v in self._findings.all(query) if _is(v, FindingState.ACCEPTED)]
        if not views:
            return []
        accepted_by = {
            d.finding_id: d
            for d in self._findings.decisions.for_repository(repository.id)  # type: ignore[arg-type]
            if d.resolution == DispositionResolution.RISK_ACCEPTED
            and (query.as_of is None or d.occurred_at <= query.as_of)
        }
        return [
            AcceptedRisk(
                finding_id=v.finding.id,  # type: ignore[arg-type]
                repository_url=repository.url,
                title=v.finding.title,
                severity=v.effective_severity,
                cvss_score=v.occurrence.cvss_score if v.occurrence else None,
                accepted_at=None if last is None else last.occurred_at,
                accepted_by=None if last is None else last.actor,
                rationale=last and last.rationale and last.rationale[:_RATIONALE_CHARS],
            )
            for v in views
            for last in [accepted_by.get(v.finding.id)]  # type: ignore[arg-type]
        ]

    def report(self, model: FindingsTrend, generated_at: datetime) -> Report:
        unknown = any(p.open_by_severity.get(ScannerSeverity.UNRATED, 0) for p in model.points)
        rows = tuple(
            (
                p.bucket.date().isoformat(),
                *(str(p.open_by_severity.get(Severity(s), 0)) for s in _RANK),
                *((str(p.open_by_severity.get(ScannerSeverity.UNRATED, 0)),) if unknown else ()),
                str(p.new),
                str(p.resolved),
                str(p.regressions),
                str(p.accepted),
                str(p.hardening),
                str(p.false_positives),
                str(p.fp_rate),
                "-" if p.mttr_days is None else str(p.mttr_days),
                "-" if p.risk_index is None else str(p.risk_index),
                "-" if p.accepted_risk_index is None else str(p.accepted_risk_index),
                str(p.coverage),
            )
            for p in model.points
        )
        columns = (
            "bucket",
            *_RANK,
            *(("unrated",) if unknown else ()),
            "new",
            "resolved",
            "regressions",
            "accepted",
            "hardening",
            "false positives",
            "fp rate %",
            "mttr days",
            "risk index",
            "accepted risk index",
            "coverage %",
        )
        latest = model.points[-1] if model.points else None
        summary = (
            f"{model.repositories} repositories, as of {model.as_of.isoformat()}. Open counts, "
            "accepted, hardening and the risk indexes stand at each bucket's end; new, resolved "
            "(velocity), regressions and false positives happened within it. The false-positive "
            "rate is of the decisions recorded within the bucket."
        )
        if latest is not None:
            summary += (
                f"\n\nLedger coverage: {latest.dispositioned} of {latest.reported} reported "
                f"repositories ({latest.coverage}%) have a decision recorded; findings without "
                "one count as open."
            )
        return Report(
            title="Findings trend",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _population(
                    model.repositories,
                    latest.reported if latest else 0,
                    latest.dispositioned if latest else 0,
                    "findings replayed to each bucket's end",
                ),
                _table_section(
                    "Direction",
                    ("metric", "last", "baseline", "change", "direction"),
                    [
                        (
                            _TREND_LABELS[d.metric],
                            str(d.last),
                            "-" if d.baseline is None else str(d.baseline),
                            "-" if d.change_pct is None else f"{d.change_pct:+}%",
                            _arrow(d),
                        )
                        for d in model.directions
                    ],
                    "_No findings reported in scope._",
                ),
                Section(heading="How directions read", body=_HOW_TO_READ_TRENDS),
                Section(
                    heading="Series",
                    body="" if rows else "_No findings reported in scope._",
                    table=Table(columns=columns, rows=rows) if rows else None,
                ),
                Section(
                    heading="Accepted risk register",
                    body=f"{len(model.accepted)} findings accepted, unfixed and unmitigated; "
                    f"accepted risk index {latest.accepted_risk_index if latest else 0.0}. The "
                    "register never decays: it shrinks only through remediation or re-triage."
                    + ("" if model.accepted else "\n\n_None._"),
                    table=Table(
                        columns=(
                            "repository",
                            "finding",
                            "severity",
                            "cvss",
                            "since",
                            "by",
                            "rationale",
                        ),
                        rows=tuple(
                            (
                                a.repository_url,
                                a.title,
                                str(a.severity),
                                "-" if a.cvss_score is None else str(a.cvss_score),
                                "-" if a.accepted_at is None else a.accepted_at.date().isoformat(),
                                a.accepted_by or "unknown",
                                a.rationale or "",
                            )
                            for a in model.accepted
                        ),
                    )
                    if model.accepted
                    else None,
                ),
            ),
        )


_RATIONALE_CHARS = 160
_DEAD_BAND = 0.10
# metric, how a bucket reads it, whether down is good
_TREND_METRICS: tuple[tuple[str, Callable[[FindingsTrendPoint], float], bool], ...] = (
    ("open", lambda p: sum(p.open_by_severity.values()), True),
    ("risk_index", lambda p: p.risk_index, True),
    ("new", lambda p: p.new, True),
    ("velocity", lambda p: p.resolved, False),
    ("mttr", lambda p: p.mttr_days or 0.0, True),
    ("fp_rate", lambda p: p.fp_rate, True),
    ("regressions", lambda p: p.regressions, True),
    ("accepted", lambda p: p.accepted, True),
    ("accepted_risk_index", lambda p: p.accepted_risk_index, True),
    ("hardening", lambda p: p.hardening, True),
    ("coverage", lambda p: p.coverage, False),
)
_TREND_LABELS = {
    "open": "Open findings",
    "risk_index": "Risk index (CVSS sum of open)",
    "new": "New findings",
    "velocity": "Remediation velocity (resolved per bucket)",
    "mttr": "MTTR (days)",
    "fp_rate": "False-positive rate (%)",
    "regressions": "Regressions",
    "accepted": "Risk-accepted findings",
    "accepted_risk_index": "Accepted risk index (CVSS sum)",
    "hardening": "Hardening backlog",
    "coverage": "Ledger coverage (%)",
}
_HOW_TO_READ_TRENDS = (
    "Direction compares the last bucket with the mean of up to three before it; within ±10% "
    "it is flat (→). ⚠ marks a metric moving the wrong way. The last bucket is usually partial: "
    "for board-ready numbers set as-of to the end of the previous bucket."
)


def _direction(metric: str, series: Sequence[float], good_down: bool) -> TrendDirection:
    """The last value against the mean of up to three before it, with a ±10% dead band."""
    last, prior = series[-1], series[-4:-1]
    if not prior:
        return TrendDirection(metric=metric, last=last)
    base = sum(prior) / len(prior)
    change = None if base == 0 else (last - base) / base
    flat = last == base == 0 or (change is not None and abs(change) <= _DEAD_BAND)
    rising = None if flat else last > base
    return TrendDirection(
        metric=metric,
        last=last,
        baseline=round(base, 2),
        change_pct=None if change is None else round(change * 100, 1),
        rising=rising,
        worsening=rising is not None and rising == good_down,
    )


def _arrow(d: TrendDirection) -> str:
    if d.rising is None:
        return "→ flat"
    return ("↑" if d.rising else "↓") + (" ⚠ worsening" if d.worsening else " improving")


def _population(in_scope: int, reported: int, dispositioned: int, unit: str) -> Section:
    """The standard population block: the scope, what of it reported findings, what of that
    has a decision recorded, and the unit counted."""
    return Section(
        heading="Population",
        body=f"Recorded state in traust-core {core_version()}; repositories are inventory rows, "
        f"each finding counted once. Unit: {unit}.",
        table=Table(
            columns=("population", "repositories"),
            rows=(
                ("In scope", str(in_scope)),
                ("With findings reported", str(reported)),
                ("With a decision recorded", str(dispositioned)),
            ),
        ),
    )


def _usd(amount: Decimal) -> str:
    return f"${amount:,.2f}"


def _summed_index(points: Sequence[FindingSeriesPoint], field: str) -> float | None:
    """The buckets' summed risk index; unknown when any bucket's is unknown."""
    values = [getattr(p, field) for p in points]
    return None if any(v is None for v in values) else round(sum(values), 1)


def _summed(
    bucket: datetime, points: Sequence[FindingSeriesPoint], dispositioned: int = 0
) -> FindingsTrendPoint:
    open_by: Counter[ScannerSeverity] = Counter()
    for p in points:
        open_by.update(p.open_by_severity)
    timed = [(p.mttr_days, p.resolved) for p in points if p.mttr_days is not None and p.resolved]
    weight = sum(n for _, n in timed)
    return FindingsTrendPoint(
        bucket=bucket,
        open_by_severity=dict(open_by),
        new=sum(p.new for p in points),
        resolved=sum(p.resolved for p in points),
        accepted=sum(p.accepted for p in points),
        hardening=sum(p.hardening for p in points),
        false_positives=sum(p.false_positives for p in points),
        regressions=sum(p.regressions for p in points),
        decisions=sum(p.decisions for p in points),
        mttr_days=round(sum(d * n for d, n in timed) / weight, 1) if weight else None,
        risk_index=_summed_index(points, "risk_index"),
        accepted_risk_index=_summed_index(points, "accepted_risk_index"),
        reported=len(points),
        dispositioned=dispositioned,
    )


class CoverageView:
    """Census and coverage gaps: what the scope's repositories had assessed by `as_of` (else
    now), the ones never assessed, and what their latest audits could not examine."""

    name = ViewName.COVERAGE

    def __init__(
        self, assessment: AssessmentService, portfolio: PortfolioService, clock: Clock
    ) -> None:
        self._assessment = assessment
        self._portfolio = portfolio
        self._clock = clock

    def build(self, filter: ViewFilter) -> CoverageDashboard:
        _, _, repositories = _scope(self._portfolio, filter)
        ids = [r.id for r in repositories]  # type: ignore[misc]
        everything = AssessmentFilter()
        return CoverageDashboard(
            repositories=len(ids),
            population=self._assessment.population(
                filter.as_of or self._clock.now(), everything, ids
            ),
            gaps=self._assessment.coverage(everything, ids),
        )

    def report(self, model: CoverageDashboard, generated_at: datetime) -> Report:
        kinds = Counter(r.kind for r in model.population.rows if r.latest is not None)
        never = len(model.population.never_assessed_repository_ids)
        summary = (
            f"{model.repositories} repositories as of {model.population.as_of.isoformat()}: "
            f"{never} never assessed. Latest audits examined {model.gaps.examined} of "
            f"{model.gaps.total} repositories' systems in full."
        )
        return Report(
            title="Coverage",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _table_section(
                    "Assessed, by kind",
                    ("kind", "repositories"),
                    [(k, str(n)) for k, n in sorted(kinds.items())],
                    "_Nothing assessed._",
                ),
                _table_section(
                    "Coverage gaps",
                    ("tool", "system", "repositories", "items"),
                    [
                        (
                            g.tool,
                            g.system,
                            str(g.repositories),
                            "-" if g.items is None else str(g.items),
                        )
                        for g in model.gaps.gaps
                    ],
                    "_No gaps reported._",
                ),
            ),
        )


class LocView:
    """Lines of code (loc-dashboard): each repository's latest measured languages at its
    default-branch commit, summed by language; documentation languages counted apart."""

    name = ViewName.LOC

    def __init__(
        self, code_facts: CodeFactsService, portfolio: PortfolioService, findings: FindingService
    ) -> None:
        self._code_facts = code_facts
        self._portfolio = portfolio
        self._findings = findings

    def build(self, filter: ViewFilter) -> LocDashboard:
        if filter.as_of is not None:
            raise ValidationError("the loc view reads the latest measurement; it takes no as_of")
        _, _, repositories = _scope(self._portfolio, filter)
        measured = [_measured(self._code_facts, self._portfolio, r) for r in repositories]
        totals: defaultdict[str, list[int]] = defaultdict(list)
        for r in measured:
            for language in r.languages:
                totals[language.name].append(language.code)
        tallies = [
            _tally(self._findings.all(FindingFilter(repository_id=r.id)))  # type: ignore[arg-type]
            for r in repositories
        ]
        return LocDashboard(
            code=sum(r.code for r in measured),
            total=sum(r.total for r in measured),
            reported=sum(map(_reported, tallies)),
            dispositioned=sum(bool(t.decided) for t in tallies),
            languages=tuple(
                sorted(
                    (
                        LanguageTotal(
                            name=name,
                            code=sum(lines),
                            repositories=len(lines),
                            documentation=name in _DOC_LANGUAGES,
                        )
                        for name, lines in totals.items()
                    ),
                    key=lambda t: (-t.code, t.name),
                )
            ),
            repositories=tuple(sorted(measured, key=lambda r: (-r.code, r.repository_url))),
        )

    def report(self, model: LocDashboard, generated_at: datetime) -> Report:
        unmeasured = [r for r in model.repositories if r.unmeasured]
        summary = (
            f"{len(model.repositories) - len(unmeasured)} of {len(model.repositories)} "
            f"repositories measured: {model.code:,} lines of code ({model.total:,} with "
            "documentation languages)."
        )
        return Report(
            title="Lines of code",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _table_section(
                    "By language",
                    ("language", "lines", "share", "repositories"),
                    [
                        (
                            t.name + (" (documentation)" if t.documentation else ""),
                            f"{t.code:,}",
                            "-" if t.documentation else f"{100 * t.code / (model.code or 1):.1f}%",
                            str(t.repositories),
                        )
                        for t in model.languages
                    ],
                    "_Nothing measured._",
                ),
                _table_section(
                    "By repository",
                    ("repository", "code lines", "all lines", "primary language"),
                    [
                        (r.repository_url, f"{r.code:,}", f"{r.total:,}", r.primary or "-")
                        for r in model.repositories
                        if not r.unmeasured
                    ],
                    "_Nothing measured._",
                ),
                _table_section(
                    "Not measured",
                    ("repository", "why"),
                    [(r.repository_url, r.unmeasured or "") for r in unmeasured],
                    "_None._",
                ),
                _population(
                    len(model.repositories),
                    model.reported,
                    model.dispositioned,
                    "lines measured at each repository's default-branch commit",
                ),
            ),
        )


def _measured(
    code_facts: CodeFactsService, portfolio: PortfolioService, repository: Repository
) -> RepositoryLoc:
    """The repository's latest measured languages at its default-branch commit, or why not."""
    found = RepositoryLoc(repository_id=repository.id, repository_url=repository.url)  # type: ignore[arg-type]
    ref = portfolio.default_ref(repository.id)  # type: ignore[arg-type]
    if ref is None:
        return found.model_copy(update={"unmeasured": "no observed default-branch head"})
    try:
        languages = code_facts.language_stats(ref.id).languages  # type: ignore[arg-type]
    except (NotFoundError, ValidationError) as e:
        return found.model_copy(update={"unmeasured": str(e)})
    code = [lang for lang in languages if lang.name not in _DOC_LANGUAGES]
    return found.model_copy(
        update={
            "code": sum(lang.code for lang in code),
            "total": sum(lang.code for lang in languages),
            "primary": max(languages, key=lambda lang: lang.code).name if languages else None,
            "languages": tuple(sorted(languages, key=lambda lang: (-lang.code, lang.name))),
        }
    )


_DOC_LANGUAGES = frozenset(
    {"Markdown", "reStructuredText", "TeX", "AsciiDoc", "HTML", "CSS", "SCSS", "Less", "Roff",
     "SVG", "Rich Text Format"}
)  # fmt: skip


class RemediationIndexView:
    """Per product, each work item's repository, fork, fix branch and status (the legacy
    per-product remediation index), derived on demand."""

    name = ViewName.REMEDIATION_INDEX

    def __init__(self, remediation: RemediationService, portfolio: PortfolioService) -> None:
        self._remediation = remediation
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> RemediationIndex:
        if filter.as_of is not None:
            raise ValidationError("the remediation index reads work items as they stand; no as_of")
        products, shipped, repositories = _scope(self._portfolio, filter)
        urls = {r.id: r.url for r in repositories}
        items = {
            r: list(every_item(partial(self._remediation.list, WorkItemFilter(repository_id=r))))
            for r in urls
        }
        groups = (
            [(p.slug, sorted(shipped[p.id], key=urls.__getitem__)) for p in products]
            if products
            else [(None, list(urls))]
        )
        rows = tuple(
            _remediation_row(slug, urls[r], item)
            for slug, repository_ids in groups
            for r in repository_ids
            for item in items[r]  # type: ignore[index]
        )
        return RemediationIndex(rows=rows, by_status=dict(Counter(r.status for r in rows)))

    def report(self, model: RemediationIndex, generated_at: datetime) -> Report:
        summary = f"{len(model.rows)} work items" + (
            ": " + ", ".join(f"{n} {s}" for s, n in sorted(model.by_status.items()))
            if model.rows
            else "."
        )
        return Report(
            title="Remediation index",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                *(
                    _table_section(
                        product or "All repositories",
                        ("repository", "work item", "status", "findings", "fork", "fix branch"),
                        [
                            (
                                r.repository_url,
                                str(r.work_item_id),
                                r.status,
                                str(r.findings),
                                r.fork_url or "-",
                                r.fix_branch or "-",
                            )
                            for r in model.rows
                            if r.product == product
                        ],
                        "_No work items._",
                    )
                    for product in dict.fromkeys(r.product for r in model.rows)
                ),
            ),
        )


def _remediation_row(product: str | None, url: str, item: WorkItem) -> RemediationRow:
    return RemediationRow(
        product=product,
        repository_url=url,
        work_item_id=item.work_item_id,
        status=item.status,
        findings=len(item.finding_ids),
        fork_url=None if item.fork is None else str(item.fork.url),
        fix_branch=item.fix_branch,
        tracker=None if item.tracker is None else item.tracker.ref,
    )


# Enterprise ATT&CK v19's tactics in kill-chain order; one a later release adds sorts last.
_TACTICS = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
_NO_OBSERVED = (
    "Observed (techniques in confirmed live-validation chains): not yet recorded in core; "
    "NEED(validation: confirmed chains' ATT&CK refs via ValidationService)."
)


class AttackCoverageView:
    """ATT&CK coverage (attack-coverage) as of `as_of`, else now: techniques the scope's latest
    threat models name (modeled) and its findings' categories imply (derived), against the pack's
    pinned catalog; a cited id not live in the release is dropped and counted."""

    name = ViewName.ATTACK_COVERAGE

    def __init__(
        self,
        assessment: AssessmentService,
        findings: FindingService,
        portfolio: PortfolioService,
        catalog: AttackCatalog,
        clock: Clock,
    ) -> None:
        self._assessment = assessment
        self._findings = findings
        self._portfolio = portfolio
        self._catalog = catalog
        self._clock = clock

    def build(self, filter: ViewFilter) -> AttackCoverage:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories = _scope(self._portfolio, filter)
        ids = tuple(r.id for r in repositories)  # type: ignore[misc]
        modeled: Counter[str] = Counter()
        dropped: Counter[str] = Counter()
        models: set[UUID] = set()
        with_techniques = 0
        query = ThreatFilter(repository_ids=ids, as_of=as_of)
        for threat in every_item(lambda p: self._assessment.threats(query, p)):
            models.add(threat.assessment_id)
            cited = {t.id for t in threat.techniques}
            live = {i for i in cited if not self._catalog.invalid((i,))}
            dropped.update(cited - live)
            modeled.update(live)
            with_techniques += bool(live)
        derived: Counter[str] = Counter()
        mapped = 0
        for repository_id in ids:
            category = FindingFilter(repository_id=repository_id, as_of=as_of)
            for group in self._findings.summary(category, FindingDimension.CATEGORY):
                implied = self._catalog.category_map.get(group.key or "", ())
                if implied:
                    mapped += group.findings
                    derived.update(dict.fromkeys(implied, group.findings))
        techniques = sorted(
            (
                TechniqueCoverage(
                    technique_id=i,
                    name=self._catalog.techniques[i].name,
                    tactics=self._catalog.techniques[i].tactics,
                    modeled=modeled[i],
                    derived=derived[i],
                    score=2 if modeled[i] else 1,
                )
                for i in modeled | derived
            ),
            key=lambda t: (-t.score, t.technique_id),
        )
        model = AttackCoverage(
            as_of=as_of,
            attack_version=self._catalog.attack_version,
            mapping_version=self._catalog.mapping_version,
            attribution=self._catalog.attribution,
            repositories=len(ids),
            threat_models=len(models),
            threats_with_techniques=with_techniques,
            findings_mapped=mapped,
            techniques=tuple(techniques),
            dropped=dict(dropped.most_common()),
        )
        return model.model_copy(update={"navigator_layer": _navigator_layer(model)})

    def report(self, model: AttackCoverage, generated_at: datetime) -> Report:
        summary = (
            f"ATT&CK v{model.attack_version} (pinned), mapping v{model.mapping_version}. "
            f"{model.repositories} repositories: {model.threat_models} threat models "
            f"({model.threats_with_techniques} threats name a technique), "
            f"{model.findings_mapped} findings mapped by weakness category. "
            f"{len(model.techniques)} techniques across "
            f"{len({a for t in model.techniques for a in t.tactics})} tactics. Evidence classes "
            "are never blended: **modeled** = named in a threat model; **derived** = candidate "
            "implied by a finding's weakness category (mapping table, not narrative)."
        )
        return Report(
            title="Attack coverage",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                Section(heading="Observed", body=_NO_OBSERVED),
                _table_section(
                    "Tactics",
                    ("tactic", "modeled", "derived", "techniques"),
                    [
                        (
                            tactic,
                            str(sum(1 for t in hit if t.modeled)),
                            str(sum(1 for t in hit if t.derived)),
                            str(len(hit)),
                        )
                        for tactic in sorted(
                            {a for t in model.techniques for a in t.tactics},
                            key=lambda a: (
                                _TACTICS.index(a) if a in _TACTICS else len(_TACTICS),
                                a,
                            ),
                        )
                        if (hit := [t for t in model.techniques if tactic in t.tactics])
                    ],
                    "_No techniques covered._",
                ),
                _table_section(
                    "Techniques",
                    ("id", "name", "score", "evidence"),
                    [
                        (t.technique_id, t.name, str(t.score), _evidence(t))
                        for t in model.techniques
                    ],
                    "_No techniques covered._",
                ),
                Section(
                    heading="Dropped references (invalid against the pinned table)",
                    body="\n".join(f"- `{i}` x {n}" for i, n in model.dropped.items()) or "_None._",
                ),
                Section(heading="Attribution", body=f"*{model.attribution}*"),
            ),
        )


def _evidence(t: TechniqueCoverage) -> str:
    return "; ".join(
        text
        for text, n in (
            (f"modeled in {t.modeled} threat(s)", t.modeled),
            (f"candidate for {t.derived} finding(s) by weakness class", t.derived),
        )
        if n
    )


def _navigator_layer(model: AttackCoverage) -> dict[str, Any]:
    def count(hit: Callable[[TechniqueCoverage], object]) -> str:
        return str(sum(1 for t in model.techniques if hit(t)))

    return {
        "name": f"Traust ATT&CK coverage ({model.as_of.date().isoformat()})",
        "versions": {
            "attack": model.attack_version.split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Deterministic fleet coverage: modeled (recorded threat models' "
        "techniques), weakness-derived candidates (finding categories via attack-mapping); "
        "observed (validated attack chains) is not yet recorded in core. " + model.attribution,
        "techniques": [
            {"techniqueID": t.technique_id, "score": t.score, "comment": _evidence(t)}
            for t in model.techniques
        ],
        "gradient": {"colors": ["#8ec843", "#ffe766", "#ff6666"], "minValue": 1, "maxValue": 3},
        "legend": [
            {"label": "1 weakness-derived candidate", "color": "#8ec843"},
            {"label": "2 modeled", "color": "#ffe766"},
            {"label": "3 observed (confirmed chain)", "color": "#ff6666"},
        ],
        "metadata": [
            {"name": "attack_version", "value": model.attack_version},
            {"name": "mapping_version", "value": model.mapping_version},
            {"name": "techniques_covered", "value": str(len(model.techniques))},
            {"name": "techniques_modeled", "value": count(lambda t: t.modeled)},
            {"name": "techniques_derived", "value": count(lambda t: t.derived)},
            {
                "name": "tactics_covered",
                "value": str(len({a for t in model.techniques for a in t.tactics})),
            },
        ],
    }


class ThreatRegisterView:
    """The fleet's standing threats (threat-register): each repository's latest threat model as
    of `as_of` (else now), ranked, with quick wins and open doc variances."""

    name = ViewName.THREAT_REGISTER

    def __init__(
        self,
        assessment: AssessmentService,
        compliance: ComplianceService,
        portfolio: PortfolioService,
        rating: RatingPolicy,
        clock: Clock,
    ) -> None:
        self._assessment = assessment
        self._compliance = compliance
        self._portfolio = portfolio
        self._rating = rating
        self._clock = clock

    def build(self, filter: ViewFilter) -> ThreatRegister:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories = _scope(self._portfolio, filter)
        urls: dict[UUID, str] = {r.id: r.url for r in repositories}  # type: ignore[misc]
        query = ThreatFilter(repository_ids=tuple(urls), as_of=as_of)
        threats = sorted(
            (self._ranked(t) for t in every_item(lambda p: self._assessment.threats(query, p))),
            key=lambda r: (
                _BANDS.index(r.band) if r.band else len(_BANDS),
                _THREAT_STATUSES.index(r.threat.status),
                urls[r.threat.repository_id],  # type: ignore[index]
                r.threat.label,
            ),
        )
        opened = {
            (r.threat.assessment_id, r.threat.label)
            for r in threats
            if r.threat.status in _OPEN_THREATS
        }
        boundaries = sorted(
            (_ranked_boundary(b, opened) for b in self._assessment.tenant_boundaries(urls, as_of)),
            key=lambda r: (
                -r.weakness,
                -_COMPLEXITY.index(r.boundary.complexity or "low"),
                -len(r.open_threats),
                urls[r.boundary.repository_id],
                r.boundary.boundary_id,
            ),
        )
        open_variances = DocVarianceFilter(disposition=DocVarianceDisposition("open"))
        return ThreatRegister(
            as_of=as_of,
            repository_urls=urls,
            models=len({r.threat.assessment_id for r in threats}),
            threats=tuple(threats),
            quick_wins=_quick_wins(threats),
            tenant_boundaries=tuple(boundaries),
            open_variances=tuple(
                v
                for v in every_item(lambda p: self._compliance.doc_variances(open_variances, p))
                if v.repository_id in urls
            ),
        )

    def _ranked(self, threat: Threat) -> RankedThreat:
        crosswalked = threat.severity is None and None not in (threat.impact, threat.likelihood)
        return RankedThreat(
            threat=threat,
            band=self._rating.threat_rating(threat) if crosswalked else threat.severity,
            crosswalked=crosswalked,
        )

    def report(self, model: ThreatRegister, generated_at: datetime) -> Report:
        urls = model.repository_urls
        threats = [r.threat for r in model.threats]
        opened = [r for r in model.threats if r.threat.status in _OPEN_THREATS]
        statuses = Counter(t.status for t in threats)
        open_bands = Counter(r.band or "unknown" for r in opened)
        per_repository: defaultdict[UUID, Counter[str]] = defaultdict(Counter)
        for r in model.threats:
            counts = per_repository[r.threat.repository_id]  # type: ignore[index]
            counts["threats"] += 1
            counts[r.threat.status] += 1
            if r.threat.status in _OPEN_THREATS:
                counts["open"] += 1
                counts[f"open {r.band}"] += 1
        exposure = sorted(
            per_repository.items(),
            key=lambda kv: (*(-kv[1][f"open {b}"] for b in _BANDS), urls[kv[0]]),
        )
        summary = (
            f"{model.models} threat models across {len(urls)} repositories as of "
            f"{model.as_of.isoformat()}: {len(threats)} threats, {len(opened)} open. "
            f"Rated with OWASP: {sum(t.severity is not None for t in threats)}; ordered by the "
            f"legacy crosswalk: {sum(r.crosswalked for r in model.threats)}. Evidence-backed: "
            f"{sum(bool(t.evidence) for t in threats)} (the rest are STRIDE gap-fill); LINDDUN "
            f"privacy rows: {sum(t.linddun for t in threats)}."
        )
        quick_wins = model.quick_wins[:_TOP_THREATS]
        show_blocking = any(w.blocked_external is not None for w in quick_wins)
        return Report(
            title="Threat register",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                Section(heading="How to read this", body=_HOW_TO_READ_THREATS),
                _table_section(
                    "Threats by status",
                    ("status", "threats"),
                    [(s, str(statuses[s])) for s in _THREAT_STATUSES],
                    "",
                ),
                _table_section(
                    "Open threats by severity",
                    ("severity", "threats"),
                    [(b, str(open_bands[b])) for b in (*_BANDS, "unknown")],
                    "",
                ),
                _table_section(
                    f"Top {_TOP_THREATS} open threats (of {len(opened)})",
                    ("repository", "threat", "title", "severity", "likelihood", "impact", "status"),
                    [
                        (
                            urls[r.threat.repository_id],  # type: ignore[index]
                            r.threat.label,
                            r.threat.title,
                            (r.band or "unknown") + (" (legacy crosswalk)" * r.crosswalked),
                            r.threat.likelihood or "-",
                            r.threat.impact or "-",
                            r.threat.status,
                        )
                        for r in opened[:_TOP_THREATS]
                    ],
                    "_No open threats._",
                ),
                _table_section(
                    f"Top {_TOP_THREATS} quick wins (of {len(model.quick_wins)})",
                    ("repository", "mitigation", "effort", "covers", "severity")
                    + (("blocked_external",) if show_blocking else ()),
                    [
                        (urls[w.repository_id], w.mitigation, w.effort, ", ".join(w.covers), w.band)
                        + (
                            (
                                str(w.blocked_external).lower()
                                if w.blocked_external is not None
                                else "-",
                            )
                            if show_blocking
                            else ()
                        )
                        for w in quick_wins
                    ],
                    "_No quick wins._",
                ),
                *_weakest_boundaries(model),
                _table_section(
                    "Risk acceptances",
                    ("repository", "risk accepted"),
                    [
                        (urls[r], str(c["risk_accepted"]))
                        for r, c in sorted(
                            per_repository.items(), key=lambda kv: -kv[1]["risk_accepted"]
                        )
                        if c["risk_accepted"]
                    ],
                    "_None._",
                ),
                _table_section(
                    f"Top {_TOP_THREATS} repositories by open-threat severity (of {len(exposure)})",
                    ("repository", "threats", "open", "open critical", "open high"),
                    [
                        (
                            urls[r],
                            *(str(c[k]) for k in ("threats", "open", "open critical", "open high")),
                        )
                        for r, c in exposure[:_TOP_THREATS]
                    ],
                    "_No threat models recorded._",
                ),
                _table_section(
                    "Documentation variance (official docs vs code)",
                    ("repository", "record", "variance", "doc version", "claim", "verified"),
                    [
                        (
                            urls[v.repository_id],
                            v.record,
                            v.kind or "-",
                            v.version,
                            v.claim[:140],
                            v.verified_at.date().isoformat(),
                        )
                        for v in model.open_variances
                    ],
                    "_No open doc variances._",
                ),
            ),
        )


_BANDS = tuple(RiskRatingBand)
_THREAT_STATUSES = ("unmitigated", "partially_mitigated", "risk_accepted", "mitigated")
_OPEN_THREATS = ("unmitigated", "partially_mitigated")
_TOP_THREATS = 25
_HOW_TO_READ_THREATS = (
    "Statuses and ratings are reported exactly as the models state them; they decay until a "
    "threat-model review re-rates them against current code. Severity is the OWASP Risk Rating "
    "Methodology band; a threat not yet re-rated is ordered by a fixed crosswalk from its legacy "
    "impact and likelihood labels and marked *legacy crosswalk*, an ordering aid, not a rating. "
    "Neither is CVSS, and neither feeds the risk index. Threats join findings only through "
    "their evidence citations."
)


_DIMENSION_WEIGHTS = {"no": 2, "partial": 1}  # yes and na weigh nothing
_COMPLEXITY = ("low", "medium", "high")
_HOW_TO_READ_BOUNDARIES = (
    "Tenant-boundary rows from multi-tenant models' optional section 10, ordered weakest-first "
    "(failed then partial isolation-hardening dimensions, then complexity and tagged open "
    "threats). Dimension results are reported exactly as the models state them; a linked "
    "isolation review carries the evidence."
)


def _weakest_boundaries(model: ThreatRegister) -> list[Section]:
    """The md's weakest-boundaries table; absent when no model carries a section 10."""
    if not model.tenant_boundaries:
        return []
    rows = tuple(
        (
            model.repository_urls[b.boundary.repository_id],
            b.boundary.boundary_id,
            b.boundary.interface,
            b.boundary.kind,
            b.boundary.exposure,
            b.boundary.complexity or "-",
            ", ".join(b.failed) or "-",
            ", ".join(b.partial) or "-",
            str(len(b.open_threats)),
            b.boundary.isolation_review_ref or "-",
        )
        for b in model.tenant_boundaries[:_TOP_THREATS]
    )
    return [
        Section(
            heading=f"Weakest tenant boundaries ({len(model.tenant_boundaries)})",
            body=_HOW_TO_READ_BOUNDARIES,
            table=Table(
                columns=(
                    *("repository", "boundary", "interface", "kind", "exposure", "complexity"),
                    *("failed dims", "partial dims", "open threats", "review"),
                ),
                rows=rows,
            ),
        )
    ]


def _ranked_boundary(
    boundary: TenantBoundary, opened: Collection[tuple[UUID, str]]
) -> RankedBoundary:
    stated = boundary.dimensions.items()
    return RankedBoundary(
        boundary=boundary,
        weakness=sum(_DIMENSION_WEIGHTS.get(v, 0) for _, v in stated),
        failed=tuple(d for d, v in stated if v == "no"),
        partial=tuple(d for d, v in stated if v == "partial"),
        open_threats=tuple(t for t in boundary.threat_ids if (boundary.assessment_id, t) in opened),
    )


def _quick_wins(threats: Sequence[RankedThreat]) -> tuple[QuickWin, ...]:
    """Class-closing xs/s mitigations over unmitigated high or critical threats, per model."""
    covered: dict[tuple[UUID, str, str, bool | None], list[RankedThreat]] = defaultdict(list)
    for r in threats:
        if r.threat.status == "unmitigated" and r.band in ("critical", "high"):
            for m in r.threat.mitigations:
                if (
                    m.closes_class == "yes"
                    and m.effort is not None
                    and any(
                        p.enum == "mitigation_effort"
                        and p.value in (MitigationEffort.XS_CANONICAL, MitigationEffort.S_CANONICAL)
                        for p in contracts.normalize_enum("mitigation_effort", m.effort).pairs
                    )
                ):
                    covered[r.threat.assessment_id, m.text, m.effort, m.blocked_external].append(r)
    wins = [
        QuickWin(
            repository_id=rs[0].threat.repository_id,  # type: ignore[arg-type]
            mitigation=text,
            effort=effort,
            covers=tuple(r.threat.label for r in rs),
            band=rs[0].band,  # type: ignore[arg-type]
            blocked_external=blocked_external,
        )
        for (_, text, effort, blocked_external), rs in covered.items()
    ]
    return tuple(sorted(wins, key=lambda w: (_BANDS.index(w.band), w.mitigation)))


class ExposureView:
    """Dependency exposure (refresh-dashboards' build_dependency_exposure): the latest impact
    analyses as of `as_of`, by advisory, by product and by verdict."""

    name = ViewName.EXPOSURE

    def __init__(self, exposure: ExposureService) -> None:
        self._exposure = exposure

    def build(self, filter: ViewFilter) -> ExposureDashboard:
        _fleet_only(self.name, filter)
        every = ExposureFilter(as_of=filter.as_of)
        return ExposureDashboard(
            by_advisory=tuple(self._exposure.summary(every, ExposureDimension.ADVISORY)),
            by_product=tuple(self._exposure.summary(every, ExposureDimension.PRODUCT)),
            by_classification=tuple(
                self._exposure.summary(every, ExposureDimension.CLASSIFICATION)
            ),
        )

    def report(self, model: ExposureDashboard, generated_at: datetime) -> Report:
        columns = ("key", "commits", "exposed", "affected")
        sections = tuple(
            _table_section(
                heading,
                columns,
                [(r.key or "-", str(r.commits), str(r.exposed), str(r.affected)) for r in rollups],
                "_No impact analyses recorded._",
            )
            for heading, rollups in (
                ("By advisory", model.by_advisory),
                ("Malicious packages (MAL- advisories)", _malicious(model.by_advisory)),
                ("By product", model.by_product),
                ("By verdict", model.by_classification),
            )
        )
        return Report(title="Dependency exposure", generated_at=generated_at, sections=sections)


def _malicious(rollups: Sequence[ExposureRollup]) -> list[ExposureRollup]:
    return [r for r in rollups if r.key and malicious_id(r.key)]


class DependencyReachView:
    """Shared dependencies (refresh-dashboards' build_dependency_exposure coverage and blast
    radius): the packages each repository's latest default-branch manifest holds, per ecosystem
    and by how many repositories share them."""

    name = ViewName.DEPENDENCY_REACH

    def __init__(self, exposure: ExposureService, portfolio: PortfolioService) -> None:
        self._exposure = exposure
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> DependencyReach:
        if filter.as_of is not None:
            raise ValidationError("the dependency-reach view reads the latest manifests; no as_of")
        _, _, repositories = _scope(self._portfolio, filter)
        held, unmeasured = _manifest_holders(self._exposure, self._portfolio, repositories)
        ecosystems: defaultdict[str, list[set[UUID]]] = defaultdict(list)
        for (ecosystem, _), holders in held.items():
            ecosystems[ecosystem].append(holders)
        return DependencyReach(
            repositories=len(repositories),
            unmeasured=unmeasured,
            ecosystems=tuple(
                sorted(
                    (
                        EcosystemReach(
                            ecosystem=e, repositories=len(set().union(*sets)), packages=len(sets)
                        )
                        for e, sets in ecosystems.items()
                    ),
                    key=lambda r: (-r.repositories, r.ecosystem),
                )
            ),
            shared=tuple(
                sorted(
                    (
                        PackageReach(ecosystem=e, name=n, repositories=len(holders))
                        for (e, n), holders in held.items()
                    ),
                    key=lambda p: (-p.repositories, p.ecosystem, p.name),
                )[:_TOP_SHARED]
            ),
        )

    def report(self, model: DependencyReach, generated_at: datetime) -> Report:
        summary = (
            f"{model.repositories - model.unmeasured} of {model.repositories} repositories have a "
            "manifest SBOM at their default-branch commit; the rest are not measured, not "
            "dependency-free. docker and helm are dependency surfaces only: their vulnerabilities "
            "come from image SBOMs, so they never appear in the exposure view's advisory tables."
        )
        return Report(
            title="Dependency reach",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _table_section(
                    "Per ecosystem",
                    ("ecosystem", "repositories", "packages"),
                    [(e.ecosystem, str(e.repositories), str(e.packages)) for e in model.ecosystems],
                    "_No manifests recorded._",
                ),
                _table_section(
                    f"Top {_TOP_SHARED} shared packages by blast radius",
                    ("ecosystem", "package", "repositories"),
                    [(p.ecosystem, p.name, str(p.repositories)) for p in model.shared],
                    "_No manifests recorded._",
                ),
            ),
        )


_TOP_SHARED = 25


def _manifest_holders(
    exposure: ExposureService, portfolio: PortfolioService, repositories: Sequence[Repository]
) -> tuple[dict[tuple[str, str], set[UUID]], int]:
    """Per (ecosystem, package): the repositories whose latest default-branch manifest holds it;
    and how many repositories have no manifest SBOM there (not measured, not dependency-free)."""
    held: defaultdict[tuple[str, str], set[UUID]] = defaultdict(set)
    unmeasured = 0
    for r in repositories:
        ref = portfolio.default_ref(r.id)  # type: ignore[arg-type]
        if ref is None or ref.manifest_sbom_id is None:
            unmeasured += 1
            continue
        for d in exposure.dependencies(ref.id):  # type: ignore[arg-type]
            held[d.package.ecosystem, d.package.name].add(r.id)  # type: ignore[arg-type]
    return held, unmeasured


_CONFIRMED = ValidationVerdict("confirmed")
_VERDICTS = tuple(ValidationVerdict)


class ValidationFuzzView:
    """The validation and fuzz campaign (create-fuzzing's rollup, validation-fuzz-dashboard):
    each target's latest recorded fuzz run as of `as_of`, crashers ranked by CVSS then proposed
    severity, and each repository's validated findings by latest verdict."""

    name = ViewName.VALIDATION_FUZZ

    def __init__(
        self,
        assessment: AssessmentService,
        portfolio: PortfolioService,
        validation: ValidationService,
    ) -> None:
        self._assessment = assessment
        self._portfolio = portfolio
        self._validation = validation

    def build(self, filter: ViewFilter) -> ValidationFuzz:
        _, _, repositories = _scope(self._portfolio, filter)
        urls: dict[UUID, str] = {r.id: r.url for r in repositories}  # type: ignore[misc]
        targets, crashers, gaps = [], [], []
        for repository_id, a, doc in self._assessment.fuzz_reports(list(urls), filter.as_of):
            assert a.id is not None
            where = {"repository": urls[repository_id], "target": doc.target.id}
            harnesses = doc.target.harnesses
            execs = [h.execs for h in harnesses if h.execs is not None]
            targets.append(
                FuzzTargetRow(
                    **where,
                    language=doc.target.language,
                    assessment_id=a.id,
                    occurred_at=a.occurred_at,
                    engines=tuple(sorted({h.engine for h in harnesses})),
                    outcomes=dict(Counter(h.outcome for h in harnesses)),
                    execs=sum(execs) if execs else None,
                    crashers=len(doc.crashers),
                    lines_covered=doc.coverage.lines_covered if doc.coverage else None,
                    lines_total=doc.coverage.lines_total if doc.coverage else None,
                    gaps=len(doc.gaps),
                )
            )
            crashers += [
                FuzzCrasherRow(
                    **where,
                    harness=c.harness,
                    crasher=c.id,
                    title=c.title,
                    crash_class=c.signature.crash_class,
                    severity=ScannerSeverity(c.severity_proposal),
                    cvss=c.cvss.score if c.cvss else None,
                    cwes=tuple(c.cwes),
                    reproducer_sha256=c.reproducer.sha256,
                    confirms_finding_id=UUID(c.finding_id) if c.finding_id else None,
                )
                for c in doc.crashers
            ]
            gaps += [
                FuzzGapRow(
                    **where, surface=g.surface, reason=g.reason, harness=g.harness, note=g.note
                )
                for g in doc.gaps
            ]
        return ValidationFuzz(
            as_of=filter.as_of,
            targets=tuple(sorted(targets, key=lambda t: (-t.crashers, t.repository, t.target))),
            crashers=tuple(
                sorted(
                    crashers,
                    key=lambda c: (
                        -(c.cvss if c.cvss is not None else -1.0),
                        list(ScannerSeverity).index(c.severity),
                        c.repository,
                        c.crasher,
                    ),
                )
            ),
            gaps=tuple(sorted(gaps, key=lambda g: (g.reason, g.repository, g.surface))),
            validation=tuple(
                sorted(
                    (
                        r.model_copy(update={"key": urls[UUID(r.key)]})  # type: ignore[arg-type]
                        for r in self._validation.summary(
                            ValidationFilter(repository_ids=frozenset(urls), as_of=filter.as_of),
                            ValidationDimension.REPOSITORY,
                        )
                    ),
                    key=lambda r: (
                        -r.by_verdict.get(_CONFIRMED, 0),
                        -r.findings,
                        r.key,
                    ),
                )
            ),
        )

    def report(self, model: ValidationFuzz, generated_at: datetime) -> Report:
        outcomes: Counter[str] = Counter()
        for t in model.targets:
            outcomes.update(t.outcomes)
        confirming = sum(c.confirms_finding_id is not None for c in model.crashers)
        verdicts: Counter[str] = Counter()
        for r in model.validation:
            verdicts.update(r.by_verdict)
        summary = (
            f"{len(model.targets)} targets across "
            f"{len({t.repository for t in model.targets})} repositories; "
            f"{sum(outcomes.values())} harnesses ran"
            + "".join(f", {n} {o}" for o, n in sorted(outcomes.items()))
            + f". {len(model.crashers)} crashers ({confirming} confirm a recorded finding), "
            f"{len(model.gaps)} surfaces left unfuzzed. A clean run is not evidence of "
            f"correctness. {sum(r.findings for r in model.validation)} findings validated live, "
            "by latest verdict: "
            + (", ".join(f"{n} {v}" for v, n in sorted(verdicts.items())) or "none")
            + "."
        )
        return Report(
            title="Validation and fuzz campaign",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _table_section(
                    "Crashers (CVSS, then proposed severity)",
                    (
                        "repository",
                        "target",
                        "harness",
                        "crasher",
                        "class",
                        "severity",
                        "CVSS",
                        "CWE",
                        "confirms",
                    ),
                    [
                        (
                            c.repository,
                            c.target,
                            c.harness,
                            f"{c.crasher}: {c.title}",
                            c.crash_class,
                            c.severity,
                            "-" if c.cvss is None else str(c.cvss),
                            ", ".join(c.cwes) or "-",
                            "-" if c.confirms_finding_id is None else str(c.confirms_finding_id),
                        )
                        for c in model.crashers
                    ],
                    "_No crashers recorded._",
                ),
                _table_section(
                    "Targets",
                    (
                        "repository",
                        "target",
                        "language",
                        "engines",
                        "harnesses by outcome",
                        "execs",
                        "crashers",
                        "line coverage",
                        "gaps",
                        "ran",
                    ),
                    [
                        (
                            t.repository,
                            t.target,
                            t.language,
                            ", ".join(t.engines),
                            ", ".join(f"{o} {n}" for o, n in sorted(t.outcomes.items())),
                            "-" if t.execs is None else str(t.execs),
                            str(t.crashers),
                            "not measured"
                            if t.lines_total is None
                            else f"{t.lines_covered}/{t.lines_total}",
                            str(t.gaps),
                            t.occurred_at.date().isoformat(),
                        )
                        for t in model.targets
                    ],
                    "_No fuzz runs recorded._",
                ),
                _table_section(
                    "Unfuzzed surfaces",
                    ("reason", "repository", "target", "surface", "harness", "note"),
                    [
                        (
                            g.reason,
                            g.repository,
                            g.target,
                            g.surface,
                            g.harness or "-",
                            g.note or "-",
                        )
                        for g in model.gaps
                    ],
                    "_No gaps recorded._",
                ),
                _table_section(
                    "Live validation (latest verdict per finding, most confirmed first)",
                    ("repository", "findings", *_VERDICTS),
                    [
                        (
                            r.key or "-",
                            str(r.findings),
                            *(str(r.by_verdict.get(v, 0)) for v in _VERDICTS),
                        )
                        for r in model.validation
                    ],
                    "_No validations recorded._",
                ),
            ),
        )


class PqcView:
    """PQC readiness (pqc dashboard, product reports): each named product's commits, else every
    commit, by readiness bucket and by dominant provenance."""

    name = ViewName.PQC

    def __init__(self, pqc: PqcService) -> None:
        self._pqc = pqc

    def build(self, filter: ViewFilter) -> PqcDashboard:
        if filter.team_ids:
            raise ValidationError("the pqc view scopes by product, not team")
        products: Sequence[UUID | None] = list(dict.fromkeys(filter.product_ids)) or [None]
        return PqcDashboard(
            scopes=tuple(
                PqcScope(
                    product_id=p,
                    by_bucket=tuple(
                        self._pqc.summary(PqcFilter(product_id=p), PqcDimension.BUCKET)
                    ),
                    by_provenance=tuple(
                        self._pqc.summary(PqcFilter(product_id=p), PqcDimension.PROVENANCE)
                    ),
                )
                for p in products
            )
        )

    def report(self, model: PqcDashboard, generated_at: datetime) -> Report:
        columns = ("key", "repositories", "mean overall", "2030 clock", "hndl priority", "blocked")
        sections = []
        for scope in model.scopes:
            label = "every commit" if scope.product_id is None else f"product {scope.product_id}"
            for heading, rollups in (
                ("by bucket", scope.by_bucket),
                ("by provenance", scope.by_provenance),
            ):
                sections.append(
                    _table_section(
                        f"Readiness {heading}, {label}",
                        columns,
                        [
                            (
                                r.key,
                                str(r.repositories),
                                str(r.mean_overall),
                                str(r.clock_2030),
                                str(r.hndl_priority),
                                str(r.blocked),
                            )
                            for r in rollups
                        ],
                        "_No readiness recorded._",
                    )
                )
        return Report(title="PQC readiness", generated_at=generated_at, sections=tuple(sections))


_BUCKET_LABELS = {
    "ready": "Ready",
    "partial": "Almost ready",
    "not-ready": "Needs work",
    "blocked-external": "Blocked on upstream",
    "not-applicable": "No crypto",
}
_PROVENANCE_LABELS = {
    "inherited-platform": "platform (cluster/OS)",
    "inherited-constrained": "constrained (pinned config)",
    "delegated-dependency": "upstream library",
    "native-first-party": "this repo's own code",
    "vendored": "vendored dependency",
    "externalized": "external service",
    "not-assessable-from-source": "can't tell from source",
    "none": "none detected",
}
_FIPS_LABELS = {
    "no-penalty": "OK: PQC works under FIPS",
    "blocked-by-provider-version": "Blocked: crypto library too old for PQC+FIPS",
    "fips-validation-gap": "Gap: PQC available but not FIPS-validated yet",
    "pqc-blocked-by-fips-mode": "Blocked: FIPS mode disables PQC entirely",
}
_PQCA_CAPABLE = 75


class PqcPortfolioView:
    """The PQC migration plan (pqc portfolio roll-up, per-product reports): ranked repositories,
    NIST clock items, harvest risk, group pins, Go quick wins and crypto packages, derived from
    each commit's latest readiness and facts."""

    name = ViewName.PQC_PORTFOLIO

    def __init__(
        self, pqc: PqcService, code_facts: CodeFactsService, portfolio: PortfolioService
    ) -> None:
        self._pqc = pqc
        self._code_facts = code_facts
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> PqcPortfolio:
        if filter.team_ids:
            raise ValidationError("the pqc-portfolio view scopes by product, not team")
        if filter.as_of is not None:
            raise ValidationError("the pqc-portfolio view reads readiness as it stands; no as_of")
        urls: dict[UUID, str] = {}

        def url(ref_id: UUID) -> str:
            if ref_id not in urls:
                urls[ref_id] = self._portfolio.inventory.subject(ref_id).repository_url
            return urls[ref_id]

        products: Sequence[UUID | None] = list(dict.fromkeys(filter.product_ids)) or [None]
        scopes = tuple(self._scope(p, url) for p in products)
        index = () if filter.product_ids else self._products(scopes[0].repositories)
        return PqcPortfolio(scopes=scopes, products=index)

    def _scope(self, product_id: UUID | None, url: Callable[[UUID], str]) -> PqcPortfolioScope:
        scope = PqcFilter(product_id=product_id)
        rows = sorted(
            (
                PqcRepositoryRow(repository_url=url(r.repository_ref_id), readiness=r)
                for r in self._pqc.list_readiness(scope)
            ),
            key=lambda row: (row.readiness.overall, row.repository_url),
        )
        sites = sorted(
            (
                PqcSiteRow(repository_url=url(s.repository_ref_id), site=s)
                for s in self._pqc.sites(scope)
            ),
            key=lambda row: (row.site.kind, row.repository_url, row.site.fact.fact_id),
        )
        using: dict[tuple[str, str | None], set[str]] = defaultdict(set)
        without_sbom = 0
        for row in rows:
            try:
                packages = self._code_facts.packages(row.readiness.repository_ref_id)
            except NoManifestSbomError:
                without_sbom += 1
                continue
            for f in packages:
                using[(f.package or f.provider or "", f.provider)].add(row.repository_url)
        return PqcPortfolioScope(
            product_id=product_id,
            repositories=tuple(rows),
            sites=tuple(sites),
            packages=tuple(
                PqcPackageUse(package=name, provider=provider, repositories=len(repos))
                for (name, provider), repos in sorted(
                    using.items(), key=lambda kv: (-len(kv[1]), kv[0][0])
                )
            ),
            without_sbom=without_sbom,
        )

    def _products(self, rows: Sequence[PqcRepositoryRow]) -> tuple[PqcProductRow, ...]:
        """Every product shipping an assessed commit, worst first (not-ready count, worst score)."""
        by_ref = {r.readiness.repository_ref_id: r for r in rows}
        index = []
        for product in every_item(self._portfolio.list_products):
            assert product.id is not None
            members = [
                by_ref[r.id]
                for r in self._portfolio.list_product_refs(product.id)
                if r.id in by_ref
            ]
            if not members:
                continue
            scored = [m for m in members if m.readiness.bucket != PqcReadinessBucket.NOT_APPLICABLE]
            worst = min(scored, key=lambda m: m.readiness.overall, default=None)
            index.append(
                PqcProductRow(
                    product=product.slug,
                    repositories=len(members),
                    not_ready=sum(
                        m.readiness.bucket == PqcReadinessBucket.NOT_READY for m in members
                    ),
                    hndl_priority=sum(m.readiness.hndl_priority for m in members),
                    clock_2030=sum(len(_clock_2030(m.readiness)) for m in members),
                    worst_url=None if worst is None else worst.repository_url,
                    worst_overall=None if worst is None else worst.readiness.overall,
                )
            )
        index.sort(
            key=lambda p: (-p.not_ready, 999 if p.worst_overall is None else p.worst_overall)
        )
        return tuple(index)

    def report(self, model: PqcPortfolio, generated_at: datetime) -> Report:
        sections = [s for scope in model.scopes for s in _pqc_scope_sections(scope)]
        if model.products:
            sections.append(
                _table_section(
                    f"Per-product roll-up ({len(model.products)} products with assessed repos)",
                    ("product", "repos", "not-ready", "hndl", "2030 clock", "worst repo"),
                    [
                        (
                            p.product,
                            str(p.repositories),
                            str(p.not_ready),
                            str(p.hndl_priority),
                            str(p.clock_2030),
                            "-" if p.worst_url is None else f"{p.worst_url} ({p.worst_overall:g})",
                        )
                        for p in model.products
                    ],
                    "",
                )
            )
        return Report(
            title="PQC portfolio roll-up", generated_at=generated_at, sections=tuple(sections)
        )


class PqcVendorsView:
    """The PQC vendor roadmap (pqc vendor tracker): the latest curated vendor claims worst first,
    each with the repositories holding its packages, and the blocked-external repositories."""

    name = ViewName.PQC_VENDORS

    def __init__(
        self, pqc: PqcService, exposure: ExposureService, portfolio: PortfolioService
    ) -> None:
        self._pqc = pqc
        self._exposure = exposure
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> PqcVendorRoadmap:
        _fleet_only(self.name, filter)
        if filter.as_of is not None:
            raise ValidationError("the pqc-vendors view reads the latest claims and manifests")
        claims = self._pqc.vendor_claims()
        _, _, repositories = _scope(self._portfolio, filter)
        held, unmeasured = _manifest_holders(self._exposure, self._portfolio, repositories)
        rows = sorted(
            (PqcVendorRow(claim=c, repositories=_vendor_holders(c, held)) for c in claims.vendors),
            key=lambda r: (
                _VENDOR_STATUS_ORDER[r.claim.status],
                -(r.repositories or 0),
                r.claim.id,
            ),
        )
        return PqcVendorRoadmap(
            claims_artifact_id=claims.artifact_id,
            version=claims.version,
            updated=claims.updated,
            vendors=tuple(rows),
            repositories=len(repositories),
            unmeasured=unmeasured,
            blocked_external=self._blocked_external({r.id: r.url for r in repositories if r.id}),
        )

    def _blocked_external(self, urls: dict[UUID, str]) -> tuple[str, ...]:
        """The repositories whose newest-assessed commit reads blocked-external."""
        repository_of = {
            r.id: r.repository_id for r in self._portfolio.inventory.list_refs_of(urls)
        }
        newest: dict[UUID, PqcReadiness] = {}
        for r in self._pqc.list_readiness(PqcFilter()):
            repository_id = repository_of[r.repository_ref_id]
            if repository_id not in newest or r.assessed_at > newest[repository_id].assessed_at:
                newest[repository_id] = r
        return tuple(
            sorted(
                urls[k]
                for k, r in newest.items()
                if r.bucket == PqcReadinessBucket.BLOCKED_EXTERNAL
            )
        )

    def report(self, model: PqcVendorRoadmap, generated_at: datetime) -> Report:
        measured = model.repositories - model.unmeasured
        summary = (
            f"Claims v{model.version} (updated {model.updated}): curated status claims dated per "
            "row; re-verify before external use. The delegated / blocked-external class: crypto "
            "the fleet cannot fix locally, sorted worst first. Fleet counts are the repositories "
            f"whose default-branch manifest SBOM holds a vendor's packages ({measured} of "
            f"{model.repositories} measured; the rest are not measured, not zero)."
        )
        rows = [r.claim for r in model.vendors]
        return Report(
            title="PQC vendor roadmap",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                _table_section(
                    "Vendors and dependencies",
                    (
                        "vendor / dependency",
                        "class",
                        "PQC status",
                        "fleet repos",
                        "watch signal",
                        "reviewed",
                    ),
                    [
                        (
                            r.claim.name,
                            r.claim.vendor_class,
                            _VENDOR_STATUS_LABELS[r.claim.status],
                            "-" if r.repositories is None else str(r.repositories),
                            r.claim.watch or "-",
                            r.claim.last_reviewed.isoformat(),
                        )
                        for r in model.vendors
                    ],
                    "",
                ),
                Section(heading="Status notes", body="\n".join(_claim_note(c) for c in rows)),
                Section(
                    heading=f"Blocked-external repos ({len(model.blocked_external)})",
                    body=", ".join(model.blocked_external) or "_None._",
                ),
            ),
        )


def _vendor_holders(claim: PqcVendorClaim, held: dict[tuple[str, str], set[UUID]]) -> int | None:
    """Repositories holding any of the claim's packages, by stored name (any ecosystem when the
    package names none); None when the claim names no package."""
    if not claim.packages:
        return None
    holders: set[UUID] = set()
    for (ecosystem, name), repos in held.items():
        eco = Ecosystem(ecosystem)
        if any(
            p.ecosystem in (None, eco) and package_name(eco, p.name) == name for p in claim.packages
        ):
            holders |= repos
    return len(holders)


def _claim_note(claim: PqcVendorClaim) -> str:
    sources = ", ".join(s.url for s in claim.sources)
    return f"- **{claim.name}**: {claim.claim} ({claim.reviewer}; {sources})"


_VENDOR_STATUS_ORDER = {
    PqcVendorStatus.NONE: 0,
    PqcVendorStatus.IN_PROGRESS: 1,
    PqcVendorStatus.PARTIAL: 2,
    PqcVendorStatus.AVAILABLE: 3,
}
_VENDOR_STATUS_LABELS = {
    PqcVendorStatus.NONE: "✗ none",
    PqcVendorStatus.IN_PROGRESS: "… in progress",
    PqcVendorStatus.PARTIAL: "◐ partial",
    PqcVendorStatus.AVAILABLE: "✓ available",
}


def _clock_2030(r: PqcReadiness) -> list[PqcClockItem]:
    return [c for c in r.clock_items if c.deprecated_after == 2030]


def _pqc_scope_sections(scope: PqcPortfolioScope) -> list[Section]:
    label = "every commit" if scope.product_id is None else f"product {scope.product_id}"
    rows = scope.repositories
    buckets = Counter(str(r.readiness.bucket or "unbucketed") for r in rows)
    clock = [
        (r.repository_url, c)
        for r in rows
        for c in sorted(
            _clock_2030(r.readiness), key=lambda c: c.remediation_effort != "significant"
        )
    ]
    later = sum(len(r.readiness.clock_items) for r in rows) - len(clock)
    efforts = Counter(
        str(c.remediation_effort or "?") for r in rows for c in r.readiness.clock_items
    )
    hndl = [r for r in rows if r.readiness.hndl_priority]
    fips = Counter(
        (r.readiness.fips_interaction, str(r.readiness.bucket))
        for r in rows
        if r.readiness.fips_interaction
    )
    control = Counter(
        (str(r.readiness.dominant), (r.readiness.pqca or 0) >= _PQCA_CAPABLE) for r in rows
    )
    pins = [s for s in scope.sites if s.site.kind == PqcSiteKind.GROUP_PIN]
    toolchains = [s for s in scope.sites if s.site.kind == PqcSiteKind.TOOLCHAIN]
    blocked = [
        r.repository_url for r in rows if r.readiness.bucket == PqcReadinessBucket.BLOCKED_EXTERNAL
    ]

    def where(s: PqcSiteRow) -> str:
        f = s.site.fact
        return f.file if f.line is None else f"{f.file}:{f.line}"

    summary = (
        f"{len(rows)} repositories assessed: "
        + ", ".join(f"{buckets[b]} {_BUCKET_LABELS.get(b, b).lower()}" for b in sorted(buckets))
        + f". {len(clock)} primitives across {len({u for u, _ in clock})} repositories are on the "
        f"NIST 2030 deprecation clock; {later} more are disallowed after 2035. {len(hndl)} "
        "repositories have harvest-now-decrypt-later exposure."
        if rows
        else "_No readiness recorded._"
    )
    return [
        Section(heading=f"PQC portfolio, {label}", body=summary),
        _table_section(
            "Repositories, worst first",
            ("repository", "status", "score", "hndl", "2030 clock", "who sets TLS"),
            [
                (
                    r.repository_url,
                    _BUCKET_LABELS.get(str(r.readiness.bucket), "-"),
                    f"{r.readiness.overall:g}",
                    "yes" if r.readiness.hndl_priority else "-",
                    str(len(_clock_2030(r.readiness))),
                    r.readiness.who_sets_tls or "-",
                )
                for r in rows
            ],
            "_No readiness recorded._",
        ),
        _table_section(
            "NIST 2030 deadline (stop using for new work)",
            ("repository", "primitive", "effort"),
            [(u, c.primitive[:200], str(c.remediation_effort or "?")) for u, c in clock],
            "_No 2030 clock items._",
        ),
        Section(
            heading="Effort to fix (all timeline items)",
            body=", ".join(f"{n} {e}" for e, n in sorted(efforts.items())) or "_None._",
        ),
        _table_section(
            "FIPS / PQC compatibility",
            ("FIPS status", "status", "repos"),
            [
                (_FIPS_LABELS.get(fi, fi), _BUCKET_LABELS.get(b, b), str(n))
                for (fi, b), n in sorted(fips.items())
            ],
            "_No FIPS-mode facts._",
        ),
        _table_section(
            f"Harvest risk, prioritize these ({len(hndl)} repos)",
            ("repository", "score", "status", "who controls the crypto"),
            [
                (
                    r.repository_url,
                    f"{r.readiness.overall:g}",
                    _BUCKET_LABELS.get(str(r.readiness.bucket), "-"),
                    _PROVENANCE_LABELS.get(str(r.readiness.dominant), str(r.readiness.dominant)),
                )
                for r in hndl
            ],
            "_No harvest-now-decrypt-later exposure._",
        ),
        _table_section(
            f"Config pins blocking PQC ({len(pins)} items)",
            ("repository", "rule", "location", "match"),
            [
                (s.repository_url, s.site.fact.rule_id, where(s), (s.site.fact.match or "")[:120])
                for s in pins
            ],
            "_No group pins._",
        ),
        _table_section(
            f"Quick wins: Go version bumps ({len(toolchains)} sites)",
            ("repository", "toolchain", "location"),
            [(s.repository_url, s.site.fact.detail, where(s)) for s in toolchains],
            "_No Go toolchain below the PQC default._",
        ),
        _table_section(
            "Who controls the crypto",
            ("who controls it", "PQC-capable already", "not yet PQC-capable"),
            [
                (_PROVENANCE_LABELS.get(p, p), str(control[(p, True)]), str(control[(p, False)]))
                for p in sorted({p for p, _ in control})
            ],
            "_No readiness recorded._",
        ),
        Section(
            heading=f"Blocked on upstream ({len(blocked)} repos)",
            body=", ".join(blocked) or "_None._",
        ),
        _table_section(
            "Crypto packages (manifest SBOMs)",
            ("package", "provider", "repos"),
            [(p.package, p.provider or "-", str(p.repositories)) for p in scope.packages],
            "_No crypto packages in the scope's manifest SBOMs._",
        ),
        *(
            [Section(heading="Without a manifest SBOM", body=f"{scope.without_sbom} repositories.")]
            if scope.without_sbom
            else []
        ),
    ]


class ComplianceDashboardView:
    """Compliance posture (compliance/dashboard.py) per framework and per boundary."""

    name = ViewName.COMPLIANCE

    def __init__(self, compliance: ComplianceService) -> None:
        self._compliance = compliance

    def build(self, filter: ViewFilter) -> ComplianceDashboard:
        _fleet_only(self.name, filter)
        every = ComplianceFilter()
        return ComplianceDashboard(
            by_framework=tuple(self._compliance.summary(every, ComplianceDimension.FRAMEWORK)),
            by_scope=tuple(self._compliance.summary(every, ComplianceDimension.SCOPE)),
        )

    def report(self, model: ComplianceDashboard, generated_at: datetime) -> Report:
        def rows(rollups: Sequence[ComplianceRollup]) -> list[tuple[str, ...]]:
            return [
                (
                    r.key,
                    str(r.pairs),
                    str(r.assessed),
                    "; ".join(
                        f"{fw}: " + ", ".join(f"{k} {n}" for k, n in sorted(c.items()))
                        for fw, c in sorted(r.coverage.items())
                    ),
                )
                for r in rollups
            ]

        columns = ("key", "declared", "assessed", "coverage")
        return Report(
            title="Compliance posture",
            generated_at=generated_at,
            sections=(
                _table_section(
                    "By framework", columns, rows(model.by_framework), "_No boundaries declared._"
                ),
                _table_section(
                    "By boundary", columns, rows(model.by_scope), "_No boundaries declared._"
                ),
            ),
        )


def _fleet_only(view: ViewName, filter: ViewFilter) -> None:
    if filter.product_ids or filter.team_ids:
        raise ValidationError(f"the {view.value} view is fleet-wide; it takes no product or team")


def _table_section(
    heading: str, columns: tuple[str, ...], rows: Sequence[tuple[str, ...]], empty: str
) -> Section:
    return Section(
        heading=heading,
        body="" if rows else empty,
        table=Table(columns=columns, rows=tuple(rows)) if rows else None,
    )


class ProgramView:
    """The program's spend and throughput over a window (traust-metrics, financial-tracking):
    derived from spend events and run orders, never a stored snapshot."""

    name = ViewName.PROGRAM

    def __init__(
        self, spend: SpendService, ops: OpsService, assets: Callable[[], Sequence[str]]
    ) -> None:
        self._spend = spend
        self._ops = ops
        self._assets = assets

    def build(self, filter: ViewFilter) -> ProgramMetrics:
        window = filter.window
        if window is None:
            raise ValidationError("the program view needs a window")
        spent = SpendFilter(window=window)
        return ProgramMetrics(
            window=window,
            bucket=filter.bucket,
            spend=self._spend.attribute(window),
            by_month=tuple(self._spend.summary(spent, SpendDimension.MONTH)),
            by_model=tuple(self._spend.summary(spent, SpendDimension.MODEL)),
            by_lane=tuple(self._spend.summary(spent, SpendDimension.LANE)),
            by_skill=tuple(self._spend.summary(spent, SpendDimension.SKILL)),
            throughput={
                a: tuple(
                    self._ops.timeline(
                        OrderFilter(asset=AssetName(a), window=window), filter.bucket
                    )
                )
                for a in sorted(self._assets())
            },
        )

    def report(self, model: ProgramMetrics, generated_at: datetime) -> Report:
        s = model.spend
        summary = (
            f"{model.window.start.date()} to {model.window.end.date()}: {_usd(s.total_usd)} "
            f"spent, {_usd(s.attributed_usd)} on run orders and {_usd(s.unattributed_usd)} no "
            "order claims "
            "(workstation sessions)."
        )
        sections = [Section(heading="Summary", body=summary)]
        for heading, rollups in (
            ("Spend by month", model.by_month),
            ("Spend by model", model.by_model),
            ("Spend by lane", model.by_lane),
            ("Spend by skill", model.by_skill),
        ):
            sections.append(
                _table_section(
                    heading,
                    ("key", "events", "tokens in", "tokens out", "cost usd"),
                    [
                        (
                            r.key or "-",
                            str(r.events),
                            str(r.tokens_in),
                            str(r.tokens_out),
                            _usd(r.cost_usd),
                        )
                        for r in rollups
                    ],
                    "_No spend._",
                )
            )
        throughput = [
            (asset, p.bucket.date().isoformat(), *(str(n) for n in p.finished.values()))
            for asset, points in model.throughput.items()
            for p in points
        ]
        sections.append(
            Section(
                heading="Throughput",
                body="Run orders finished per bucket, by outcome."
                + ("" if throughput else "\n\n_No assets registered._"),
                table=Table(
                    columns=("asset", "bucket", *FINISHED_ORDER_STATES), rows=tuple(throughput)
                )
                if throughput
                else None,
            )
        )
        return Report(title="Program metrics", generated_at=generated_at, sections=tuple(sections))


class ExecutiveSummaryView:
    """Leadership roll-up (executive-summary-findings): the scope's findings rollup as of
    `as_of`, credential leaks, risk themes, findings by primary language, least-privilege
    posture and, fleet-wide, dependency exposure."""

    name = ViewName.EXECUTIVE_SUMMARY

    def __init__(
        self,
        findings: FindingService,
        portfolio: PortfolioService,
        assessment: AssessmentService,
        code_facts: CodeFactsService,
        exposure: ExposureService,
    ) -> None:
        self._findings = findings
        self._portfolio = portfolio
        self._assessment = assessment
        self._code_facts = code_facts
        self._exposure = exposure

    def build(self, filter: ViewFilter) -> ExecutiveSummary:
        products, shipped, repositories, views = _scoped_findings(
            self._findings, self._portfolio, filter
        )
        urls = {r.id: r.url for r in repositories}
        opened = [v for found in views.values() for v in found if _is(v, _OPEN)]
        hardening = [v for found in views.values() for v in found if _is(v, _HARDENING)]
        by_language: defaultdict[str, list[UUID]] = defaultdict(list)
        for r in repositories:
            primary = _measured(self._code_facts, self._portfolio, r).primary
            by_language[primary or "unknown"].append(r.id)  # type: ignore[arg-type]
        profiles = self._assessment.privileges(AssessmentFilter(), list(urls), filter.as_of)
        fleet = not (filter.product_ids or filter.team_ids)
        return ExecutiveSummary(
            rollup=_rollup(filter.as_of, products, shipped, repositories, views),
            credential_leaks=tuple(
                sorted(
                    (_top(v, urls[v.finding.repository_id]) for v in opened if _credential(v)),
                    key=lambda t: (_severity_rank(t.severity), t.repository_url, t.title),
                )
            ),
            themes=_themes(opened),
            hardening_themes=_themes(hardening),
            languages=tuple(
                sorted(
                    (
                        LanguageSeverity(
                            language=language,
                            repositories=len(ids),
                            open=_tally(v for r in ids for v in views[r]).open,
                        )
                        for language, ids in by_language.items()
                    ),
                    key=lambda row: (-row.open.total, row.language),
                )
            ),
            privileges=LeastPrivilege(
                profiles=len(profiles),
                privileged=sum(bool(p.privileged_workloads) for p in profiles),
                scc_requesting=sum(bool(p.scc_requests) for p in profiles),
                wildcard_repositories=sum(bool(p.wildcard_rules) for p in profiles),
                wildcard_rules=sum(p.wildcard_rules or 0 for p in profiles),
                flags=dict(sum((Counter(p.flags) for p in profiles), Counter()).most_common()),
            ),
            exposure=tuple(
                self._exposure.summary(
                    ExposureFilter(as_of=filter.as_of), ExposureDimension.ADVISORY
                )[:_TOP_N]
            )
            if fleet
            else None,
        )

    def report(self, model: ExecutiveSummary, generated_at: datetime) -> Report:
        rollup = model.rollup
        t = rollup.total
        with_critical = sum(r.tally.open.critical > 0 for r in rollup.repositories)
        summary = (
            f"{len(rollup.repositories)} repositories: {t.open.total} open findings "
            f"({_severities(t.open)}); {with_critical} repositories with at least one critical. "
            f"{len(model.credential_leaks)} open credential or secret leaks. "
            f"Not counted as open: {t.false_positive} false positives, {t.resolved} resolved, "
            f"{t.risk_accepted} risk accepted, {t.hardening} hardening."
        )
        if rollup.as_of is not None:
            summary += f"\n\nAs of {rollup.as_of.isoformat()}."
        p = model.privileges
        privileges = (
            f"{p.profiles} operator privilege profiles (posture, not findings: they stay out of "
            f"the finding counts): {p.privileged} run privileged or host-touching workloads, "
            f"{p.scc_requesting} request SCCs, {p.wildcard_repositories} carry wildcard RBAC rules "
            f"({p.wildcard_rules} rules)."
        )
        unrated = bool(t.open.unrated)
        severity_columns = (
            "critical",
            "high",
            "medium",
            "low",
            "info",
            *(("unrated",) if unrated else ()),
            "total",
        )
        tallies = [r.tally for r in rollup.repositories]
        ledgered = [r for r in tallies if r.decided]
        tracked = sum(r.tracked for r in ledgered)
        closed = sum(r.resolved + r.risk_accepted for r in ledgered)
        remediation = (
            f"{len(ledgered)} of {len(tallies)} repositories have a decision recorded. Across "
            f"their {tracked} findings (false positives excluded): {closed} closed (resolved or "
            "risk accepted)"
            + (f", a closure rate of {100 * closed / tracked:.1f}%." if tracked else ".")
            + f" Findings remediated: {t.remediated.total} resolved ({_severities(t.remediated)})."
            " The trend over time is the findings-trend view."
        )
        backlog = sorted(
            (r for r in rollup.repositories if r.tally.hardening),
            key=lambda r: (-r.tally.hardening, r.repository_url),
        )
        sections = [
            Section(heading="Summary", body=summary),
            _population(
                len(tallies),
                sum(map(_reported, tallies)),
                len(ledgered),
                "findings, each counted once; false positives, resolved, risk accepted and "
                "hardening counted apart from open",
            ),
            Section(heading="Remediation status", body=remediation),
            _table_section(
                "Critical and high findings",
                ("repository", "finding", "severity", "cvss", "proven", "sla due"),
                [_top_row(f) for f in rollup.top[:_TOP_N]],
                "_None open._",
            ),
            _table_section(
                "Credential and secret leaks",
                ("repository", "finding", "severity", "cvss", "proven", "sla due"),
                [_top_row(f) for f in model.credential_leaks],
                "_None open._",
            ),
            _table_section(
                "Risk themes",
                ("theme", "open findings"),
                [(k, str(n)) for k, n in model.themes.items()],
                "_None open._",
            ),
            _table_section(
                "By primary language",
                ("language", "repositories", *severity_columns),
                [
                    (r.language, str(r.repositories), *_counts(r.open, unrated=unrated))
                    for r in model.languages
                ],
                "_No repositories in scope._",
            ),
            Section(
                heading="Hardening backlog (posture debt)",
                body=f"{t.hardening} defense-in-depth and benchmark gaps with no demonstrated "
                "exploit path, excluded from the severity totals but never dropped: absent "
                "hardening amplifies co-located vulnerabilities."
                + ("" if model.hardening_themes else "\n\n_None._"),
                table=Table(
                    columns=("theme", "hardening"),
                    rows=tuple((k, str(n)) for k, n in model.hardening_themes.items()),
                )
                if model.hardening_themes
                else None,
            ),
            _table_section(
                f"Largest hardening backlogs (top {_TOP_N} of {len(backlog)})",
                ("repository", "hardening", "categories"),
                [
                    (
                        r.repository_url,
                        str(r.tally.hardening),
                        ", ".join(f"{c} {n}" for c, n in r.hardening_categories.items()),
                    )
                    for r in backlog[:_TOP_N]
                ],
                "_None._",
            ),
            Section(
                heading="Least privilege",
                body=privileges,
                table=Table(
                    columns=("rbac risk flag", "matches"),
                    rows=tuple((k, str(n)) for k, n in p.flags.items()),
                )
                if p.flags
                else None,
            ),
            Section(
                heading="Dependency exposure (fleet-wide)",
                body="_Fleet-wide only: not shown for a product or team scope._"
                if model.exposure is None
                else ("" if model.exposure else "_No impact analyses recorded._"),
                table=Table(
                    columns=("advisory", "commits", "exposed", "affected"),
                    rows=tuple(
                        (r.key or "-", str(r.commits), str(r.exposed), str(r.affected))
                        for r in model.exposure
                    ),
                )
                if model.exposure
                else None,
            ),
        ]
        return Report(
            title="Executive summary: findings", generated_at=generated_at, sections=tuple(sections)
        )


_TOP_N = 10
# CWEs and title patterns that mark a secret or credential committed to or surfaced by code.
_CREDENTIAL_LEAK_CWES = frozenset(
    {"CWE-798", "CWE-259", "CWE-321", "CWE-547", "CWE-256", "CWE-312", "CWE-313", "CWE-522",
     "CWE-540", "CWE-260", "CWE-1392"}
)  # fmt: skip
_CREDENTIAL_TITLE = re.compile(
    r"(hard.?cod|default (?:cred|password)|committed (?:secret|cred|key|token)"
    r"|secret in |private key|api[- ]?key|access[- ]?token in"
    r"|credential leak|leaked (?:secret|token|cred)|\.env|kubeconfig committed"
    r"|password in (?:source|repo|code|config))",
    re.I,
)
_THEMES = {
    cwe: theme
    for theme, cwes in {
        "Command / Code Injection": ("CWE-77", "CWE-78", "CWE-94", "CWE-1336"),
        "SQL / Query Injection": ("CWE-89", "CWE-943"),
        "Path Traversal & Arbitrary File Access": ("CWE-22", "CWE-23", "CWE-59", "CWE-73"),
        "Hard-coded / Leaked Secrets": ("CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-540",
                                        "CWE-256", "CWE-312", "CWE-1392"),
        "Weak / Broken Cryptography": ("CWE-327", "CWE-326", "CWE-338", "CWE-330"),
        "Broken Authentication": ("CWE-287", "CWE-306"),
        "Missing / Broken Authorization": ("CWE-862", "CWE-863", "CWE-269", "CWE-284", "CWE-639"),
        "SSRF": ("CWE-918",),
        "Insecure Deserialization": ("CWE-502", "CWE-915"),
        "TLS / Certificate Validation": ("CWE-295", "CWE-319", "CWE-297"),
        "Excessive Privilege / RBAC": ("CWE-250", "CWE-266"),
        "Insecure File / Resource Permissions": ("CWE-732",),
        "Supply-Chain / CI-CD Hardening": ("CWE-1357", "CWE-494", "CWE-829", "CWE-1104"),
        "Cross-Site Scripting": ("CWE-79",),
        "CSRF": ("CWE-352",),
        "Sensitive Information Disclosure": ("CWE-200", "CWE-209"),
        "Sensitive Data in Logs": ("CWE-532",),
        "Resource Exhaustion / DoS": ("CWE-400", "CWE-770", "CWE-1333"),
    }.items()
    for cwe in cwes
}  # fmt: skip


def _reported(tally: FindingTally) -> bool:
    return bool(tally.tracked or tally.false_positive)


def _credential(view: FindingView) -> bool:
    return bool(_CREDENTIAL_LEAK_CWES & set(view.cwes)) or bool(
        _CREDENTIAL_TITLE.search(view.finding.title)
    )


def _themes(views: Iterable[FindingView]) -> dict[str, int]:
    """Findings per risk theme, largest first; a finding counts once in each theme its CWEs
    map to, and under Other when none do."""
    counts = Counter(
        theme
        for v in views
        for theme in ({_THEMES[c] for c in v.cwes if c in _THEMES} or {"Other"})
    )
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _top_row(f: TopFinding) -> tuple[str, ...]:
    return (
        f.repository_url,
        f.title,
        "-" if f.severity is None else str(f.severity),
        "-" if f.cvss_score is None else str(f.cvss_score),
        "yes" if f.execution_proven else "",
        "-" if f.sla_due is None else f.sla_due.date().isoformat(),
    )


class PrivilegesView:
    """Operator least privilege (operator-priv-profile's fleet rollup): each repository's latest
    priv-profile as of `as_of`, ranked by tier-2 surplus, wildcard rules, privileged workloads."""

    name = ViewName.PRIVILEGES

    def __init__(self, assessment: AssessmentService, portfolio: PortfolioService) -> None:
        self._assessment = assessment
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> PrivilegesRollup:
        _, _, repositories = _scope(self._portfolio, filter)
        urls: dict[UUID, str] = {r.id: r.url for r in repositories}  # type: ignore[misc]
        profiles = self._assessment.privileges(AssessmentFilter(), list(urls), filter.as_of)
        rows = (
            PrivilegeRow(
                repository=urls[p.repository_id],
                **p.model_dump(exclude={"permissions", "tenancy", "repository_id"}),
            )
            for p in profiles
        )
        return PrivilegesRollup(
            as_of=filter.as_of,
            rows=tuple(
                sorted(
                    rows,
                    key=lambda r: (
                        -(r.surplus or 0),
                        -(r.wildcard_rules or 0),
                        -(r.privileged_workloads or 0),
                        r.repository,
                    ),
                )
            ),
        )

    def report(self, model: PrivilegesRollup, generated_at: datetime) -> Report:
        rows = model.rows
        requesting = sum(bool(r.scc_requests) for r in rows)
        kpis = (
            f"{len(rows)} operators profiled: {requesting} request explicit SCCs, "
            f"{len(rows) - requesting} expect the restricted-v2 default, "
            f"{sum(bool(r.privileged_containers or r.privileged_workloads) for r in rows)} run "
            f"privileged or host-touching workloads, {sum(bool(r.surplus) for r in rows)} carry "
            "tier-2 RBAC surplus."
        )
        return Report(
            title="Operator least-privilege rollup",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=kpis),
                Section(heading="How to read this", body=_HOW_TO_READ_PRIVILEGES),
                _table_section(
                    "Assessment",
                    (
                        "Repo",
                        "SCCs requested",
                        "Security context",
                        "Namespaces / install modes",
                        "Required roles (RBAC)",
                    ),
                    [
                        (
                            r.repository,
                            _scc(r),
                            _security_context(r),
                            " · ".join(x for x in (_namespaces(r), ", ".join(r.install_modes)) if x)
                            or "—",
                            _rbac(r),
                        )
                        for r in rows
                    ],
                    "_No priv-profiles recorded._",
                ),
            ),
        )

    def export(self, model: PrivilegesRollup) -> Table:
        """The rollup as a spreadsheet: one row per repository, one column per question."""
        return Table(
            columns=_PRIVILEGE_COLUMNS,
            rows=tuple(
                tuple(
                    "" if v is None else str(v)
                    for v in (
                        r.repository,
                        ";".join(sorted(set(r.scc_requests))),
                        r.privileged_containers,
                        r.privileged_workloads,
                        r.run_as_non_root_containers,
                        r.containers,
                        ";".join(r.namespaces),
                        ";".join(r.install_modes),
                        r.distinct_cluster_triples,
                        r.distinct_rule_triples,
                        r.wildcard_rules,
                        ";".join(f"{k}={n}" for k, n in sorted(r.flags.items())),
                        "n/a" if r.surplus is None else r.surplus,
                        r.kubebuilder_markers,
                    )
                )
                for r in model.rows
            ),
        )


_SHOWN_NAMESPACES = 3
_PRIVILEGE_COLUMNS = (
    "repo", "sccs_requested", "privileged_containers", "host_touching_workloads",
    "runasnonroot_containers", "containers_total", "namespaces", "install_modes",
    "cluster_grants", "total_grants", "wildcard_rules", "rbac_risk_flags",
    "tier2_surplus", "kubebuilder_markers",
)  # fmt: skip
_HOW_TO_READ_PRIVILEGES = (
    "Static tiers 1-2, one row per operator. The SCC column is what the operator REQUESTS (RBAC "
    "`use` on securitycontextconstraints); the SCC it runs with is cluster-assigned, a tier-3 "
    "runtime capture. No SCC request means OpenShift assigns restricted-v2. Surplus is shipped "
    "RBAC with no +kubebuilder:rbac marker backing it (verify non-kubebuilder call sites before "
    "filing); n/a means no markers, so no baseline is statically derivable."
)


def _scc(r: PrivilegeRow) -> str:
    return ", ".join(sorted(set(r.scc_requests))) or "(none — restricted-v2 default)"


def _security_context(r: PrivilegeRow) -> str:
    bits = [f"{r.privileged_containers} privileged"] if r.privileged_containers else []
    if r.privileged_workloads:
        bits.append(f"{r.privileged_workloads} host-touching wl")
    if r.containers is None:
        return ", ".join([*bits, "no workloads listed"])
    return ", ".join([*bits, f"runAsNonRoot {r.run_as_non_root_containers}/{r.containers}"])


def _rbac(r: PrivilegeRow) -> str:
    parts = [f"{r.distinct_cluster_triples} cluster / {r.distinct_rule_triples} total grants"]
    if (
        risk := ", ".join(
            f"{k}×{n}"  # noqa: RUF001
            for k, n in sorted(r.flags.items(), key=lambda kv: -kv[1])[:3]
        )
    ):
        parts.append(risk)
    if r.surplus:
        parts.append(f"surplus {r.surplus}")
    return "; ".join(parts)


def _namespaces(r: PrivilegeRow) -> str:
    shown = r.namespaces[:_SHOWN_NAMESPACES]
    return ", ".join(shown) + ("…" if len(r.namespaces) > _SHOWN_NAMESPACES else "")


class ScoreboardView:
    """The leadership scoreboard (traust-metrics): headline numbers read off the executive
    summary, findings trend and threat register views as of `as_of`; it authors none."""

    name = ViewName.SCOREBOARD

    def __init__(
        self,
        executive: ExecutiveSummaryView,
        trend: FindingsTrendView,
        threats: ThreatRegisterView,
        findings: FindingService,
        clock: Clock,
    ) -> None:
        self._executive = executive
        self._trend = trend
        self._threats = threats
        self._findings = findings
        self._clock = clock

    def build(self, filter: ViewFilter) -> Scoreboard:
        at = filter.model_copy(update={"as_of": filter.as_of or self._clock.now()})
        summary = self._executive.build(at)
        trend = self._trend.build(at)
        register = self._threats.build(at)
        rollup, t = summary.rollup, summary.rollup.total
        return Scoreboard(
            as_of=at.as_of,
            repositories=len(rollup.repositories),
            reported=sum(_reported(r.tally) for r in rollup.repositories),
            dispositioned=sum(bool(r.tally.decided) for r in rollup.repositories),
            open=t.open,
            repositories_with_critical=sum(r.tally.open.critical > 0 for r in rollup.repositories),
            repositories_with_high=sum(r.tally.open.high > 0 for r in rollup.repositories),
            credential_leaks=len(summary.credential_leaks),
            resolved=t.resolved,
            risk_accepted=t.risk_accepted,
            false_positives=t.false_positive,
            hardening=t.hardening,
            execution_proven=t.execution_proven,
            themes=dict(list(summary.themes.items())[:3]),
            trend=trend.points[-1] if trend.points else None,
            threat_models=register.models,
            threats=len(register.threats),
            open_threats=sum(r.threat.status in _OPEN_THREATS for r in register.threats),
            filed=sum(
                c.filed_at is not None
                for r in rollup.repositories
                for c in self._findings.clocks(
                    FindingFilter(repository_id=r.repository_id, as_of=at.as_of)
                )
            ),
        )

    def report(self, model: Scoreboard, generated_at: datetime) -> Report:
        p, o = model.trend, model.open
        mean = "-" if p is None or not o.total else round(p.risk_index / o.total, 2)
        mttr = "-" if p is None or p.mttr_days is None else p.mttr_days
        rows = {
            "Scale and coverage": [
                ("Repositories in scope", model.repositories),
                ("With findings reported", model.reported),
                ("With a decision recorded (ledger coverage)", model.dispositioned),
                ("Ledger coverage, latest bucket (%)", "-" if p is None else p.coverage),
                ("Threat models", model.threat_models),
            ],
            "Findings and impact": [
                ("Open findings", o.total),
                ("Open critical / high", f"{o.critical} / {o.high}"),
                ("Repositories with an open critical", model.repositories_with_critical),
                ("Repositories with an open high", model.repositories_with_high),
                ("Credential or secret leaks open", model.credential_leaks),
                ("Risk index (CVSS sum of open)", "-" if p is None else p.risk_index),
                ("Mean CVSS of open", mean),
                ("Hardening backlog", model.hardening),
                ("Risk accepted", model.risk_accepted),
                ("Threats / open", f"{model.threats} / {model.open_threats}"),
                ("Top risk themes", ", ".join(f"{k} {n}" for k, n in model.themes.items()) or "-"),
            ],
            "Empirical validation": [
                ("Execution-proven open findings", model.execution_proven),
                ("Confirmed false positives", model.false_positives),
            ],
            "Delivery and adoption": [
                ("Findings resolved", model.resolved),
                ("Findings filed in Jira", model.filed),
                ("Remediation velocity, latest bucket", "-" if p is None else p.resolved),
                ("MTTR, latest bucket (days)", mttr),
            ],
        }
        return Report(
            title="Traust metrics",
            generated_at=generated_at,
            sections=(
                Section(
                    heading="About",
                    body=f"As of {model.as_of.isoformat()}, from the executive-summary, "
                    "findings-trend and threat-register views over traust-core's recorded state "
                    f"(traust-core {core_version()}); every number is derived, none authored. "
                    "Validation and fuzz campaign figures wait on the validation-fuzz view.",
                ),
                *(
                    Section(
                        heading=heading,
                        table=Table(
                            columns=("metric", "value"),
                            rows=tuple((m, str(v)) for m, v in metrics),
                        ),
                    )
                    for heading, metrics in rows.items()
                ),
            ),
        )


class CensusView:
    """The corpus census: per corpus ownership class (the registry's, per product, as of
    `as_of`), the secure-code work done and the distinct vulnerabilities over the scope."""

    name = ViewName.CENSUS

    def __init__(
        self,
        findings: FindingService,
        assessment: AssessmentService,
        portfolio: PortfolioService,
        clock: Clock,
    ) -> None:
        self._findings = findings
        self._assessment = assessment
        self._portfolio = portfolio
        self._clock = clock

    def build(self, filter: ViewFilter) -> Census:
        as_of = filter.as_of or self._clock.now()
        named, _, repositories = _scope(self._portfolio, filter)
        in_scope = {r.id for r in repositories}
        doc = self._portfolio.corpus_registry(filter.as_of)
        registry = CorpusRegistry() if doc is None else CorpusRegistry.of(doc)
        products = named or list(every_item(self._portfolio.list_products))
        shipped = {
            p.id: {r.repository_id for r in self._portfolio.list_product_refs(p.id)} & in_scope  # type: ignore[arg-type]
            for p in products
        }
        listed = [
            CensusProduct(
                product_id=p.id,  # type: ignore[arg-type]
                slug=p.slug,
                name=p.name,
                ownership=s.ownership if (s := registry.subject(str(p.id))) else None,
                business_unit=s.business_unit if s else None,
                repositories=len(shipped[p.id]),
            )
            for p in sorted(products, key=lambda p: p.slug)
            if not filter.team_ids or shipped[p.id]
        ]
        classes: defaultdict[UUID, set[OwnershipClass]] = defaultdict(set)
        for p in listed:
            for r in shipped[p.product_id] if p.ownership else ():
                classes[r].add(p.ownership)  # type: ignore[arg-type]
        population = self._assessment.population(as_of, AssessmentFilter(), list(in_scope))  # type: ignore[arg-type]
        audits = {row.repository_id: row for row in population.rows if row.kind == _CENSUS_AUDIT}
        line = default_line(self._portfolio.inventory.list_refs_of(in_scope))  # type: ignore[arg-type]
        cuts: defaultdict[OwnershipClass | None, Counter[str]] = defaultdict(Counter)
        layers: Counter[str] = Counter()
        reported = dispositioned = 0
        for r in repositories:
            views = self._findings.all(FindingFilter(repository_id=r.id, as_of=filter.as_of))  # type: ignore[arg-type]
            tally = _tally(views)
            reported += _reported(tally)
            dispositioned += bool(tally.decided)
            counted = self._counted(r.id, views, as_of, line, layers)  # type: ignore[arg-type]
            row = audits.get(r.id)  # type: ignore[arg-type]
            if row is not None:
                counted.update(
                    audited=row.default_line > 0,
                    audits=row.default_line,
                    branch_audits=row.branches,
                )
            for ownership in classes.get(r.id) or {None}:  # type: ignore[arg-type]
                cuts[ownership] += counted
        return Census(
            as_of=as_of,
            repositories=len(repositories),
            reported=reported,
            dispositioned=dispositioned,
            never_assessed=len(population.never_assessed_repository_ids),
            cuts=tuple(
                _census_cut(o, cuts[o], sum(p.ownership == o for p in listed))
                for o in (*OwnershipClass, None)
                if o in cuts or any(p.ownership == o for p in listed)
            ),
            products=tuple(listed),
            cloud_config=_census_layer(layers, AssessmentKind.CLOUD_CONFIG_CANONICAL),
            container=_census_layer(layers, AssessmentKind.CONTAINER),
            unregistered=tuple(r.url for r in repositories if r.id not in classes),
        )

    def _counted(
        self,
        repository_id: UUID,
        views: list[FindingView],
        as_of: datetime,
        line: set[UUID],
        layers: Counter[str],
    ) -> Counter[str]:
        """The repository's census counts; findings only a declared-IaC or container
        assessment reported go to `layers`, keyed by that kind."""
        held = {
            a.id: a
            for a in self._assessment.list_for_repository(repository_id)
            if a.occurred_at <= as_of
        }
        seen: defaultdict[UUID, list[Occurrence]] = defaultdict(list)
        ids = [v.finding.id for v in views]
        for o in self._findings.occurrences(finding_ids=ids) if ids else ():  # type: ignore[arg-type]
            if o.assessment_id in held:
                seen[o.finding_id].append(o)
        counted: Counter[str] = Counter(repositories=1)
        for v in views:
            found = [held[o.assessment_id] for o in seen[v.finding.id]]  # type: ignore[index]
            kinds = {a.kind for a in found}
            state, severity = v.state(), str(v.effective_severity)
            layer = next((k for k in _CENSUS_LAYERS if kinds == {k}), None)
            if layer is not None:
                layers[f"{layer}.{'fp' if state is _FALSE_POSITIVE else severity}"] += 1
                continue
            head = sum(a.repository_ref_id in line for a in found)
            if not found or (not head and state in _NOT_VULNERABILITY):
                continue
            if not head:
                counted["branch_only"] += 1
            elif state is _FALSE_POSITIVE:
                counted["false_positives"] += 1
            elif state is _HARDENING:
                counted["hardening"] += 1
            else:
                counted.update(
                    {
                        f"distinct.{severity}": 1,
                        f"open.{severity}": state is _OPEN,
                        "occurrences": head,
                        "dispositioned": v.disposition is not None,
                        "branch_confirmed": head < len(found),
                    }
                )
        return counted

    def report(self, model: Census, generated_at: datetime) -> Report:
        by = {c.ownership: c for c in model.cuts}
        owned, upstream, external = (by.get(o, CensusCut()) for o in _HEADLINE)
        summary = (
            f"As of {model.as_of.isoformat()}: **{owned.distinct.total} distinct owned "
            f"vulnerabilities**, {owned.open.total} open ({_severities(owned.open)}); "
            f"all distinct: {_severities(owned.distinct)}. {owned.hardening} distinct hardening "
            f"gaps, reported apart.\n\nUpstream, adjacent and never folded in: "
            f"{upstream.distinct.total} distinct, {upstream.open.total} open "
            f"({_severities(upstream.open)}).\n\nExternal business units, work performed only: "
            f"{external.audits} secure-code audits over {external.repositories} repositories."
        )
        cuts = [
            (
                str(c.ownership or "no registered ownership"),
                str(c.products),
                str(c.repositories),
                str(c.audits),
                str(c.distinct.total),
                str(c.open.total),
                *_counts(c.open)[:5],
                str(c.hardening),
                str(c.false_positives),
                str(c.occurrences),
            )
            for c in model.cuts
        ]
        branch = [
            (
                str(c.ownership or "no registered ownership"),
                str(c.branch_audits),
                str(c.branch_confirmed),
                str(c.branch_only),
            )
            for c in model.cuts
            if c.branch_audits or c.branch_only
        ]
        layers = [
            (
                name,
                str(layer.findings.total),
                *_counts(layer.findings)[:5],
                str(layer.false_positives),
            )
            for name, layer in (
                ("cloud-config (declared IaC)", model.cloud_config),
                ("container images", model.container),
            )
        ]
        return Report(
            title="Census",
            generated_at=generated_at,
            sections=(
                Section(heading="Executive view", body=summary),
                _table_section(
                    "Ownership cuts",
                    (
                        "ownership",
                        "products",
                        "repositories",
                        "audits",
                        "distinct",
                        "open",
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "info",
                        "hardening",
                        "false positives",
                        "occurrences",
                    ),
                    cuts,
                    "_No repositories in scope._",
                ),
                _table_section(
                    "By product",
                    ("product", "ownership", "business unit", "repositories"),
                    [
                        (
                            p.slug,
                            str(p.ownership or "-"),
                            p.business_unit or "-",
                            str(p.repositories),
                        )
                        for p in model.products
                    ],
                    "_No products registered._",
                ),
                Section(
                    heading="Duplication",
                    body="Each finding counts once however many assessments, layers or commits "
                    "reported it: `occurrences` against `distinct` is the restatement folded "
                    "away. Branch re-audit confirmations are coverage evidence, not new exposure."
                    + ("" if branch else "\n\n_No branch re-audits._"),
                    table=Table(
                        columns=(
                            "ownership",
                            "branch audits",
                            "confirmed on a branch",
                            "branch only",
                        ),
                        rows=tuple(branch),
                    )
                    if branch
                    else None,
                ),
                Section(
                    heading="Outside the headline",
                    body="Declared-IaC and container-image findings are a different unit: "
                    "counted here, never folded into the distinct vulnerabilities.",
                    table=Table(
                        columns=(
                            "unit",
                            "findings",
                            "critical",
                            "high",
                            "medium",
                            "low",
                            "info",
                            "false positives",
                        ),
                        rows=tuple(layers),
                    ),
                ),
                _table_section(
                    "Not in the registry",
                    ("repository",),
                    [(url,) for url in model.unregistered],
                    "_Every repository in scope ships in a product with a registered ownership._",
                ),
                _population(
                    model.repositories,
                    model.reported,
                    model.dispositioned,
                    "distinct vulnerabilities = findings on the default line, false positives "
                    "dropped, hardening apart; a repository several ownership classes ship counts "
                    f"under each; {model.never_assessed} repositories never assessed",
                ),
            ),
        )


_CENSUS_AUDIT = AssessmentKind.SECURE_CODE_CANONICAL
_CENSUS_LAYERS = (AssessmentKind.CLOUD_CONFIG_CANONICAL, AssessmentKind.CONTAINER)
_HEADLINE = (OwnershipClass.OWNED, OwnershipClass.UPSTREAM, OwnershipClass.EXTERNAL_BU)
_FALSE_POSITIVE = FindingState.FALSE_POSITIVE
_NOT_VULNERABILITY = (FindingState.FALSE_POSITIVE, FindingState.HARDENING)
_CUT_COUNTS = (
    "repositories", "audited", "audits", "branch_audits", "occurrences", "hardening",
    "false_positives", "dispositioned", "branch_confirmed", "branch_only",
)  # fmt: skip


def _census_cut(
    ownership: OwnershipClass | None, counted: Counter[str], products: int
) -> CensusCut:
    return CensusCut(
        ownership=ownership,
        products=products,
        distinct=_by_severity(counted, "distinct"),
        open=_by_severity(counted, "open"),
        **{k: counted[k] for k in _CUT_COUNTS},
    )


def _census_layer(layers: Counter[str], kind: AssessmentKind) -> CensusLayer:
    return CensusLayer(findings=_by_severity(layers, kind), false_positives=layers[f"{kind}.fp"])


def _by_severity(counted: Counter[str], prefix: str) -> SeverityCounts:
    return SeverityCounts(**{str(s): counted[f"{prefix}.{s}"] for s in Severity})


class ReviewCardView:
    """The countersign queue (countersign render_*_card): each case waiting on a person in
    scope, oldest first, as a card with a decision form."""

    name = ViewName.REVIEW_CARD

    def __init__(self, findings: FindingService, portfolio: PortfolioService) -> None:
        self._findings = findings
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> ReviewCards:
        if filter.as_of is not None:
            raise ValidationError("the review card view reads the queue now; it takes no as_of")
        scoped = filter.product_ids or filter.team_ids
        wanted = {r.id for r in _scope(self._portfolio, filter)[2]} if scoped else None
        review = self._findings.review
        cases = [
            c
            for c in every_item(lambda page: review.queue(ReviewFilter(), page))
            if wanted is None or c.repository_id in wanted
        ]
        views = {v.finding.id: v for v in self._findings.list_by_ids({c.finding_id for c in cases})}
        return ReviewCards(
            cards=tuple(
                ReviewCard(
                    case=c,
                    finding=views[c.finding_id],
                    refutation=None
                    if c.kind == ReviewCaseKind.NEEDS_REVIEW
                    else next(
                        (
                            d
                            for d in reversed(self._findings.history(c.finding_id))
                            if d.validity == Validity.FALSE_POSITIVE
                        ),
                        None,
                    ),
                )
                for c in cases
            )
        )

    def report(self, model: ReviewCards, generated_at: datetime) -> Report:
        groups = {
            kind: [c for c in model.cards if c.case.kind in kinds]
            for kind, kinds in _CARD_GROUPS.items()
        }
        summary = (
            f"{len(groups['signoff'])} awaiting human sign-off, {len(groups['review'])} "
            f"needs-review item(s), {len(groups['attention'])} attention item(s) (overrides / "
            "second-signer / conflicts).\n\nMark ONE box per card ([x]) and add a rationale "
            "where required. Signing records a false positive attributed to you; `keep_open` "
            "records a human `confirmed` (your rationale required); `defer` leaves it pending. "
            "Every decision remains overridable by execution evidence."
        )
        sections = [Section(heading="Summary", body=summary)]
        for key, heading in (
            ("signoff", "Awaiting sign-off"),
            ("attention", "Attention: overrides, second-signer requests, conflicts"),
            ("review", "Needs review (resolve interactively)"),
        ):
            cards = groups[key]
            sections.append(
                Section(
                    heading=heading,
                    body="\n\n".join(_card(c, i, len(cards)) for i, c in enumerate(cards, 1))
                    or "_None._",
                )
            )
        return Report(
            title="Countersign queue", generated_at=generated_at, sections=tuple(sections)
        )


_CARD_GROUPS = {
    "signoff": (ReviewCaseKind.AWAITING_SIGNOFF,),
    "attention": (
        ReviewCaseKind.FP_OVERRIDDEN,
        ReviewCaseKind.FP_REASSERTION_BLOCKED,
        ReviewCaseKind.CONFLICT,
    ),
    "review": (ReviewCaseKind.NEEDS_REVIEW,),
}
_ATTENTION = {
    ReviewCaseKind.FP_OVERRIDDEN: (
        "FP OVERRIDDEN BY EXECUTION EVIDENCE",
        "A reproducing exploit/crash confirmed this finding over a prior human false-positive "
        "assertion (both events remain in the ledger with attribution). No action is required — "
        "validity is `confirmed`. Re-asserting false positive now requires TWO independent "
        "identity-verified humans addressing the PoC.",
    ),
    ReviewCaseKind.FP_REASSERTION_BLOCKED: (
        "SECOND SIGNER NEEDED (two-person rule)",
        "One human re-asserted false positive AFTER execution-verified confirmation. The "
        "two-person rule holds validity at `confirmed` until a SECOND independent "
        "identity-verified human concurs. If you are that second reviewer and you concur, mark "
        "false_positive below WITH your own rationale addressing the PoC; keep_open leaves the "
        "confirmation standing.",
    ),
    ReviewCaseKind.CONFLICT: (
        "CONFLICTING DETERMINATIONS — adjudicate",
        "The ledger carries both `confirmed` and `false_positive` determinations for this "
        "finding. Adjudicate: your decision below records a fresh human determination "
        "(rationale in your own words required either way for a conflict).",
    ),
}
_DECISION_FORM = (
    "DECISION: [ ] false_positive   [ ] keep_open   [ ] defer\n"
    "RATIONALE: (required for keep_open; blank adopts the machine rationale for false_positive)"
)
_IF_YOU_SIGN = (
    "**IF YOU SIGN:** validity → false_positive, attributed to you (identity-verified). The "
    "finding stays in the refuted register — a reproducing exploit from fuzzing or live "
    "validation can still override your signature (`fp_overridden`)."
)


def _card(card: ReviewCard, idx: int, total: int) -> str:
    """One countersign card; every untrusted string goes through `_clip`."""
    case, view, ref = card.case, card.finding, card.refutation
    title = _clip(view.finding.title, 160)
    marker = f"<!-- countersign finding={case.finding_id} -->"
    if case.kind == ReviewCaseKind.NEEDS_REVIEW:
        reason = case.review_item.reason if case.review_item else None
        return "\n\n".join(
            (
                f"### {idx}/{total} — needs_review ({_clip(reason or '?', 60)}) — {title}",
                f"Waiting since {case.since.date().isoformat()}.",
                "Resolve by confirming or rejecting the review item with a resolution note.",
            )
        )
    last = "" if ref is None else "> Last FP rationale: " + _clip(ref.rationale, 400)
    if case.kind in _ATTENTION:
        header, why = _ATTENTION[case.kind]
        form = case.kind != ReviewCaseKind.FP_OVERRIDDEN
        parts = (
            marker if form else "",
            f"### {idx}/{total} — {header} — {title}",
            why,
            last,
            _DECISION_FORM if form else "",
        )
        return "\n\n".join(p for p in parts if p)
    loc = view.locations[0] if view.locations else None
    where = (
        "?"
        if loc is None
        else _clip(loc.path, 200) + (f":{loc.line_start}" if loc.line_start is not None else "")
    )
    refuted = (
        "**THE REFUTATION**: none recorded"
        if ref is None
        else f"**THE REFUTATION** ({_clip(ref.actor or 'machine', 120)} · "
        f"{ref.occurred_at.date().isoformat()})\n\n> {_clip(ref.rationale, 700)}"
    )
    claim = (
        f"**THE CLAIM** (claimed {view.effective_severity} · {_clip(_category(view), 60)})\n"
        f"`{where.replace('`', '')}`"
    )
    return "\n\n".join(
        (marker, f"### {idx}/{total} — {title}", claim, refuted, _IF_YOU_SIGN, _DECISION_FORM)
    )


def _clip(text: object, n: int) -> str:
    """Untrusted text for a card: one printable line, and neither a card marker nor a decision
    form can be forged or terminated by it."""
    text = "".join(ch for ch in " ".join(str(text or "").split()) if ch.isprintable())
    text = text.replace("<!--", "<\\!--").replace("-->", "--\\>")
    text = re.sub(r"(?i)DECISION\s*:", "DECISION\u2236", text)
    text = re.sub(r"(?i)RATIONALE\s*:", "RATIONALE\u2236", text)
    text = re.sub(r"\[\s*[xX]\s*\]", "[\u00d7]", text)
    return text[:n] + ("…" if len(text) > n else "")


class TriageView:
    """A triage document as a report: act on these, hardening, undetermined, dropped."""

    name = ViewName.TRIAGE
    _SEVERITY = ("critical", "high", "medium", "low", "informational")

    per_item = True

    def __init__(self, artifacts: ArtifactPublisher | None = None) -> None:
        self._artifacts = artifacts

    def build(self, filter: ViewFilter) -> TriageDocument:
        if filter.artifact_id is None:
            raise ValidationError("the triage view renders one document: name its artifact_id")
        if self._artifacts is None:
            raise ConfigError("the triage view has no artifact reader wired")
        doc = self._artifacts.read(filter.artifact_id, TriageArtifact)
        return TriageDocument(artifact_id=filter.artifact_id, payload=doc.payload.decode())

    def report(
        self, model: TriageArtifact | TriageDocument, generated_at: datetime | None = None
    ) -> Report:
        """The triage report; dated by the triage's completion, not by `generated_at`."""
        doc = (
            TriageArtifact.parse(model.payload.encode())
            if isinstance(model, TriageDocument)
            else model
        )
        findings = doc.findings
        by: dict[str, list[Any]] = {
            v: []
            for v in ("true_positive", "hardening", "undetermined", "false_positive", "duplicate")
        }
        for finding in findings:
            verdict = (
                "hardening"
                if finding.verdict == "true_positive" and finding.kind == "weakness"
                else finding.verdict
            )
            by[verdict].append(finding)
        sections = [
            self._summary(doc),
            Section(heading="Act on these", body=self._confirmed(by["true_positive"])),
            Section(
                heading="Hardening backlog",
                body="Defense-in-depth, benchmark and best-practice gaps, not exploitable "
                "vulnerabilities. Pending manual verification is shown per finding. "
                "These are NOT false positives." + ("" if by["hardening"] else "\n\n_None._"),
                table=self._table(
                    ("id", "title", "location", "owner", "why hardening", "verification"),
                    [
                        (
                            f.id,
                            f.title,
                            _where(f),
                            f.owner_hint or "-",
                            _first_sentence(f.rationale),
                            f.verify_verdict or "-",
                        )
                        for f in sorted(by["hardening"], key=lambda f: -(f.confidence or 0))
                    ],
                ),
            ),
        ]
        if by["undetermined"]:
            sections.append(
                Section(
                    heading="Undetermined",
                    body="Nothing was proven or refuted: cited material was missing or "
                    "unreadable, or "
                    "verification couldn't decide. A person must review these; they are not false "
                    "positives.",
                    table=self._table(
                        ("id", "title", "location", "why undetermined"),
                        [
                            (
                                f.id,
                                f.title,
                                _where(f),
                                _first_sentence(f.rationale or ", ".join(f.refute_reasons)),
                            )
                            for f in by["undetermined"]
                        ],
                    ),
                )
            )
        dropped = [
            (
                f.id,
                f.title,
                _where(f),
                (", ".join(f.refute_reasons) or "refuted")
                + (f" (rule {f.exclusion_rule})" if f.exclusion_rule is not None else ""),
            )
            for f in by["false_positive"]
        ] + [(f.id, f.title, _where(f), f"duplicate of {f.duplicate_of}") for f in by["duplicate"]]
        sections.append(
            Section(
                heading="Dropped",
                body="" if dropped else "_None._",
                table=self._table(("id", "title", "location", "why dropped"), dropped),
            )
        )
        when = datetime.combine(date.fromisoformat(str(doc.triage_completed)), time(), UTC)
        return Report(title="Triage Report", generated_at=when, sections=tuple(sections))

    def _summary(self, doc: TriageArtifact) -> Section:
        s, ctx = doc.summary, doc.triage_context
        by_severity = s.by_severity
        severities = " / ".join(
            f"{getattr(by_severity, k)} {k}"
            for k in self._SEVERITY
            if getattr(by_severity, k, None) is not None
        )
        counts = (
            f"{s.input_count} in: {s.true_positives} confirmed ({severities}), "
            f"{s.hardening} hardening, {s.undetermined} undetermined, {s.duplicates} duplicates, "
            f"{s.false_positives} false positives"
        )
        context = (
            f"Context: {inline(ctx.mode)}; environment = {inline(ctx.environment)}; "
            f"{inline(ctx.votes_per_finding)}-vote verification; "
            f"harness {inline(ctx.harness_version)}; "
            f"completed {inline(doc.triage_completed)}"
        )
        return Section(heading="Summary", body=f"{counts}\n\n{context}")

    def _confirmed(self, findings: Sequence[Any]) -> str:
        if not findings:
            return "_No confirmed findings._"
        rank = {s: i for i, s in enumerate(self._SEVERITY)}
        entries = []
        for f in sorted(
            findings, key=lambda f: (rank.get(str(f.severity).lower(), 9), -(f.confidence or 0))
        ):
            meta = f"{_where(f)} | {inline(f.category or '-')}"
            if f.claimed_severity:
                meta += f" | claimed {inline(f.claimed_severity)}"
                if f.severity_alignment is not None:
                    meta += f" (alignment {inline(f.severity_alignment)})"
            if f.confidence is not None:
                meta += f" | confidence {f.confidence}/10"
            lines = [
                f"### [{inline(str(f.severity or '?').upper())}] "
                f"{inline(f.title)} ({inline(f.id)})",
                meta,
            ]
            fields = (
                ("Source finding", f.orig_id),
                ("Owner", f.owner_hint),
                (
                    "Verdict",
                    f"{inline(f.verify_verdict or 'confirmed')}, votes {_votes(f.vote_breakdown)}",
                ),
                ("Preconditions", "; ".join(map(inline, f.preconditions))),
                ("Threat-model match", f.threat_match),
                ("Why", f.rationale),
                ("Reachability evidence", ", ".join(map(inline, f.first_links))),
            )
            lines += [f"**{label}:** {inline(value)}" for label, value in fields if value]
            if f.verify_verdict == "needs_manual_test":
                lines.append("> Recommend a person build a PoC; static reasoning hit its limit.")
            entries.append("\n".join(lines))
        return "\n\n".join(entries)

    @staticmethod
    def _table(columns: tuple[str, ...], rows: Sequence[tuple[Any, ...]]) -> Table | None:
        return (
            Table(columns=columns, rows=tuple(tuple(map(str, r)) for r in rows)) if rows else None
        )


def _where(f: Any) -> str:
    """`file:line`; backticks stripped so a hostile path can't close the code span."""
    path = inline(f.file or "-").replace("`", "")
    return f"`{path}:{f.line}`" if f.line is not None else f"`{path}`"


def _votes(v: Any) -> str:
    if v is None:
        return "-"
    return f"{v.true_positive}T/{v.hardening}H/{v.false_positive}F/{v.cannot_verify}C"


def _first_sentence(text: str | None, limit: int = 220) -> str:
    text = inline(text)
    for stop in (". ", "; "):
        if 0 < (i := text.find(stop)) < limit:
            return text[: i + 1]
    return text[:limit] + ("…" if len(text) > limit else "")


class SlaView:
    """Owner-response SLA clocks (sla-view, `metrics sla`): every policy profile over the
    scope's findings as of `as_of` (else now), with per-team overdue tables and an escalation
    digest that is generated, never sent."""

    name = ViewName.SLA

    def __init__(
        self, findings: FindingService, portfolio: PortfolioService, policy: SlaPolicy, clock: Clock
    ) -> None:
        self._findings = findings
        self._portfolio = portfolio
        self._policy = policy
        self._clock = clock

    def build(self, filter: ViewFilter) -> SlaDashboard:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories = _scope(self._portfolio, filter)
        clocked = [
            (repository, clock, owners)
            for repository in repositories
            for owners in [
                tuple(t.name for t in self._portfolio.list_owners(repository.id, filter.as_of))  # type: ignore[arg-type]
            ]
            for clock in self._findings.clocks(
                FindingFilter(repository_id=repository.id, as_of=filter.as_of)  # type: ignore[arg-type]
            )
            if clock.view.state() not in (FindingState.FALSE_POSITIVE, FindingState.HARDENING)
        ]
        profiles = sorted(self._policy.profiles.items(), key=lambda p: (not p[1].default, p[0]))
        return SlaDashboard(
            policy_name=self._policy.policy_name,
            source=self._policy.source,
            clock_start=self._policy.clock_start,
            as_of=as_of,
            profiles=tuple(
                _sla_profile(n, p, self._policy.clock_start, clocked, as_of) for n, p in profiles
            ),
        )

    def report(self, model: SlaDashboard, generated_at: datetime) -> Report:
        # NEED(registry): product-definitions door for the digest's accountable contacts
        # (trusted match tiers only); until then the report says they are unavailable.
        src = model.source
        sections = [
            Section(
                heading="About",
                body=f"As of {model.as_of.isoformat()} · policy {model.policy_name}, source "
                f"{src.name} (retrieved {src.retrieved.isoformat()}) · clock start: "
                f"{model.clock_start}. Profiles are different clocks over the same findings. "
                "SLAs are policy data: swap the policy file, never the code. Accountable "
                "contacts: unavailable (no product registry in traust-core).",
            )
        ]
        for p in model.profiles:
            c = p.counts
            rows = [
                ("Open, within SLA", c.open_in_sla),
                ("Open, overdue", c.open_overdue),
                ("Open, no SLA (tracked, never overdue)", c.open_no_sla),
                ("Unclocked (no report and no decision)", c.unclocked),
                ("Risk accepted (no clock)", c.accepted),
                ("Outside this profile's severity scope", c.out_of_profile_scope),
                ("Resolved within SLA", c.resolved_met),
                ("Resolved past SLA", c.resolved_breached),
                ("Resolved, no resolution time", c.resolved_unclocked),
            ]
            notes = [
                f"Resolved-SLA compliance: {p.resolved_compliance_pct}%."
                if p.resolved_compliance_pct is not None
                else "",
                "Overdue by severity: "
                + ", ".join(f"{k}: {v}" for k, v in p.overdue_by_severity.items())
                + "."
                if p.overdue_by_severity
                else "",
                "Median days-to-resolve: "
                + ", ".join(f"{k}: {v}d" for k, v in p.median_days_to_resolve.items())
                + "."
                if p.median_days_to_resolve
                else "",
            ]
            sections += [
                Section(
                    heading=f"{p.profile}: summary",
                    body=" ".join(n for n in [p.description or "", *notes] if n),
                    table=Table(
                        columns=("metric", "count"), rows=tuple((m, str(n)) for m, n in rows)
                    ),
                ),
                _table_section(
                    f"{p.profile}: overdue by owner team",
                    ("team", "overdue", "critical", "worst (days over)"),
                    [
                        (t.team, str(t.overdue), str(t.critical), str(t.worst_days))
                        for t in p.teams[:_TOP_SLA_ROWS]
                    ],
                    "_Nothing overdue._",
                ),
                _table_section(
                    f"{p.profile}: escalation digest (generated; human review before any routing)",
                    ("repository", "finding", "severity", "teams", "due", "days overdue", "basis"),
                    [
                        (
                            e.repository_url,
                            e.title,
                            "-" if e.severity is None else str(e.severity),
                            ", ".join(e.teams),
                            e.due.date().isoformat(),
                            str(e.days_overdue),
                            str(e.clock_basis),
                        )
                        for e in p.escalations[:_TOP_SLA_ROWS]
                    ],
                    "_Nothing overdue._",
                ),
            ]
        return Report(
            title=f"SLA view: {model.policy_name}",
            generated_at=generated_at,
            sections=tuple(sections),
        )


_TOP_SLA_ROWS = 25
_MAX_ESCALATIONS = 100
_UNASSIGNED = "(unassigned)"


def _sla_profile(
    name: str,
    profile: SlaProfile,
    mode: SlaClockStart,
    clocked: Sequence[tuple[Repository, FindingClock, tuple[str, ...]]],
    as_of: datetime,
) -> SlaProfileView:
    floor = profile.cvss_floor_days
    rule = RatingPolicy(
        RatingConfig(
            sla=SlaConfig(
                resolve_days={s: t.resolve_days for s, t in profile.slas.items()},
                cvss_floor=None
                if floor is None
                else CvssFloor(threshold=floor.threshold, resolve_days=floor.resolve_days),
            )
        )
    )
    counts: Counter[str] = Counter()
    overdue: Counter[ScannerSeverity] = Counter()
    to_resolve: defaultdict[ScannerSeverity, list[int]] = defaultdict(list)
    teams: defaultdict[str, list[tuple[ScannerSeverity, int]]] = defaultdict(list)
    escalations = []
    for repository, clock, owners in clocked:
        view = clock.view
        severity = view.effective_severity
        cvss = view.occurrence.cvss_score if view.occurrence else None
        floored = floor is not None and cvss is not None and cvss >= floor.threshold
        if severity not in profile.slas and not floored:
            counts["out_of_profile_scope"] += 1
            continue
        state = view.state()
        if state == FindingState.ACCEPTED:
            counts["accepted"] += 1
            continue
        resolved = state == FindingState.RESOLVED
        start, basis = _clock_start(clock, mode)
        if start is None:
            counts["resolved_unclocked" if resolved else "unclocked"] += 1
            continue
        due = rule.sla_due(severity, start, cvss)
        if due is None:
            counts["open_no_sla"] += not resolved
            continue
        bucket = ScannerSeverity.UNRATED if severity is None else ScannerSeverity(severity)
        if resolved:
            if clock.resolved_at is None:
                counts["resolved_unclocked"] += 1
                continue
            counts["resolved_met" if clock.resolved_at <= due else "resolved_breached"] += 1
            to_resolve[bucket].append(
                (clock.resolved_at.astimezone(UTC) - start.astimezone(UTC)).days
            )
        elif due < as_of:
            late = (as_of - due).days
            counts["open_overdue"] += 1
            overdue[bucket] += 1
            for team in owners or (_UNASSIGNED,):
                teams[team].append((bucket, late))
            escalations.append(
                SlaEscalation(
                    finding_id=view.finding.id,  # type: ignore[arg-type]
                    repository_url=repository.url,
                    severity=severity,
                    title=view.finding.title[:120],
                    teams=owners or (_UNASSIGNED,),
                    due=due,
                    days_overdue=late,
                    clock_basis=basis,  # type: ignore[arg-type]
                )
            )
        else:
            counts["open_in_sla"] += 1
    scored = counts["resolved_met"] + counts["resolved_breached"]
    return SlaProfileView(
        profile=name,
        description=profile.description,
        counts=SlaCounts(**counts),
        resolved_compliance_pct=round(100 * counts["resolved_met"] / scored, 1) if scored else None,
        median_days_to_resolve={s: sorted(d)[len(d) // 2] for s, d in sorted(to_resolve.items())},
        overdue_by_severity=dict(sorted(overdue.items())),
        teams=tuple(
            sorted(
                (
                    SlaTeamRow(
                        team=team,
                        overdue=len(late),
                        critical=sum(s == "critical" for s, _ in late),
                        worst_days=max(d for _, d in late),
                    )
                    for team, late in teams.items()
                ),
                key=lambda t: (-t.overdue, t.team),
            )
        ),
        escalations=tuple(
            sorted(escalations, key=lambda e: (_severity_rank(e.severity), -e.days_overdue))[
                :_MAX_ESCALATIONS
            ]
        ),
    )


def _clock_start(clock: FindingClock, mode: SlaClockStart) -> tuple[datetime | None, str]:
    """The policy's clock-start ladder: filed, else the first thing recorded about the finding,
    else its first report; none of them is unclocked, never guessed."""
    first = min((t for t in (clock.reported_at, clock.decided_at) if t), default=None)
    ladder = {
        "first_routed_or_filed": [(clock.filed_at, "filed"), (first, "first_event")],
        "first_event": [(first, "first_event")],
    }.get(str(mode), [])
    for at, basis in [*ladder, (clock.reported_at, "audit_date")]:
        if at is not None:
            return at, basis
    return None, "unclocked"


class SarifExport:
    """Findings as SARIF 2.1.0 for code scanning: a one-way projection, never a store. False
    positives and accepted risks arrive as suppressions, resolved findings as `absent`."""

    name = ViewName.SARIF

    def document(self, views: Sequence[FindingView], repository_url: str) -> dict[str, Any]:
        categories = list(dict.fromkeys(_category(v) for v in views))
        version = core_version()
        driver = {
            "name": "traust",
            "version": version,
            "semanticVersion": version,
            "rules": _category_rules(categories),
        }
        run = {
            "tool": {"driver": driver},
            "columnKind": "utf16CodeUnits",
            "results": [_sarif_result(v, categories.index(_category(v))) for v in views],
            "properties": {
                "traust/repository": repository_url,
                "traust/authoritative_source": "traust-core decisions; this file is a projection",
            },
            "versionControlProvenance": [{"repositoryUri": repository_url}],
        }
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}

    def report(
        self, document: ReportArtifact | CloudConfigAuditArtifact, tool_uri: str | None
    ) -> dict[str, Any]:
        """A report document a caller holds as SARIF; `tool_uri` is `locations.sarif_tool_uri`."""
        raw = json.loads(document.payload)
        if isinstance(document, CloudConfigAuditArtifact):
            return _declared_run(raw, tool_uri)
        findings, meta = raw["findings"], raw["metadata"]
        categories = list(dict.fromkeys(f.get("category") or "uncategorized" for f in findings))
        version = str(meta.get("additional", {}).get("harness_version", ""))
        semantic = version.split("-")[0] if version else "0.0.0"
        properties = {
            "traust/report_title": raw["title"],
            "traust/audit_profile": meta.get("audit_profile", "code"),
            "traust/repository": meta.get("repository", ""),
            "traust/commit": meta.get("commit", ""),
            "traust/date": meta["date"],
            "traust/authoritative_source": "the harness report + disposition ledger; this SARIF "
            "file is a derived one-way projection — never an authoritative store",
        }
        if meta.get("ref"):
            properties |= {"traust/ref": meta["ref"], "traust/ref_kind": meta.get("ref_kind", "")}
        run: dict[str, Any] = {
            "tool": {"driver": _driver(tool_uri, version or semantic, semantic, categories)},
            "columnKind": "utf16CodeUnits",
            # a run whose deterministic steps were skipped is not full coverage
            "invocations": [{"executionSuccessful": not _degraded(raw)}],
            "results": [_report_result(f, categories) for f in findings],
            "properties": properties,
        }
        if meta.get("repository"):
            commit = {"revisionId": meta["commit"]} if meta.get("commit") else {}
            run["versionControlProvenance"] = [{"repositoryUri": meta["repository"], **commit}]
        return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _category_rules(categories: Sequence[str]) -> list[dict[str, Any]]:
    return [
        {
            "id": c,
            "name": c.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": f"Finding category: {c}"},
            "properties": {"tags": ["security", c]},
        }
        for c in categories
    ]


def _driver(
    tool_uri: str | None, version: str, semantic: str, categories: Sequence[str]
) -> dict[str, Any]:
    return {
        "name": "traust",
        **({"informationUri": tool_uri} if tool_uri else {}),
        "version": version,
        "semanticVersion": semantic,
        "rules": _category_rules(categories),
    }


def _degraded(raw: dict[str, Any]) -> bool:
    """The run's own record says coverage was incomplete."""
    additional = raw["metadata"].get("additional", {})
    if additional.get("degraded"):
        return True
    probes = [*raw.get("negative_results", []), *additional.get("deterministic_steps", [])]
    words = ("skipped", "unavailable", "not-run", "tool_missing")
    return any(w in json.dumps(p).lower() for p in probes for w in words)


_LINES = re.compile(r"^\s*(\d+)\s*(?:[-\u2013]\s*(\d+))?\s*$")


def _report_location(loc: dict[str, Any]) -> dict[str, Any]:
    path = loc["path"]
    if _PSEUDO_PATH.match(path):
        out: dict[str, Any] = {"logicalLocations": [{"fullyQualifiedName": path}]}
    else:
        physical: dict[str, Any] = {"artifactLocation": {"uri": path}}
        if m := _LINES.match(loc.get("lines") or ""):
            physical["region"] = {"startLine": int(m[1])} | ({"endLine": int(m[2])} if m[2] else {})
        out = {"physicalLocation": physical}
    if loc.get("description"):
        out["message"] = {"text": loc["description"]}
    return out


def _report_result(finding: dict[str, Any], categories: list[str]) -> dict[str, Any]:
    category = finding.get("category") or "uncategorized"
    severity = finding.get("effective_severity") or finding["severity"]
    level, security_severity = _SARIF_LEVEL.get(severity, ("note", "0.5"))
    disposition = finding.get("disposition") or {}
    properties: dict[str, Any] = {
        "security-severity": security_severity,
        "traust/severity": severity,
        "traust/validation_status": finding.get("validation_status", "not_verified"),
    }
    if finding.get("cwes"):
        properties["tags"] = ["security", *finding["cwes"]]
    if finding.get("cvss", {}).get("vector"):
        properties["traust/cvss"] = finding["cvss"]
    if disposition:
        properties["traust/disposition"] = disposition
    text = _message(finding["title"], finding.get("description"), _remediation(finding))
    fingerprints = {"traustFindingId/v1": finding["id"]} | (
        {"traustFingerprint/v1": finding["fingerprint"]} if finding.get("fingerprint") else {}
    )
    result: dict[str, Any] = {
        "ruleId": category,
        "ruleIndex": categories.index(category),
        "level": level,
        "message": {"text": text or finding["id"]},
        "locations": [_report_location(loc) for loc in finding["locations"]],
        "partialFingerprints": fingerprints,
        "properties": properties,
    }
    if suppressions := _suppressions(
        disposition.get("validity") == "false_positive",
        disposition.get("resolution") == "risk_accepted",
    ):
        result["suppressions"] = suppressions
    if disposition.get("resolution") == "resolved":
        result["baselineState"] = "absent"
    return result


def _remediation(finding: dict[str, Any]) -> str | None:
    return f"Remediation: {finding['remediation']}" if finding.get("remediation") else None


def _message(title: str, *parts: str | None) -> str:
    return "\n\n".join([title, *(p for p in parts if p)])


def _suppressions(false_positive: bool, risk_accepted: bool) -> list[dict[str, str]]:
    return [
        {"kind": "external", "status": "accepted", "justification": f"traust disposition: {why}"}
        for said, why in (
            (false_positive, "validity=false_positive"),
            (risk_accepted, "resolution=risk_accepted"),
        )
        if said
    ]


def _declared_run(raw: dict[str, Any], tool_uri: str | None) -> dict[str, Any]:
    """Cloud-config audits: Checkov checks as rules, DECLARED configuration, never observed."""
    findings, meta = raw["findings"], raw["metadata"]
    titles: dict[str, str] = {}
    for f in findings:
        check = f.get("check_id") or "unknown-check"
        titles.setdefault(check, f.get("title", check))
    checks = list(titles)
    version = str(meta.get("harness_version", ""))
    rules = [
        {
            "id": c,
            "shortDescription": {"text": titles[c]},
            "properties": {"tags": ["security", "iac", "declared-configuration"]},
        }
        for c in checks
    ]
    driver = _driver(tool_uri, version or "0.0.0", version.split("-")[0] or "0.0.0", ())
    run: dict[str, Any] = {
        "tool": {"driver": driver | {"rules": rules}},
        "columnKind": "utf16CodeUnits",
        "results": [_declared_result(f, checks) for f in findings],
        "properties": {
            "traust/report_title": raw.get("title", ""),
            "traust/target": meta.get("target", ""),
            "traust/assessment_mode": "declared",
            "traust/engine": f"checkov {meta.get('checkov_version', '')}".strip(),
            "traust/authoritative_source": "the cloud-config-audit report; this SARIF file is a "
            "derived one-way projection of DECLARED configuration — never an observation claim",
        },
    }
    if meta.get("repository"):
        run["versionControlProvenance"] = [{"repositoryUri": meta["repository"]}]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _declared_result(finding: dict[str, Any], checks: list[str]) -> dict[str, Any]:
    check = finding.get("check_id") or "unknown-check"
    severity = finding.get("severity") or "informational"
    level, security_severity = _SARIF_LEVEL.get(severity, ("note", "0.5"))
    text = _message(finding.get("title", ""), finding.get("rationale"), _remediation(finding))
    locations = []
    for loc in finding.get("locations") or []:
        physical: dict[str, Any] = {"artifactLocation": {"uri": loc.get("file_path", "")}}
        if span := loc.get("file_line_range") or []:
            physical["region"] = {"startLine": span[0]} | (
                {"endLine": span[1]} if len(span) > 1 and span[1] >= span[0] else {}
            )
        entry: dict[str, Any] = {"physicalLocation": physical}
        if loc.get("resource"):
            entry["logicalLocations"] = [{"fullyQualifiedName": loc["resource"]}]
        locations.append(entry)
    properties: dict[str, Any] = {
        "security-severity": security_severity,
        "traust/severity": severity,
        "traust/status": finding.get("status", "confirmed"),
        "traust/assessment_mode": "declared",
    }
    if finding.get("cwe"):
        properties["tags"] = ["security", finding["cwe"]]
    for key in ("fact_ids", "control_refs"):
        if finding.get(key):
            properties[f"traust/{key}"] = finding[key]
    result: dict[str, Any] = {
        "ruleId": check,
        "ruleIndex": checks.index(check),
        "level": level,
        "message": {"text": text or finding.get("id", "(untitled)")},
        "locations": locations,
        "partialFingerprints": {"traustFindingId/v1": finding.get("id", "")},
        "properties": properties,
    }
    if finding.get("status") == "suppressed":
        why = finding.get("rationale") or (
            "suppressed at audit time (auditor's claim; see the cloud-config-audit report)"
        )
        result["suppressions"] = [{"kind": "external", "status": "accepted", "justification": why}]
    return result


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
# severity -> (SARIF level, GitHub security-severity)
_SARIF_LEVEL = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "2.0"),
    "informational": ("note", "0.5"),
}
# Not files: a package, an image config or layer, named rather than located.
_PSEUDO_PATH = re.compile(r"^(pkg:|oci-config:|layer:|sha256:)")


def _category(view: FindingView) -> str:
    return view.label("category") or "uncategorized"


def _sarif_location(loc: Location) -> dict[str, Any]:
    if _PSEUDO_PATH.match(loc.path):
        return {"logicalLocations": [{"fullyQualifiedName": loc.path}]}
    physical: dict[str, Any] = {"artifactLocation": {"uri": loc.path}}
    if loc.line_start is not None:
        physical["region"] = {"startLine": loc.line_start}
        if loc.line_end is not None and loc.line_end != loc.line_start:
            physical["region"]["endLine"] = loc.line_end
    return {"physicalLocation": physical}


def _sarif_result(view: FindingView, rule_index: int) -> dict[str, Any]:
    severity = view.effective_severity
    rating = _SARIF_LEVEL.get(severity)
    level = rating[0] if rating is not None else "none"
    disposition = view.disposition
    properties: dict[str, Any] = {
        "traust/severity": severity,
        "traust/validity": (disposition.validity if disposition else None) or "not_verified",
    }
    if rating is not None:
        properties["security-severity"] = rating[1]
    if view.cwes:
        properties["tags"] = ["security", *view.cwes]
    if view.occurrence is not None and view.occurrence.cvss_vector:
        properties["traust/cvss"] = {
            "vector": view.occurrence.cvss_vector,
            "score": str(view.occurrence.cvss_score),
        }
    if disposition is not None:
        properties["traust/disposition"] = disposition.model_dump(mode="json")
    result: dict[str, Any] = {
        "ruleId": _category(view),
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": view.finding.title},
        "locations": [_sarif_location(loc) for loc in view.locations],
        "partialFingerprints": {
            "traustFindingId/v1": str(view.finding.id),
            "traustFingerprint/v1": view.finding.fingerprint,
        },
        "properties": properties,
    }
    suppressions = _suppressions(
        bool(disposition and disposition.validity == "false_positive"),
        bool(disposition and disposition.resolution == "risk_accepted"),
    )
    if suppressions:
        result["suppressions"] = suppressions
    if disposition is not None and disposition.resolution == "resolved":
        result["baselineState"] = "absent"
    return result


class OscalExport:
    """One recorded compliance assessment as OSCAL 1.1.2 assessment-results (800-53 spine)."""

    name = ViewName.OSCAL
    per_item = True

    def __init__(self, compliance: ComplianceService) -> None:
        self._compliance = compliance

    def build(self, filter: ViewFilter) -> OscalAssessmentResults:
        if filter.artifact_id is None:
            raise ValidationError(
                "the oscal view exports one compliance assessment: name its artifact_id"
            )
        doc = self._compliance.export_oscal(filter.artifact_id)
        return OscalAssessmentResults.model_validate(doc)

    def report(self, model: OscalAssessmentResults, generated_at: datetime) -> Report:
        results = model.assessment_results
        observations = [o for r in results["results"] for o in r["observations"]]
        rows = [
            (
                o["title"],
                *(p["value"] for p in o["props"]),
                ", ".join(o["methods"]),
                o["description"],
            )
            for o in observations
        ]
        columns = ("control", "verdict", "classification", "method", "description")
        return Report(
            title=results["metadata"]["title"],
            generated_at=generated_at,
            sections=(_table_section("Observations", columns, rows, "_No spine results._"),),
        )
