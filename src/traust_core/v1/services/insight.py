from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from traust_core.v1.errors import ConfigError, NotFoundError, TraustError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.assessment import AssessmentFilter, Threat, ThreatFilter
from traust_core.v1.models.common import every_item
from traust_core.v1.models.compliance import (
    ComplianceDimension,
    ComplianceFilter,
    ComplianceRollup,
    DocVarianceDisposition,
    DocVarianceFilter,
)
from traust_core.v1.models.dependencies import ExposureDimension, ExposureFilter
from traust_core.v1.models.findings import (
    FindingClock,
    FindingFilter,
    FindingSeriesPoint,
    FindingState,
    FindingView,
    Location,
    ReviewCaseKind,
    ReviewFilter,
)
from traust_core.v1.models.insight import (
    ComplianceDashboard,
    CoverageDashboard,
    ExecutiveSummary,
    ExposureDashboard,
    FindingsRollup,
    FindingsTrend,
    FindingTally,
    LanguageSeverity,
    LanguageTotal,
    LeastPrivilege,
    LocDashboard,
    PqcDashboard,
    PqcScope,
    ProductRollup,
    ProgramMetrics,
    QuickWin,
    RankedThreat,
    RefreshResult,
    RenderedView,
    RepositoryLoc,
    RepositoryRollup,
    ReviewCard,
    ReviewCards,
    SeverityCounts,
    SlaCounts,
    SlaDashboard,
    SlaEscalation,
    SlaPolicy,
    SlaProfile,
    SlaProfileView,
    SlaTeamRow,
    ThreatRegister,
    TopFinding,
    TriageDocument,
    ViewFilter,
    ViewModel,
    ViewName,
)
from traust_core.v1.models.inventory import Product, Repository, RepositoryFilter
from traust_core.v1.models.operations import (
    FINISHED_ORDER_STATES,
    AssetName,
    OrderFilter,
    SpendDimension,
    SpendFilter,
)
from traust_core.v1.models.pqc import PqcDimension, PqcFilter
from traust_core.v1.models.vocabulary import (
    DispositionAssurance,
    RiskRatingBand,
    Severity,
    SlaClockStart,
    Validity,
)
from traust_core.v1.providers.clock import Clock
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer, Report, Section, Table, inline
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
        return RenderedView(
            view=view,
            stem=_stem(report.title),
            model=model,
            markdown=MarkdownRenderer().render(report).decode(),
            html=HtmlRenderer().render(report).decode(),
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

    def __init__(self, findings: FindingService, portfolio: PortfolioService) -> None:
        self._findings = findings
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> FindingsRollup:
        return _rollup(filter.as_of, *_scoped_findings(self._findings, self._portfolio, filter))

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
        severity_columns = ("critical", "high", "medium", "low", "info", "total")
        sections = [Section(heading="Summary", body=summary)]
        if model.products:
            sections.append(
                Section(
                    heading="By product",
                    body="A finding in a repository several products ship counts under each.",
                    table=Table(
                        columns=("product", "repositories", *severity_columns),
                        rows=tuple(
                            (p.name, str(p.repositories), *_counts(p.tally.open))
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
                            *_counts(r.tally.open),
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
                key=lambda t: (_RANK[str(t.severity)], -(t.cvss_score or -1), t.repository_url),
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
    proven = unverified = 0
    for v in views:
        bucket = v.state()
        buckets[bucket] += 1
        if bucket == _OPEN:
            severities[str(v.effective_severity)] += 1
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
    )


def _counts(c: SeverityCounts) -> tuple[str, ...]:
    return tuple(map(str, (c.critical, c.high, c.medium, c.low, c.informational, c.total)))


def _severities(c: SeverityCounts) -> str:
    return ", ".join(
        f"{n} {s}"
        for s, n in (
            ("critical", c.critical),
            ("high", c.high),
            ("medium", c.medium),
            ("low", c.low),
            ("informational", c.informational),
        )
    )


# Unbuilt views: each names the dashboard it replaces and the stubbed door it waits on.
class _StubView:
    name: ViewName
    replaces = ""

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError(f"stub: replaces {self.replaces}")


class FindingsTrendView:
    """The scope's findings over time: each repository's series replayed to `as_of` (else now)
    and summed per bucket; MTTR is weighted by each repository's resolutions."""

    name = ViewName.FINDINGS_TREND

    def __init__(self, findings: FindingService, portfolio: PortfolioService, clock: Clock) -> None:
        self._findings = findings
        self._portfolio = portfolio
        self._clock = clock

    def build(self, filter: ViewFilter) -> FindingsTrend:
        as_of = filter.as_of or self._clock.now()
        _, _, repositories = _scope(self._portfolio, filter)
        by_bucket: defaultdict[datetime, list[FindingSeriesPoint]] = defaultdict(list)
        for r in repositories:
            query = FindingFilter(repository_id=r.id, as_of=as_of)  # type: ignore[arg-type]
            for point in self._findings.timeline(query, filter.bucket):
                by_bucket[point.bucket].append(point)
        window = filter.window
        return FindingsTrend(
            as_of=as_of,
            repositories=len(repositories),
            points=tuple(
                _summed(bucket, points)
                for bucket, points in sorted(by_bucket.items())
                if window is None or window.start <= bucket < window.end
            ),
        )

    def report(self, model: FindingsTrend, generated_at: datetime) -> Report:
        rows = tuple(
            (
                p.bucket.date().isoformat(),
                *(str(p.open_by_severity.get(Severity(s), 0)) for s in _RANK),
                str(p.new),
                str(p.resolved),
                str(p.regressions),
                str(p.accepted),
                str(p.hardening),
                str(p.false_positives),
                "-" if p.mttr_days is None else str(p.mttr_days),
                str(p.risk_index),
            )
            for p in model.points
        )
        columns = (
            "bucket",
            *_RANK,
            "new",
            "resolved",
            "regressions",
            "accepted",
            "hardening",
            "false positives",
            "mttr days",
            "risk index",
        )
        summary = (
            f"{model.repositories} repositories, as of {model.as_of.isoformat()}. Open counts, "
            "accepted, hardening and the risk index stand at each bucket's end; new, resolved, "
            "regressions and false positives happened within it."
        )
        return Report(
            title="Findings trend",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=summary),
                Section(
                    heading="Series",
                    body="" if rows else "_No findings reported in scope._",
                    table=Table(columns=columns, rows=rows) if rows else None,
                ),
            ),
        )


def _usd(amount: Decimal) -> str:
    return f"${amount:,.2f}"


def _summed(bucket: datetime, points: Sequence[FindingSeriesPoint]) -> FindingSeriesPoint:
    open_by: Counter[Severity] = Counter()
    for p in points:
        open_by.update(p.open_by_severity)
    timed = [(p.mttr_days, p.resolved) for p in points if p.mttr_days is not None and p.resolved]
    weight = sum(n for _, n in timed)
    return FindingSeriesPoint(
        bucket=bucket,
        open_by_severity=dict(open_by),
        new=sum(p.new for p in points),
        resolved=sum(p.resolved for p in points),
        accepted=sum(p.accepted for p in points),
        hardening=sum(p.hardening for p in points),
        false_positives=sum(p.false_positives for p in points),
        regressions=sum(p.regressions for p in points),
        mttr_days=round(sum(d * n for d, n in timed) / weight, 1) if weight else None,
        risk_index=round(sum(p.risk_index for p in points), 1),
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

    def __init__(self, code_facts: CodeFactsService, portfolio: PortfolioService) -> None:
        self._code_facts = code_facts
        self._portfolio = portfolio

    def build(self, filter: ViewFilter) -> LocDashboard:
        if filter.as_of is not None:
            raise ValidationError("the loc view reads the latest measurement; it takes no as_of")
        _, _, repositories = _scope(self._portfolio, filter)
        measured = [_measured(self._code_facts, self._portfolio, r) for r in repositories]
        totals: defaultdict[str, list[int]] = defaultdict(list)
        for r in measured:
            for language in r.languages:
                totals[language.name].append(language.code)
        return LocDashboard(
            code=sum(r.code for r in measured),
            total=sum(r.total for r in measured),
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
            ),
        )


def _measured(
    code_facts: CodeFactsService, portfolio: PortfolioService, repository: Repository
) -> RepositoryLoc:
    """The repository's latest measured languages at its default-branch commit, or why not."""
    found = RepositoryLoc(repository_id=repository.id, repository_url=repository.url)  # type: ignore[arg-type]
    ref = portfolio.inventory.default_ref(repository.id)  # type: ignore[arg-type]
    if ref is None:
        return found.model_copy(update={"unmeasured": "no default-branch commit"})
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


class AttackCoverageView(_StubView):
    name, replaces = (
        ViewName.ATTACK_COVERAGE,
        "attack-coverage; needs ValidationService.summary (stub)",
    )


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
        open_variances = DocVarianceFilter(disposition=DocVarianceDisposition("open"))
        return ThreatRegister(
            as_of=as_of,
            repository_urls=urls,
            models=len({r.threat.assessment_id for r in threats}),
            threats=tuple(threats),
            quick_wins=_quick_wins(threats),
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
                    ("repository", "mitigation", "effort", "covers", "severity"),
                    [
                        (urls[w.repository_id], w.mitigation, w.effort, ", ".join(w.covers), w.band)
                        for w in model.quick_wins[:_TOP_THREATS]
                    ],
                    "_No quick wins._",
                ),
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


def _quick_wins(threats: Sequence[RankedThreat]) -> tuple[QuickWin, ...]:
    """Class-closing XS/S mitigations over unmitigated high or critical threats, per model."""
    covered: dict[tuple[UUID, str, str], list[RankedThreat]] = defaultdict(list)
    for r in threats:
        if r.threat.status == "unmitigated" and r.band in ("critical", "high"):
            for m in r.threat.mitigations:
                if m.closes_class == "yes" and m.effort in ("XS", "S"):
                    covered[r.threat.assessment_id, m.text, m.effort].append(r)
    wins = [
        QuickWin(
            repository_id=rs[0].threat.repository_id,  # type: ignore[arg-type]
            mitigation=text,
            effort=effort,
            covers=tuple(r.threat.label for r in rs),
            band=rs[0].band,  # type: ignore[arg-type]
        )
        for (_, text, effort), rs in covered.items()
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
                ("By product", model.by_product),
                ("By verdict", model.by_classification),
            )
        )
        return Report(title="Dependency exposure", generated_at=generated_at, sections=sections)


class ValidationFuzzView(_StubView):
    name, replaces = (
        ViewName.VALIDATION_FUZZ,
        "validation-fuzz-dashboard; needs ValidationService.summary (stub)",
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
                    key=lambda t: (_RANK[str(t.severity)], t.repository_url, t.title),
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
        severity_columns = ("critical", "high", "medium", "low", "info", "total")
        sections = [
            Section(heading="Summary", body=summary),
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
                [(r.language, str(r.repositories), *_counts(r.open)) for r in model.languages],
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
        str(f.severity),
        "-" if f.cvss_score is None else str(f.cvss_score),
        "yes" if f.execution_proven else "",
        "-" if f.sla_due is None else f.sla_due.date().isoformat(),
    )


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
        by = {
            v: [f for f in findings if f.verdict == v]
            for v in ("true_positive", "hardening", "undetermined", "false_positive", "duplicate")
        }
        sections = [
            self._summary(doc),
            Section(heading="Act on these", body=self._confirmed(by["true_positive"])),
            Section(
                heading="Hardening backlog",
                body="Real gaps confirmed by verification, with no concrete exploit path "
                "(exclusion "
                "rule 13: defense in depth, benchmark and best-practice deviations). Track them as "
                "engineering hygiene, not vulnerabilities. These are NOT false positives."
                + ("" if by["hardening"] else "\n\n_None._"),
                table=self._table(
                    ("id", "title", "location", "owner", "why hardening"),
                    [
                        (
                            f.id,
                            f.title,
                            _where(f),
                            f.owner_hint or "-",
                            _first_sentence(f.rationale),
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
                            str(e.severity),
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
    overdue: Counter[Severity] = Counter()
    to_resolve: defaultdict[Severity, list[int]] = defaultdict(list)
    teams: defaultdict[str, list[tuple[Severity, int]]] = defaultdict(list)
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
        if resolved:
            if clock.resolved_at is None:
                counts["resolved_unclocked"] += 1
                continue
            counts["resolved_met" if clock.resolved_at <= due else "resolved_breached"] += 1
            to_resolve[severity].append((clock.resolved_at - start).days)
        elif due < as_of:
            late = (as_of - due).days
            counts["open_overdue"] += 1
            overdue[severity] += 1
            for team in owners or (_UNASSIGNED,):
                teams[team].append((severity, late))
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
            sorted(escalations, key=lambda e: (_RANK[str(e.severity)], -e.days_overdue))[
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
            "rules": [
                {
                    "id": c,
                    "name": c.replace("-", " ").title().replace(" ", ""),
                    "shortDescription": {"text": f"Finding category: {c}"},
                    "properties": {"tags": ["security", c]},
                }
                for c in categories
            ],
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
    severity = str(view.effective_severity)
    level, security_severity = _SARIF_LEVEL.get(severity, ("note", "0.5"))
    disposition = view.disposition
    properties: dict[str, Any] = {
        "security-severity": security_severity,
        "traust/severity": severity,
        "traust/validity": (disposition.validity if disposition else None) or "not_verified",
    }
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
    suppressions = [
        {"kind": "external", "status": "accepted", "justification": f"traust disposition: {why}"}
        for said, why in (
            (disposition and disposition.validity == "false_positive", "validity=false_positive"),
            (disposition and disposition.resolution == "risk_accepted", "resolution=risk_accepted"),
        )
        if said
    ]
    if suppressions:
        result["suppressions"] = suppressions
    if disposition is not None and disposition.resolution == "resolved":
        result["baselineState"] = "absent"
    return result


class OscalExport(_StubView):
    name, replaces = ViewName.OSCAL, "run_compliance_check.export_oscal"
