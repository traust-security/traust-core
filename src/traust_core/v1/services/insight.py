from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, time
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

from traust_core.v1.errors import ConfigError, TraustError, ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import every_item
from traust_core.v1.models.findings import FindingFilter, FindingState, FindingView, Location
from traust_core.v1.models.insight import (
    FindingsRollup,
    FindingTally,
    ProductRollup,
    RefreshResult,
    RenderedView,
    RepositoryRollup,
    SeverityCounts,
    TopFinding,
    ViewFilter,
    ViewModel,
    ViewName,
)
from traust_core.v1.models.inventory import Repository, RepositoryFilter
from traust_core.v1.models.vocabulary import DispositionAssurance
from traust_core.v1.providers.clock import Clock
from traust_core.v1.rendering import HtmlRenderer, MarkdownRenderer, Report, Section, Table, inline
from traust_core.v1.services.provider_catalog import core_version

if TYPE_CHECKING:
    from traust_core.v1.services.findings import FindingService
    from traust_core.v1.services.portfolio import PortfolioService

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
        """Render each view (all registered when None); a view that fails doesn't stop the rest.
        A ConfigError is the deployment's, not one view's, so it stops the refresh."""
        names = list(self._views) if views is None else list(dict.fromkeys(views))
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
        products = [self._portfolio.get_product(p) for p in dict.fromkeys(filter.product_ids)]
        shipped = {
            p.id: {r.repository_id for r in self._portfolio.list_product_refs(p.id)}  # type: ignore[arg-type]
            for p in products
        }
        repositories = sorted(self._repositories(filter, shipped), key=lambda r: r.url)
        views = {r.id: self._views(r.id, filter.as_of) for r in repositories}  # type: ignore[arg-type]
        urls = {r.id: r.url for r in repositories}
        everything = [v for found in views.values() for v in found]
        return FindingsRollup(
            as_of=filter.as_of,
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
                        sorted(
                            Counter(_category(v) for v in views[r.id] if _is(v, _HARDENING)).items()
                        )
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

    def _views(self, repository_id: UUID, as_of: datetime | None) -> list[FindingView]:
        query = FindingFilter(repository_id=repository_id, as_of=as_of)
        return self._findings.all(query)

    def _repositories(
        self, filter: ViewFilter, in_product: dict[Any, set[UUID]]
    ) -> list[Repository]:
        if not (filter.product_ids or filter.team_ids):
            return list(every_item(lambda page: self._portfolio.list_repositories(_ALL, page)))
        wanted = {r for repos in in_product.values() for r in repos} | {
            r
            for t in dict.fromkeys(filter.team_ids)
            for r in self._portfolio.list_owned_repositories(t, filter.as_of)
        }
        return [self._portfolio.get_repository(r) for r in sorted(wanted, key=str)]

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
                    rows=tuple(
                        (
                            f.repository_url,
                            f.title,
                            str(f.severity),
                            "-" if f.cvss_score is None else str(f.cvss_score),
                            "yes" if f.execution_proven else "",
                            "-" if f.sla_due is None else f.sla_due.date().isoformat(),
                        )
                        for f in model.top
                    ),
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


class FindingsTrendView(_StubView):
    name, replaces = ViewName.FINDINGS_TREND, "findings-trends; needs FindingService.timeline"


class CoverageView(_StubView):
    name, replaces = ViewName.COVERAGE, "census; needs AssessmentService.population / coverage"


class LocView(_StubView):
    name, replaces = ViewName.LOC, "loc-dashboard; needs CodeFactsService.language_stats"


class AttackCoverageView(_StubView):
    name, replaces = (
        ViewName.ATTACK_COVERAGE,
        "attack-coverage; needs AssessmentService.threats, FindingService.summary",
    )


class ThreatRegisterView(_StubView):
    name, replaces = (
        ViewName.THREAT_REGISTER,
        "threat-register; needs AssessmentService.threats, ComplianceService.doc_variances",
    )


class ExposureView(_StubView):
    name, replaces = (
        ViewName.EXPOSURE,
        "refresh-dashboards/build_dependency_exposure; needs ExposureService.summary",
    )


class ValidationFuzzView(_StubView):
    name, replaces = (
        ViewName.VALIDATION_FUZZ,
        "validation-fuzz-dashboard; needs ValidationService.summary",
    )


class PqcView(_StubView):
    name, replaces = (
        ViewName.PQC,
        "pqc dashboard, product reports, vendor/xcrypto trackers; needs PqcService.summary",
    )


class ComplianceDashboardView(_StubView):
    name, replaces = (
        ViewName.COMPLIANCE,
        "compliance/dashboard.py; needs ComplianceService.summary / scopes",
    )


class ProgramView(_StubView):
    name, replaces = (
        ViewName.PROGRAM,
        "traust-metrics, financial-tracking; needs OpsService.timeline (series derived "
        "at points in time, never snapshotted)",
    )


class ExecutiveSummaryView(_StubView):
    name, replaces = (
        ViewName.EXECUTIVE_SUMMARY,
        "executive-summary-findings; needs AssessmentService.privileges, ExposureService.impacts",
    )


class ReviewCardView(_StubView):
    name, replaces = ViewName.REVIEW_CARD, "countersign render_*_card"


class TriageView:
    """A triage document as a report: act on these, hardening, undetermined, dropped."""

    name = ViewName.TRIAGE
    _SEVERITY = ("critical", "high", "medium", "low", "informational")

    def build(self, filter: ViewFilter) -> ViewModel:
        raise NotImplementedError("stub: a triage view over stored triage artifacts")

    def report(self, doc: TriageArtifact) -> Report:
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
