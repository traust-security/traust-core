"""InsightService doors and the findings rollup, ported from traust fabdb13
(cli/refresh_dashboards.py, generate-team-report SKILL.md step 3 and extract_findings.py)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import CLOCK, SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.findings import Disposition, Finding, FindingView, Occurrence
from traust_core.v1.models.insight import FindingsRollup, ViewFilter, ViewModel, ViewName
from traust_core.v1.models.vocabulary import (
    DispositionAssurance,
    DispositionResolution,
    Severity,
    Validity,
)
from traust_core.v1.rendering import MarkdownRenderer, Report
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import FindingsRollupView, InsightService

HUMAN = "human:analyst@example.com"


def view(
    severity: str = "high",
    validity: str | None = None,
    resolution: str | None = None,
    assurance: str = "human_reviewed",
    repository_id: UUID | None = None,
    cvss: str | None = None,
    category: str | None = None,
    title: str = "SQL injection in handler",
) -> FindingView:
    finding = Finding(
        id=uuid4(),
        repository_id=repository_id or uuid4(),
        fingerprint_algo="v3",
        fingerprint=uuid4().hex,
        title=title,
    )
    disposition = (
        None
        if validity is None and resolution is None
        else Disposition(
            finding_id=finding.id,  # type: ignore[arg-type]
            validity=validity and Validity(validity),
            resolution=resolution and DispositionResolution(resolution),
            assurance=DispositionAssurance(assurance),
        )
    )
    occurrence = Occurrence(
        finding_id=finding.id,  # type: ignore[arg-type]
        assessment_id=uuid4(),
        severity=severity,
        cvss_score=None if cvss is None else Decimal(cvss),
    )
    labels = ()
    if category:
        from traust_core.v1.models.findings import FindingLabel

        labels = (FindingLabel(finding_id=finding.id, taxonomy="category", label=category),)  # type: ignore[arg-type]
    return FindingView(
        finding=finding,
        occurrence=occurrence,
        disposition=disposition,
        effective_severity=Severity(severity),
        labels=labels,
    )


@dataclass
class FakePortfolio:
    repositories: dict[UUID, str] = field(default_factory=dict)
    products: dict[UUID, tuple[str, set[UUID]]] = field(default_factory=dict)
    teams: dict[UUID, set[UUID]] = field(default_factory=dict)

    def get_product(self, product_id: UUID) -> Any:
        if product_id not in self.products:
            raise NotFoundError(f"product {product_id}")
        slug, _ = self.products[product_id]
        return type("P", (), {"id": product_id, "slug": slug, "name": slug.title()})()

    def list_product_refs(self, product_id: UUID) -> list[Any]:
        return [type("R", (), {"repository_id": r})() for r in self.products[product_id][1]]

    def list_owned_repositories(self, team_id: UUID, as_of: datetime | None) -> list[UUID]:
        return sorted(self.teams[team_id], key=str)

    def get_repository(self, repository_id: UUID) -> Any:
        return type("Repo", (), {"id": repository_id, "url": self.repositories[repository_id]})()

    def list_repositories(self, filter: Any, page: Any) -> Any:
        from traust_core.v1.models.common import Page

        return Page(items=tuple(self.get_repository(r) for r in self.repositories))


@dataclass
class FakeFindings:
    views: list[FindingView]

    def all(self, filter: Any) -> list[FindingView]:
        return [v for v in self.views if v.finding.repository_id == filter.repository_id]


class NoThreatModels:
    def attack_scenarios(self, repository_ids: Any, as_of: Any) -> list[Any]:
        return []


def rollup(
    views: list[FindingView], portfolio: FakePortfolio, filter: ViewFilter | None = None
) -> FindingsRollup:
    return FindingsRollupView(FakeFindings(views), portfolio, NoThreatModels()).build(  # type: ignore[arg-type]
        filter or ViewFilter()
    )


def single(*views: FindingView) -> FindingsRollup:
    repo = uuid4()
    pinned = [
        v.model_copy(update={"finding": v.finding.model_copy(update={"repository_id": repo})})
        for v in views
    ]
    return rollup(pinned, FakePortfolio(repositories={repo: "https://github.com/org/a"}))


# extract_findings / SKILL.md step 3: where each finding counts.
@pytest.mark.parametrize(
    ("validity", "resolution", "bucket"),
    [
        (None, None, "open"),
        ("confirmed", None, "open"),
        ("not_verified", None, "open"),
        ("corrected", "fix_in_progress", "open"),
        ("confirmed", "regression_introduced", "open"),
        ("false_positive", None, "false_positive"),
        ("false_positive", "resolved", "false_positive"),
        ("hardening", None, "hardening"),
        ("hardening", "resolved", "resolved"),
        ("confirmed", "resolved", "resolved"),
        ("confirmed", "risk_accepted", "risk_accepted"),
    ],
)
def test_each_finding_counts_in_one_bucket(
    validity: str | None, resolution: str | None, bucket: str
) -> None:
    total = single(view(validity=validity, resolution=resolution)).total
    counts = {
        "open": total.open.total,
        "false_positive": total.false_positive,
        "hardening": total.hardening,
        "resolved": total.resolved,
        "risk_accepted": total.risk_accepted,
    }
    assert counts == {k: int(k == bucket) for k in counts}


def test_open_findings_count_by_effective_severity() -> None:
    total = single(
        view("critical"),
        view("high"),
        view("high"),
        view("medium"),
        view("low"),
        view("informational"),
    ).total
    assert (total.open.critical, total.open.high, total.open.medium) == (1, 2, 1)
    assert (total.open.low, total.open.informational, total.open.total) == (1, 1, 6)


def test_execution_proven_and_unverified_open_findings_are_badged() -> None:
    total = single(
        view(validity="confirmed", assurance="execution_proven"),
        view(),
        view(validity="not_verified", assurance="claimed"),
        view(validity="confirmed", resolution="resolved", assurance="execution_proven"),
    ).total
    assert (total.execution_proven, total.unverified) == (1, 2)


def test_top_lists_open_critical_then_high_by_cvss_descending() -> None:
    top = single(
        view("high", cvss="7.1", title="high low score"),
        view("critical", cvss="9.1", title="critical"),
        view("high", title="high no score"),
        view("high", cvss="8.8", title="high top score"),
        view("medium", cvss="9.9", title="medium"),
        view("critical", validity="false_positive", title="refuted"),
        view("high", validity="hardening", title="hardening"),
    ).top
    assert [t.title for t in top] == [
        "critical",
        "high top score",
        "high low score",
        "high no score",
    ]


def test_hardening_backlog_counts_categories_per_repository() -> None:
    model = single(
        view(validity="hardening", category="supply-chain"),
        view(validity="hardening", category="supply-chain"),
        view(validity="hardening"),
        view(category="injection"),
    )
    (repo,) = model.repositories
    assert repo.tally.hardening == 3
    assert dict(repo.hardening_categories) == {"supply-chain": 2, "uncategorized": 1}


def test_no_scope_rolls_up_every_repository() -> None:
    a, b = uuid4(), uuid4()
    model = rollup(
        [view(repository_id=a), view(repository_id=b), view(repository_id=b)],
        FakePortfolio(repositories={b: "https://github.com/org/b", a: "https://github.com/org/a"}),
    )
    assert [(r.repository_url, r.tally.open.total) for r in model.repositories] == [
        ("https://github.com/org/a", 1),
        ("https://github.com/org/b", 2),
    ]
    assert model.products == ()


def test_a_shared_repository_counts_under_each_product_and_once_in_the_total() -> None:
    shared, only_a, elsewhere = uuid4(), uuid4(), uuid4()
    pa, pb = uuid4(), uuid4()
    portfolio = FakePortfolio(
        repositories={
            shared: "https://github.com/org/shared",
            only_a: "https://github.com/org/a",
            elsewhere: "https://github.com/org/x",
        },
        products={pa: ("alpha", {shared, only_a}), pb: ("beta", {shared})},
    )
    views = [view(repository_id=shared), view(repository_id=only_a), view(repository_id=elsewhere)]
    model = rollup(views, portfolio, ViewFilter(product_ids=(pb, pa, pa)))
    assert [(p.slug, p.repositories, p.tally.open.total) for p in model.products] == [
        ("alpha", 2, 2),
        ("beta", 1, 1),
    ]
    assert model.total.open.total == 2
    assert len(model.repositories) == 2


def test_teams_and_products_scope_the_union_of_their_repositories() -> None:
    owned, shipped = uuid4(), uuid4()
    team, product = uuid4(), uuid4()
    portfolio = FakePortfolio(
        repositories={
            owned: "https://github.com/org/owned",
            shipped: "https://github.com/org/shipped",
        },
        products={product: ("alpha", {shipped})},
        teams={team: {owned}},
    )
    model = rollup(
        [view(repository_id=owned), view(repository_id=shipped)],
        portfolio,
        ViewFilter(product_ids=(product,), team_ids=(team,)),
    )
    assert model.total.open.total == 2


def test_an_unknown_product_is_not_found() -> None:
    with pytest.raises(NotFoundError):
        rollup([], FakePortfolio(), ViewFilter(product_ids=(uuid4(),)))


def test_empty_scope_renders_a_report_saying_so() -> None:
    model = rollup([], FakePortfolio())
    md = MarkdownRenderer().render(FindingsRollupView(None, None, None).report(model, T0)).decode()  # type: ignore[arg-type]
    assert "0 open" in md
    assert "_No repositories in scope._" in md
    assert "_None open._" in md


def test_report_sections_and_hostile_titles_stay_on_one_row() -> None:
    model = single(
        view("critical", cvss="9.8", title="Bad | title\n## injected"),
        view(validity="hardening", category="supply-chain"),
        view(validity="false_positive"),
    )
    md = MarkdownRenderer().render(FindingsRollupView(None, None, None).report(model, T0)).decode()  # type: ignore[arg-type]
    headings = (
        "## Summary",
        "## By repository",
        "## Critical and high findings",
        "## Hardening backlog",
    )
    assert [md.index(h) for h in headings] == sorted(md.index(h) for h in headings)
    assert "1 false positives" in md
    assert "Bad \\| title ## injected" in md
    assert "\n## injected" not in md
    assert "supply-chain 1" in md


# InsightService doors over fake views


@dataclass
class FakeView:
    name: ViewName
    error: Exception | None = None
    built: list[ViewFilter] = field(default_factory=list)

    def build(self, filter: ViewFilter) -> ViewModel:
        self.built.append(filter)
        if self.error:
            raise self.error
        return ViewModel()

    def report(self, model: Any, generated_at: datetime) -> Report:
        return Report(title=str(self.name), generated_at=generated_at)


def insight(*views: FakeView) -> InsightService:
    return InsightService(views, CLOCK)  # type: ignore[arg-type]


def test_build_returns_the_views_model_and_refuses_an_unbuilt_view() -> None:
    rollup_view = FakeView(ViewName.FINDINGS_ROLLUP)
    service = insight(rollup_view)
    assert service.build(ViewName.FINDINGS_ROLLUP, ViewFilter()) == ViewModel()
    with pytest.raises(
        ValidationError, match="'exposure' is not built; built views: findings-rollup"
    ):
        service.build(ViewName.EXPOSURE, ViewFilter())


def test_report_is_dated_as_of_the_filter_else_now() -> None:
    service = insight(FakeView(ViewName.FINDINGS_ROLLUP))
    assert service.report(ViewName.FINDINGS_ROLLUP, ViewFilter()).generated_at == CLOCK.now()
    assert service.report(ViewName.FINDINGS_ROLLUP, ViewFilter(as_of=T0)).generated_at == T0


def test_publish_returns_the_model_and_its_renders_and_stores_nothing() -> None:
    rendered = insight(FakeView(ViewName.FINDINGS_ROLLUP)).publish(
        ViewName.FINDINGS_ROLLUP, ViewFilter(as_of=T0)
    )
    assert (rendered.view, rendered.stem, rendered.model) == (
        ViewName.FINDINGS_ROLLUP,
        "findings-rollup",
        ViewModel(),
    )
    assert rendered.markdown.startswith("# findings-rollup\n")
    assert rendered.html.startswith("<!DOCTYPE html>")


def test_refresh_renders_every_built_view_and_collects_failures() -> None:
    ok, broken = (
        FakeView(ViewName.FINDINGS_ROLLUP),
        FakeView(ViewName.LOC, NotFoundError("product x")),
    )
    result = insight(ok, broken).refresh(None, ViewFilter())
    assert list(result.rendered) == [ViewName.FINDINGS_ROLLUP]
    assert result.failed == {ViewName.LOC: "NotFoundError: product x"}


def test_refresh_runs_only_the_named_views_once_each() -> None:
    a, b = FakeView(ViewName.FINDINGS_ROLLUP), FakeView(ViewName.LOC)
    result = insight(a, b).refresh([ViewName.LOC, ViewName.LOC], ViewFilter())
    assert list(result.rendered) == [ViewName.LOC]
    assert (len(a.built), len(b.built)) == (0, 1)


def test_refresh_checks_every_name_before_running_any() -> None:
    a = FakeView(ViewName.FINDINGS_ROLLUP)
    with pytest.raises(ValidationError, match="'pqc' is not built"):
        insight(a).refresh([ViewName.FINDINGS_ROLLUP, ViewName.PQC], ViewFilter())
    assert a.built == []


def test_refresh_stops_on_a_deployment_config_error() -> None:
    a = FakeView(ViewName.FINDINGS_ROLLUP, ConfigError("no rating config"))
    b = FakeView(ViewName.LOC)
    with pytest.raises(ConfigError, match="no rating config"):
        insight(a, b).refresh(None, ViewFilter())
    assert b.built == []


@dataclass
class WindowedView(FakeView):
    windowed: bool = True


def test_a_windowed_view_refreshed_without_a_window_covers_the_month_of_as_of() -> None:
    windowed, plain = WindowedView(ViewName.SPEND), FakeView(ViewName.LOC)
    insight(windowed, plain).refresh(None, ViewFilter(as_of=T0))
    assert windowed.built[0].window == TimeWindow.month_of(T0)
    assert plain.built[0].window is None
    insight(windowed).refresh(None, ViewFilter())
    assert windowed.built[1].window == TimeWindow.month_of(CLOCK.now())


def test_a_windowed_view_keeps_the_window_it_is_given() -> None:
    windowed = WindowedView(ViewName.PROGRAM)
    given = TimeWindow(start=T0 - timedelta(days=7), end=T0)
    insight(windowed).refresh(None, ViewFilter(window=given))
    assert windowed.built[0].window == given


def test_refresh_of_no_views_renders_nothing() -> None:
    result = insight(FakeView(ViewName.FINDINGS_ROLLUP)).refresh([], ViewFilter())
    assert (dict(result.rendered), dict(result.failed)) == ({}, {})


# The real path: Context.services() on SQLite and Postgres.


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    return ctx


def test_rollup_over_stored_findings(context: Context, engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product(slug="alpha", name="Alpha")
        release = seed.release(product)
        repo = seed.repository(url="https://github.com/example-org/svc")
        other = seed.repository(url="https://github.com/example-org/elsewhere")
        ref = seed.repository_ref(repo)
        seed.component(release, ref)
        audit = seed.assessment(ref)
        validation = seed.assessment(ref, kind="validation", assessor="skill:validate")
        proven = seed.finding(repo, title="Proven RCE")
        seed.occurrence(proven, audit, severity="critical", cvss_score=Decimal("9.8"))
        seed.decision(
            proven,
            assessment_id=validation.id,
            validity="confirmed",
            evidence_grade="E0",
            actor=None,
        )
        refuted = seed.finding(repo, title="Refuted")
        seed.occurrence(refuted, audit, severity="high")
        seed.decision(refuted, validity="false_positive", actor=HUMAN)
        fixed = seed.finding(repo, title="Fixed")
        seed.occurrence(fixed, audit, severity="high")
        seed.decision(fixed, validity="confirmed", resolution="resolved", actor=HUMAN)
        seed.occurrence(seed.finding(repo, title="Unreviewed"), audit, severity="medium")
        seed.occurrence(
            seed.finding(other, title="Out of scope"),
            seed.assessment(seed.repository_ref(other)),
            severity="critical",
        )
        team = seed.team(name="platform")
        seed.ownership(other, team)
        seed.ownership(
            repo, team, valid_from=T0 - timedelta(days=30), valid_to=T0 - timedelta(days=1)
        )
        uow.commit()

    insight_service = context.services().insight
    model = insight_service.build(ViewName.FINDINGS_ROLLUP, ViewFilter(product_ids=(product.id,)))  # type: ignore[arg-type]
    assert isinstance(model, FindingsRollup)
    t = model.total
    assert (t.open.critical, t.open.medium, t.open.total) == (1, 1, 2)
    assert (t.false_positive, t.resolved, t.execution_proven, t.unverified) == (1, 1, 1, 1)
    assert [(p.slug, p.repositories) for p in model.products] == [("alpha", 1)]
    assert [(f.title, f.cvss_score, f.execution_proven) for f in model.top] == [
        ("Proven RCE", Decimal("9.8"), True)
    ]

    by_team = insight_service.build(ViewName.FINDINGS_ROLLUP, ViewFilter(team_ids=(team.id,)))  # type: ignore[arg-type]
    assert [r.repository_url for r in by_team.repositories] == [
        "https://github.com/example-org/elsewhere"
    ]  # type: ignore[attr-defined]
    earlier = insight_service.build(
        ViewName.FINDINGS_ROLLUP,
        ViewFilter(team_ids=(team.id,), as_of=T0 - timedelta(days=2)),  # type: ignore[arg-type]
    )
    assert [r.repository_url for r in earlier.repositories] == [
        "https://github.com/example-org/svc"
    ]  # type: ignore[attr-defined]

    md = (
        MarkdownRenderer()
        .render(insight_service.report(ViewName.FINDINGS_ROLLUP, ViewFilter()))
        .decode()
    )
    assert "https://github.com/example-org/elsewhere" in md


def test_an_unknown_team_is_not_found(context: Context) -> None:
    with pytest.raises(NotFoundError):
        context.services().insight.build(ViewName.FINDINGS_ROLLUP, ViewFilter(team_ids=(uuid4(),)))


def test_refresh_through_context_renders_the_rollup(context: Context, engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product = seed.product(slug="alpha", name="Alpha <b>")
        repo = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(repo)
        seed.component(seed.release(product), ref)
        seed.occurrence(seed.finding(repo, title="<script>x</script>"), seed.assessment(ref))
        uow.commit()
    result = context.services().insight.refresh(None, ViewFilter(product_ids=(product.id,)))  # type: ignore[arg-type]
    rendered = result.rendered[ViewName.FINDINGS_ROLLUP]
    assert rendered.stem == "findings-rollup-alpha-b"
    assert "<script>" not in rendered.html
    assert "&lt;script&gt;x&lt;/script&gt;" in rendered.html
    assert "default-src 'none'" in rendered.html
    assert rendered.model.total.open.high == 1  # type: ignore[attr-defined]
    assert json.loads(rendered.model_dump_json())["model"]["total"]["open"]["high"] == 1


def test_a_trend_is_the_rollup_at_earlier_points_in_time(context: Context, engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        ref = seed.repository_ref(repo)
        early = seed.assessment(ref, occurred_at=T0)
        late = seed.assessment(ref, occurred_at=T0 + timedelta(days=10))
        fixed = seed.finding(repo, title="Fixed later")
        seed.occurrence(fixed, early, severity="critical")
        seed.decision(
            fixed,
            validity="confirmed",
            resolution="resolved",
            actor=HUMAN,
            occurred_at=T0 + timedelta(days=5),
        )
        seed.occurrence(seed.finding(repo, title="Found later"), late, severity="high")
        uow.commit()
    insight_service = context.services().insight

    def at(day: int) -> tuple[int, int, int]:
        model = insight_service.build(
            ViewName.FINDINGS_ROLLUP, ViewFilter(as_of=T0 + timedelta(days=day, hours=1))
        )
        t = model.total  # type: ignore[attr-defined]
        return (t.open.critical, t.open.high, t.resolved)

    assert [at(0), at(5), at(10)] == [(1, 0, 0), (0, 0, 1), (0, 1, 1)]
