"""The insecure-patterns view (harnessing/insecure-patterns build_insecure_patterns.py, traust
fabdb13): current findings grouped by primary CWE per ownership class, through Context on SQLite
and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.models.insight import (
    InsecurePatterns,
    PatternExample,
    SeverityCounts,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

DAY = timedelta(days=1)
HUMAN = "human:analyst@example.com"
OWNED, UPSTREAM = OwnershipClass.OWNED, OwnershipClass.UPSTREAM
SVC, LIB, API = (f"https://github.com/example-org/{n}" for n in ("svc", "lib", "api"))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def corpus(context: Context, engine: Engine) -> Any:
    """Owned `svc` and `api`, upstream `lib`: CWE-89 in two owned repositories (one restated
    on a second path, one re-reported on the same path, one a false positive), CWE-79 in one,
    a finding without a CWE, and CWE-89 upstream."""
    portfolio = context.services().portfolio
    core, _ = portfolio.register_corpus_product(ProductSlug.parse("core"), "Core", OWNED, "core")
    oss, _ = portfolio.register_corpus_product(ProductSlug.parse("oss"), "Oss", UPSTREAM, "oss")
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        sql, xss = s.cwe(identifier="CWE-89"), s.cwe(identifier="CWE-79")

        def report(url: str, product: Any, *findings: tuple[str | None, str, str, dict[str, Any]]):
            repo = s.repository(url=url)
            head = s.repository_ref(repo, is_default=True)
            s.component(s.release(product), head)
            assessment = s.assessment(head, kind="secure-code", occurred_at=T0)
            for cwe, path, severity, decided in findings:
                finding = s.finding(repo, title=f"{cwe} in {path}")
                if cwe is not None:
                    s.finding_cwe(finding, sql if cwe == "CWE-89" else xss)
                occurrence = s.occurrence(finding, assessment, severity=severity)
                s.location(occurrence, path=path, line_start=3, line_end=3, symbol="handler")
                if decided:
                    s.decision(finding, actor=HUMAN, occurred_at=T0 + DAY, **decided)

        report(
            SVC,
            core,
            ("CWE-89", "a.go", "high", {}),
            ("CWE-89", "b.go", "critical", {}),
            ("CWE-89", "b.go", "critical", {}),
            ("CWE-89", "c.go", "high", {"validity": "false_positive"}),
            ("CWE-79", "web.go", "medium", {}),
            (None, "d.go", "low", {}),
        )
        report(API, core, ("CWE-89", "q.go", "high", {}))
        report(LIB, oss, ("CWE-89", "l.go", "low", {}))
        uow.commit()
    return oss


def patterns(context: Context, scope: ViewFilter | None = None) -> InsecurePatterns:
    built = context.services().insight.build(ViewName.INSECURE_PATTERNS, scope or ViewFilter())
    assert isinstance(built, InsecurePatterns)
    return built


def test_patterns_rank_by_repositories_then_occurrences_per_ownership_class(
    context: Context, engine: Engine
) -> None:
    corpus(context, engine)
    owned, upstream = patterns(context).cuts
    assert owned.ownership is OWNED
    assert owned.without_cwe == 1
    assert [(p.cwe, p.repositories, p.occurrences) for p in owned.patterns] == [
        ("CWE-89", 2, 3),
        ("CWE-79", 1, 1),
    ]
    assert owned.patterns[0].severities == SeverityCounts(high=2, critical=1)
    assert owned.patterns[0].examples[0] == PatternExample(
        repository_url=SVC, path="b.go", line_start=3, line_end=3, symbol="handler"
    )
    assert upstream.ownership is UPSTREAM
    assert (upstream.total_findings, upstream.code_findings) == (1, 1)
    pattern = upstream.patterns[0]
    assert (pattern.cwe, pattern.repositories, pattern.occurrences) == ("CWE-89", 1, 1)
    assert pattern.severities == SeverityCounts(low=1)
    assert pattern.asvs == "V1.2"
    assert pattern.name == "SQL Injection"


def test_a_product_scope_keeps_only_its_repositories(context: Context, engine: Engine) -> None:
    oss = corpus(context, engine)
    cuts = patterns(context, ViewFilter(product_ids=(oss.id,))).cuts
    assert [(c.ownership, [p.cwe for p in c.patterns]) for c in cuts] == [(UPSTREAM, ["CWE-89"])]


def test_re_reports_keep_highest_severity_and_unlocated_findings_are_excluded(
    context: Context, engine: Engine
) -> None:
    """Repeated paths collapse; a missing source path and language is not code evidence."""
    portfolio = context.services().portfolio
    core, _ = portfolio.register_corpus_product(ProductSlug.parse("core"), "Core", OWNED, "core")
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        sql = s.cwe(identifier="CWE-89")
        repo = s.repository(url=SVC)
        head = s.repository_ref(repo, is_default=True)
        s.component(s.release(core), head)
        assessment = s.assessment(head, kind="secure-code", occurred_at=T0)

        def occur(cwe: str | None, path: str | None, severity: str) -> None:
            finding = s.finding(repo, title=f"{cwe or 'no-cwe'} in {path or 'unlocated'}")
            if cwe:
                s.finding_cwe(finding, sql)
            occurrence = s.occurrence(finding, assessment, severity=severity)
            if path is not None:
                s.location(occurrence, path=path, line_start=3, line_end=3, symbol="handler")

        occur("CWE-89", "b.go", "high")
        occur("CWE-89", "b.go", "critical")
        occur(None, "d.go", "low")
        occur(None, "d.go", "low")
        occur("CWE-89", None, "medium")
        uow.commit()
    owned = patterns(context).cuts[0]
    assert owned.without_cwe == 1
    pattern = owned.patterns[0]
    assert (pattern.occurrences, pattern.severities) == (1, SeverityCounts(critical=1))
    assert owned.excluded_non_code == 1


def test_an_empty_portfolio_has_no_cuts(context: Context) -> None:
    assert patterns(context).cuts == ()


def test_published_report_carries_metadata_examples_and_reconcilable_population(
    context: Context, engine: Engine, tmp_path: Path
) -> None:
    corpus(context, engine)
    insight = context.services().insight
    report = insight.report(ViewName.INSECURE_PATTERNS, ViewFilter())
    ranked = [
        section.table
        for section in report.sections
        if section.table and section.table.columns[0] == "cwe"
    ]
    assert [len(table.rows) for table in ranked] == [2, 1]
    assert ranked[0].rows[0][:5] == ("CWE-89", "SQL Injection", "V1.2", "2", "3")
    model = patterns(context)
    assert model.population.repositories == 3
    assert len(model.population.roots) == 2
    owned = model.cuts[0]
    assert (owned.total_findings, owned.code_findings, owned.false_positives) == (7, 6, 1)
    published = insight.publish(ViewName.INSECURE_PATTERNS, ViewFilter())
    (tmp_path / "insecure-patterns.html").write_text(published.html)
    (tmp_path / "insecure-patterns.md").write_text(published.markdown)
    (tmp_path / "insecure-patterns.json").write_text(published.model.model_dump_json(indent=2))


def test_code_filter_metadata_and_trend_replay_the_same_scoped_population(
    context: Context, engine: Engine
) -> None:
    from traust_core.v1.models.common import TimeWindow

    product, _ = context.services().portfolio.register_corpus_product(
        ProductSlug.parse("app"), "Application", OWNED, "app"
    )
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=SVC)
        head = seed.repository_ref(repo, is_default=True)
        seed.component(seed.release(product), head)
        first = seed.assessment(head, occurred_at=T0)
        later = seed.assessment(head, occurred_at=T0 + 10 * DAY)
        future = seed.assessment(head, occurred_at=T0 + 30 * DAY)
        sql, xss, validation = (
            seed.cwe(identifier=identifier) for identifier in ("CWE-89", "CWE-79", "CWE-20")
        )
        old = seed.finding(repo)
        seed.finding_cwe(old, sql)
        seed.location(seed.occurrence(old, first), path="old.go")
        seed.decision(old, actor=HUMAN, validity="false_positive", occurred_at=T0 + 15 * DAY)
        config = seed.finding(repo)
        seed.finding_cwe(config, validation)
        seed.location(seed.occurrence(config, first), path="deploy/config.yaml", language="yaml")
        unknown = seed.finding(repo)
        seed.finding_cwe(unknown, validation)
        seed.occurrence(unknown, first)
        source = seed.finding(repo)
        seed.finding_cwe(source, xss)
        seed.location(seed.occurrence(source, later), path="web.go")
        mixed = seed.finding(repo)
        seed.finding_cwe(mixed, sql)
        seed.finding_cwe(mixed, validation)
        occurrence = seed.occurrence(mixed, later)
        seed.location(occurrence, path="deploy/values.yaml", language="yaml")
        seed.location(occurrence, path="a-values.yaml", language="yaml")
        seed.location(
            occurrence, path="bin/server", language="go", line_start=9, line_end=9, symbol="handle"
        )
        seed.finding_label(mixed, taxonomy="asvs", label="V8.3")
        unseen = seed.finding(repo)
        seed.finding_cwe(unseen, validation)
        seed.location(seed.occurrence(unseen, future), path="future.go")
        uow.commit()
    scope = ViewFilter(
        product_ids=(product.id,),
        window=TimeWindow(start=T0 + 10 * DAY, end=T0 + 20 * DAY),
    )
    result = patterns(context, scope)
    cut = result.cuts[0]
    assert (cut.total_findings, cut.code_findings, cut.false_positives, cut.excluded_non_code) == (
        5,
        2,
        1,
        2,
    )
    assert {pattern.cwe for pattern in cut.patterns} == {"CWE-79", "CWE-20"}
    mixed_pattern = next(pattern for pattern in cut.patterns if pattern.cwe == "CWE-20")
    assert mixed_pattern.co_cwes == ("CWE-89",)
    assert mixed_pattern.asvs == "V8.3"
    assert mixed_pattern.asvs_name is None
    assert {example.path for example in mixed_pattern.examples} == {"bin/server"}
    assert {
        (example.line_start, example.line_end, example.symbol) for example in mixed_pattern.examples
    } == {(9, 9, "handle")}
    trend = result.trends["owned"]
    assert (
        trend.code_findings,
        trend.previous_code_findings,
        trend.distinct_cwes,
        trend.previous_distinct_cwes,
    ) == (2, 1, 2, 1)
    assert trend.compared_at == T0 + 10 * DAY - timedelta(microseconds=1)


def test_examples_are_severity_ranked_and_duplicate_hits_keep_all_cotags(
    context: Context, engine: Engine
) -> None:
    product, _ = context.services().portfolio.register_corpus_product(
        ProductSlug.parse("examples"), "Examples", OWNED, "examples"
    )
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url=SVC)
        head = seed.repository_ref(repository, is_default=True)
        seed.component(seed.release(product), head)
        assessment = seed.assessment(head, occurred_at=T0)
        primary = seed.cwe(identifier="CWE-20")
        xss, sql = seed.cwe(identifier="CWE-79"), seed.cwe(identifier="CWE-89")
        for index in range(8):
            finding = seed.finding(repository)
            seed.finding_cwe(finding, primary)
            occurrence = seed.occurrence(
                finding, assessment, severity="critical" if index == 7 else "low"
            )
            seed.location(occurrence, path=f"source-{index}.go", symbol=f"handler{index}")
        for secondary, severity in ((xss, "high"), (sql, "medium")):
            finding = seed.finding(repository)
            seed.finding_cwe(finding, primary)
            seed.finding_cwe(finding, secondary)
            seed.location(
                seed.occurrence(finding, assessment, severity=severity), path="source-0.go"
            )
        uow.commit()
    pattern = patterns(context).cuts[0].patterns[0]
    assert pattern.occurrences == 8
    assert pattern.co_cwes == ("CWE-79", "CWE-89")
    assert pattern.severities == SeverityCounts(critical=1, high=1, low=6)
    assert len(pattern.examples) == 6
    assert pattern.examples[0].symbol == "handler7"
    assert pattern.examples[1].path == "source-0.go"
    assert pattern.repository_urls == (SVC,)
