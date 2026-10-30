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
    InsecurePattern,
    InsecurePatternCut,
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
        repository_url=API, path="q.go", line_start=3, line_end=3, symbol="handler"
    )
    assert upstream == InsecurePatternCut(
        ownership=UPSTREAM,
        patterns=(
            InsecurePattern(
                cwe="CWE-89",
                repositories=1,
                occurrences=1,
                severities=SeverityCounts(low=1),
                examples=(
                    PatternExample(
                        repository_url=LIB,
                        path="l.go",
                        line_start=3,
                        line_end=3,
                        symbol="handler",
                    ),
                ),
            ),
        ),
    )


def test_a_product_scope_keeps_only_its_repositories(context: Context, engine: Engine) -> None:
    oss = corpus(context, engine)
    cuts = patterns(context, ViewFilter(product_ids=(oss.id,))).cuts
    assert [(c.ownership, [p.cwe for p in c.patterns]) for c in cuts] == [(UPSTREAM, ["CWE-89"])]


def test_re_reports_keep_the_highest_severity_and_unlocated_findings_collapse(
    context: Context, engine: Engine
) -> None:
    """A re-reported (repository, path) counts once and keeps its highest severity whatever
    the read order; findings without a CWE count once per (repository, path); a finding with
    no location shares the repository's empty path, as the retired builder's
    (repo, cwe, path) key did."""
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
    assert (pattern.occurrences, pattern.severities) == (2, SeverityCounts(critical=1, medium=1))


def test_an_empty_portfolio_has_no_cuts(context: Context) -> None:
    assert patterns(context).cuts == ()


def test_the_report_lists_each_class_with_its_top_patterns(
    context: Context, engine: Engine
) -> None:
    corpus(context, engine)
    md = context.services().insight.publish(ViewName.INSECURE_PATTERNS, ViewFilter()).markdown
    assert "## owned: top 25 patterns (1 occurrence(s) without a CWE)" in md
    assert "| CWE-89 | - | 2 | 3 | 1 | 2 | 0 | 0 | 0 | 0 |" in md
    assert f"{API} · q.go:3 · handler" in md
    assert "## upstream: top 25 patterns" in md
