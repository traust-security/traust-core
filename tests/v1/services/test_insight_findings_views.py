"""The findings trend's directions, coverage and accepted-risk register, the executive summary's
remediation, population and hardening sections, and the team report's attack scenarios; ported
from traust fabdb13 (build_trends.py, build_executive_summary.py, generate-team-report step 3b)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import FakeFindings, FakePortfolio, view
from traust_core.v1.context import Config, Context
from traust_core.v1.models.assessment import AttackScenario
from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.insight import (
    FindingsTrend,
    TrendDirection,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.vocabulary import Severity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import FindingsRollupView, _direction

HUMAN = "human:analyst@example.com"
DAY = timedelta(days=1)


@pytest.mark.parametrize(
    ("series", "good_down", "expected"),
    [
        ([4.0], True, TrendDirection(metric="m", last=4.0)),
        ([0.0, 0.0], True, TrendDirection(metric="m", last=0.0, baseline=0.0)),
        ([10.0, 10.5], True, TrendDirection(metric="m", last=10.5, baseline=10.0, change_pct=5.0)),
        (
            [9.0, 1.0, 2.0, 3.0, 4.0],
            True,
            TrendDirection(
                metric="m", last=4.0, baseline=2.0, change_pct=100.0, rising=True, worsening=True
            ),
        ),
        (
            [0.0, 3.0],
            False,
            TrendDirection(metric="m", last=3.0, baseline=0.0, rising=True, worsening=False),
        ),
        (
            [100.0, 50.0, 50.0],
            False,
            TrendDirection(
                metric="m", last=50.0, baseline=75.0, change_pct=-33.3, rising=False, worsening=True
            ),
        ),
        (
            [8.0, 4.0],
            True,
            TrendDirection(metric="m", last=4.0, baseline=8.0, change_pct=-50.0, rising=False),
        ),
    ],
)
def test_direction_is_the_last_bucket_against_up_to_three_before_with_a_dead_band(
    series: list[float], good_down: bool, expected: TrendDirection
) -> None:
    assert _direction("m", series, good_down) == expected


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def seed(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        api = s.repository(url="https://github.com/example-org/api")
        s.repository(url="https://github.com/example-org/quiet")
        early = s.assessment(s.repository_ref(svc), occurred_at=T0)
        accepted = s.finding(svc, title="Accepted debug endpoint")
        s.occurrence(accepted, early, severity="critical")
        s.decision(
            accepted,
            validity="confirmed",
            resolution="risk_accepted",
            actor=HUMAN,
            rationale="compensating network policy " * 10,
            occurred_at=T0 + 2 * DAY,
        )
        refuted = s.finding(svc, title="Refuted later")
        s.occurrence(refuted, early, severity="high")
        s.decision(refuted, validity="false_positive", actor=HUMAN, occurred_at=T0 + 9 * DAY)
        later = s.assessment(s.repository_ref(api), occurred_at=T0 + 8 * DAY)
        s.occurrence(s.finding(api, title="Found later"), later, severity="high")
        uow.commit()


def test_the_trend_carries_coverage_fp_rate_directions_and_the_register(
    context: Context, engine: Engine
) -> None:
    seed(engine)
    trend = context.services().insight.build(
        ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK)
    )
    assert isinstance(trend, FindingsTrend)
    assert [
        (p.reported, p.dispositioned, p.coverage, p.decisions, p.fp_rate, p.accepted_risk_index)
        for p in trend.points
    ] == [(1, 1, 100.0, 1, 0.0, 9.5), (2, 1, 50.0, 1, 100.0, 9.5), (2, 1, 50.0, 0, 0.0, 9.5)]
    directions = {d.metric: d for d in trend.directions}
    assert list(directions) == [
        "open", "risk_index", "new", "velocity", "mttr", "fp_rate", "regressions", "accepted",
        "accepted_risk_index", "hardening", "coverage",
    ]  # fmt: skip
    assert directions["open"].rising is None
    assert (directions["coverage"].rising, directions["coverage"].worsening) == (False, True)
    (entry,) = trend.accepted
    assert (entry.title, entry.severity, entry.accepted_by) == (
        "Accepted debug endpoint",
        Severity.CRITICAL,
        HUMAN,
    )
    assert entry.accepted_at == T0 + 2 * DAY
    assert entry.rationale is not None and len(entry.rationale) == 160


def test_the_trend_report_reads_direction_coverage_population_and_register(
    context: Context, engine: Engine
) -> None:
    seed(engine)
    md = (
        context.services()
        .insight.publish(ViewName.FINDINGS_TREND, ViewFilter(bucket=TimeBucket.WEEK))
        .markdown
    )
    assert "Ledger coverage: 1 of 2 reported repositories (50.0%)" in md
    assert "| Ledger coverage (%) | 50.0 | 75.0 | -33.3% | ↓ ⚠ worsening |" in md
    assert "| Open findings | 1.0 | 1.0 | +0.0% | → flat |" in md
    assert "| In scope | 3 |" in md and "| With a decision recorded | 1 |" in md
    assert "1 findings accepted, unfixed and unmitigated; accepted risk index 9.5" in md
    assert "| https://github.com/example-org/svc | Accepted debug endpoint | critical |" in md


def test_an_empty_trend_has_no_directions_or_register(context: Context) -> None:
    rendered = context.services().insight.publish(ViewName.FINDINGS_TREND, ViewFilter())
    assert (rendered.model.directions, rendered.model.accepted) == ((), ())  # type: ignore[attr-defined]
    assert "| With findings reported | 0 |" in rendered.markdown
    assert "accepted risk index 0.0" in rendered.markdown


def test_the_executive_summary_reports_remediation_population_and_hardening_backlogs(
    context: Context, engine: Engine
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        s.repository(url="https://github.com/example-org/quiet")
        audit = s.assessment(s.repository_ref(svc), occurred_at=T0)
        for title, severity, decided in (
            ("Fixed", "high", {"validity": "confirmed", "resolution": "resolved"}),
            ("Accepted", "low", {"validity": "confirmed", "resolution": "risk_accepted"}),
            ("Refuted", "medium", {"validity": "false_positive"}),
            ("Debug port", "low", {"validity": "hardening"}),
            ("Open", "critical", None),
        ):
            finding = s.finding(svc, title=title)
            s.occurrence(finding, audit, severity=severity)
            if decided:
                s.decision(finding, actor=HUMAN, occurred_at=T0 + DAY, **decided)
        uow.commit()
    md = context.services().insight.publish(ViewName.EXECUTIVE_SUMMARY, ViewFilter()).markdown
    assert (
        "1 of 2 repositories have a decision recorded. Across their 4 findings (false positives "
        "excluded): 2 closed (resolved or risk accepted), a closure rate of 50.0%. Findings "
        "remediated: 1 resolved (0 critical, 1 high, 0 medium, 0 low, 0 informational)."
    ) in md
    assert "| With findings reported | 1 |" in md
    assert "## Largest hardening backlogs (top 10 of 1)" in md
    assert "| https://github.com/example-org/svc | 1 |" in md


def test_the_executive_summary_with_nothing_decided_has_no_closure_rate(context: Context) -> None:
    md = context.services().insight.publish(ViewName.EXECUTIVE_SUMMARY, ViewFilter()).markdown
    assert "0 of 0 repositories have a decision recorded. Across their 0 findings" in md
    assert "closure rate" not in md
    assert "## Largest hardening backlogs (top 10 of 0)" in md


class ThreatModels:
    def __init__(self, *scenarios: AttackScenario) -> None:
        self.scenarios = scenarios
        self.asked: list[Any] = []

    def attack_scenarios(self, repository_ids: Any, as_of: Any) -> list[AttackScenario]:
        self.asked.append((list(repository_ids), as_of))
        return list(self.scenarios)


def test_the_team_report_lifts_attack_scenarios_verbatim_for_a_scope() -> None:
    repo, product = uuid4(), uuid4()
    portfolio = FakePortfolio(
        repositories={repo: "https://github.com/example-org/svc"},
        products={product: ("alpha", {repo})},
    )
    scenario = AttackScenario(
        assessment_id=uuid4(),
        repository_id=repo,
        label="T3",
        threat="Tenant escape",
        steps=("An attacker signs up.", "## Not a heading\nThen pivots."),
    )
    assessment = ThreatModels(scenario)
    rollup_view = FindingsRollupView(
        FakeFindings([view(repository_id=repo)]), portfolio, assessment
    )  # type: ignore[arg-type]

    model = rollup_view.build(ViewFilter(product_ids=(product,)))
    md = MarkdownRenderer().render(rollup_view.report(model, T0)).decode()

    assert model.attack_scenarios == (scenario,)
    assert assessment.asked == [([repo], None)]
    assert "## Attack scenarios: https://github.com/example-org/svc T3, Tenant escape" in md
    assert "> An attacker signs up.\n\n> ## Not a heading Then pivots." in md
    assert "_From the repository's latest threat model (T3)._" in md


def test_the_fleet_rollup_reads_no_threat_models() -> None:
    repo = uuid4()
    assessment = ThreatModels()
    portfolio = FakePortfolio(repositories={repo: "https://github.com/example-org/svc"})
    model = FindingsRollupView(FakeFindings([]), portfolio, assessment).build(ViewFilter())  # type: ignore[arg-type]
    assert (model.attack_scenarios, assessment.asked) == ((), [])


def test_the_rollup_counts_findings_by_category_label() -> None:
    repo, other = uuid4(), uuid4()
    portfolio = FakePortfolio(
        repositories={
            repo: "https://github.com/example-org/svc",
            other: "https://github.com/example-org/lib",
        }
    )
    findings = FakeFindings(
        [
            view(repository_id=repo, category="authorization", severity="critical"),
            view(repository_id=repo, category="authorization", validity="false_positive"),
            view(repository_id=repo, category="tenant-isolation"),
            view(repository_id=other),
        ]
    )
    rollup_view = FindingsRollupView(findings, portfolio, ThreatModels())  # type: ignore[arg-type]

    model = rollup_view.build(ViewFilter())
    md = MarkdownRenderer().render(rollup_view.report(model, T0)).decode()

    assert [(c.key, c.findings, c.open) for c in model.categories] == [
        ("authorization", 2, 1),
        ("tenant-isolation", 1, 1),
        (None, 1, 1),
    ]
    assert "## By category" in md
    assert "| authorization | 2 | 1 | 0 | 0 | 0 | 1 |" in md


def test_a_category_scope_keeps_only_matching_findings() -> None:
    repo = uuid4()
    portfolio = FakePortfolio(repositories={repo: "https://github.com/example-org/svc"})
    findings = FakeFindings(
        [
            view(repository_id=repo, category="authorization"),
            view(repository_id=repo, category="tenant-isolation"),
            view(repository_id=repo),
        ]
    )
    rollup_view = FindingsRollupView(findings, portfolio, ThreatModels())  # type: ignore[arg-type]

    model = rollup_view.build(ViewFilter(categories=("authorization",)))

    assert [c.key for c in model.categories] == ["authorization"]
    assert model.total.open.total == 1
