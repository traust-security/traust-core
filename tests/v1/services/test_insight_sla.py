"""The SLA view through Context on SQLite and Postgres: policy profiles over FindingService's
clocks, the clock-start ladder, per-team overdue tables and the escalation digest."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.findings import FindingClock, FindingFilter
from traust_core.v1.models.insight import SlaCounts, SlaDashboard, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import SlaClockStart
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import _clock_start

POLICY = Path(__file__).parents[2] / "fixtures" / "insight" / "sla-policy.yaml"
DAY = timedelta(days=1)
HUMAN = "human:analyst@example.com"
LATER = T0 + 100 * DAY


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(LATER))
    ctx.__dict__["database"] = engine
    ctx.register_sla_policy(POLICY)
    return ctx


@dataclass
class Fleet:
    svc: UUID
    api: UUID
    crit: UUID
    filed: UUID
    filed_at: datetime


def seed(engine: Engine) -> Fleet:
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        api = s.repository(url="https://github.com/example-org/api")
        s.ownership(svc, s.team(name="payments"))
        s.ownership(svc, s.team(name="gone"), valid_to=T0 + DAY)
        refs = {repo.id: s.repository_ref(repo) for repo in (svc, api)}
        at = {
            (repo.id, day): s.assessment(refs[repo.id], occurred_at=T0 + day * DAY)
            for repo in (svc, api)
            for day in (0, 50)
        }

        def finding(repo, title, severity, day=0, cvss=None, *decisions):
            f = s.finding(repo, title=title)
            s.occurrence(f, at[(repo.id, day)], severity=severity, cvss_score=cvss)
            for when, kw in decisions:
                said = {"validity": "confirmed", "actor": HUMAN, **kw}
                s.decision(f, occurred_at=T0 + when * DAY, **said)
            return f

        crit = finding(svc, "Overdue | crit", "critical")
        filed = finding(svc, "Filed high", "high", 50)
        ref = s.finding_external_ref(filed)
        s.finding_external_ref(filed, system="forge", ref="mr-1")
        finding(api, "In SLA medium", "medium", 50)
        finding(svc, "Low with cvss", "low", 0, Decimal("5.0"))
        finding(api, "Informational", "informational")
        finding(svc, "Fixed fast", "critical", 0, None, (10, {"resolution": "resolved"}))
        finding(api, "Fixed late", "high", 0, None, (70, {"resolution": "resolved"}))
        finding(svc, "Accepted", "high", 0, None, (5, {"resolution": "risk_accepted"}))
        finding(svc, "Not real", "critical", 0, None, (1, {"validity": "false_positive"}))
        finding(svc, "Posture", "critical", 0, None, (1, {"validity": "hardening"}))
        uow.commit()
    assert ref.created_at is not None
    return Fleet(svc.id, api.id, crit.id, filed.id, ref.created_at)  # type: ignore[arg-type]


def build(context: Context, **filter: object) -> SlaDashboard:
    model = context.services().insight.build(ViewName.SLA, ViewFilter(**filter))
    assert isinstance(model, SlaDashboard)
    return model


@pytest.mark.parametrize(
    ("as_of", "profile", "counts"),
    [
        (
            LATER,
            "internal-cve",
            SlaCounts(
                open_in_sla=1,
                open_overdue=2,
                open_no_sla=1,
                accepted=1,
                resolved_met=1,
                resolved_breached=1,
                out_of_profile_scope=1,
            ),
        ),
        (
            LATER,
            "example-profile",
            SlaCounts(open_in_sla=1, open_overdue=1, out_of_profile_scope=6),
        ),
        (
            T0 + 20 * DAY,
            "internal-cve",
            SlaCounts(
                open_in_sla=2, open_no_sla=1, accepted=1, resolved_met=1, out_of_profile_scope=1
            ),
        ),
        (T0 + 20 * DAY, "example-profile", SlaCounts(open_in_sla=1, out_of_profile_scope=5)),
        (T0 - DAY, "internal-cve", SlaCounts()),
    ],
)
def test_each_profile_clocks_the_same_findings_as_of_a_point_in_time(
    context: Context, engine: Engine, as_of: datetime, profile: str, counts: SlaCounts
) -> None:
    seed(engine)
    model = build(context, as_of=as_of)
    assert [p.profile for p in model.profiles] == ["internal-cve", "example-profile"]
    assert {p.profile: p.counts for p in model.profiles}[profile] == counts
    assert model.as_of == as_of


def test_overdue_findings_land_in_the_team_table_and_the_digest(
    context: Context, engine: Engine
) -> None:
    fleet = seed(engine)
    internal, floored = build(context).profiles
    assert internal.resolved_compliance_pct == 50.0
    assert internal.median_days_to_resolve == {"critical": 10, "high": 70}
    assert internal.overdue_by_severity == {"critical": 1, "high": 1}
    [team] = internal.teams
    assert (team.team, team.overdue, team.critical, team.worst_days) == ("payments", 2, 1, 70)
    crit, filed = internal.escalations
    assert (crit.finding_id, crit.days_overdue, crit.clock_basis) == (fleet.crit, 70, "first_event")
    assert (crit.due, crit.teams) == (T0 + 30 * DAY, ("payments",))
    assert (filed.finding_id, filed.clock_basis) == (fleet.filed, "filed")
    assert filed.due == fleet.filed_at + 60 * DAY
    [low] = floored.escalations
    assert (low.title, low.due, low.days_overdue) == ("Low with cvss", T0 + 30 * DAY, 70)
    assert floored.resolved_compliance_pct is None


def test_the_report_labels_each_profile_and_keeps_titles_on_one_row(
    context: Context, engine: Engine
) -> None:
    seed(engine)
    md = context.services().insight.publish(ViewName.SLA, ViewFilter()).markdown
    assert "# SLA view: example-sla-policy" in md
    assert "retrieved 2026-07-18" in md and "Accountable contacts: unavailable" in md
    for heading in ("summary", "overdue by owner team", "escalation digest"):
        assert f"internal-cve: {heading}" in md and f"example-profile: {heading}" in md
    assert "| Overdue \\| crit | critical | payments |" in md.replace(
        "https://github.com/example-org/svc | ", ""
    )
    assert "| payments | 2 | 1 | 70 |" in md


def test_a_scope_with_nothing_overdue_says_so(context: Context, engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        product = Seed(uow).product()
        uow.commit()
    model = build(context, product_ids=(product.id,))
    assert all(p.counts == SlaCounts() and not p.escalations for p in model.profiles)
    assert (
        "_Nothing overdue._"
        in context.services()
        .insight.publish(ViewName.SLA, ViewFilter(product_ids=(product.id,)))
        .markdown
    )


def test_the_view_is_built_only_on_a_registered_policy(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(LATER))
    ctx.__dict__["database"] = engine
    with pytest.raises(ValidationError, match="'sla' is not built"):
        ctx.services().insight.build(ViewName.SLA, ViewFilter())
    assert ViewName.SLA not in ctx.services().insight.refresh(None, ViewFilter()).rendered


@pytest.mark.parametrize(
    ("text", "match"),
    [
        (None, "cannot read SLA policy"),
        ("policy_name: [unclosed", "cannot read SLA policy"),
        ("policy_name: x\nsource: {name: n, retrieved: '2026-01-01'}\n", "sla-policy"),
        (POLICY.read_text().replace("resolve_days: 30}", "resolve_days: 0}"), "sla-policy"),
        (
            POLICY.read_text().replace("medium: {resolve_days: 90}", "urgent: {resolve_days: 1}"),
            "sla-policy",
        ),
    ],
)
def test_a_missing_or_invalid_policy_is_a_config_error(
    tmp_path: Path, text: str | None, match: str
) -> None:
    path = tmp_path / "sla-policy.yaml"
    if text is not None:
        path.write_text(text)
    with pytest.raises(ConfigError, match=match):
        Context(Config(home=tmp_path)).register_sla_policy(path)


def test_clocks_read_report_decision_filing_and_resolution_times(
    context: Context, engine: Engine
) -> None:
    fleet = seed(engine)
    findings = context.services().findings
    clocks = {
        c.view.finding.title: c for c in findings.clocks(FindingFilter(repository_id=fleet.svc))
    }
    assert set(clocks) == {
        "Overdue | crit",
        "Filed high",
        "Low with cvss",
        "Fixed fast",
        "Accepted",
        "Not real",
        "Posture",
    }
    fast, filed = clocks["Fixed fast"], clocks["Filed high"]
    assert (fast.reported_at, fast.decided_at, fast.resolved_at) == (
        T0,
        T0 + 10 * DAY,
        T0 + 10 * DAY,
    )
    assert (filed.reported_at, filed.filed_at, filed.decided_at) == (
        T0 + 50 * DAY,
        fleet.filed_at,
        None,
    )
    assert clocks["Accepted"].resolved_at is None
    early = findings.clocks(FindingFilter(repository_id=fleet.svc, as_of=fleet.filed_at - DAY))
    assert all(c.filed_at is None for c in early)
    opened = findings.clocks(FindingFilter(repository_id=fleet.svc, open=True))
    assert {c.view.finding.title for c in opened} == {
        "Overdue | crit",
        "Filed high",
        "Low with cvss",
        "Posture",
    }


def test_owners_are_the_teams_holding_the_repository_then(context: Context, engine: Engine) -> None:
    fleet = seed(engine)
    portfolio = context.services().portfolio
    assert [t.name for t in portfolio.list_owners(fleet.svc)] == ["payments"]
    assert [t.name for t in portfolio.list_owners(fleet.svc, T0)] == ["gone", "payments"]
    assert portfolio.list_owners(fleet.api) == []
    with pytest.raises(NotFoundError):
        portfolio.list_owners(UUID(int=1))


T = T0


@pytest.mark.parametrize(
    ("mode", "times", "expected"),
    [
        ("first_routed_or_filed", (T, T + DAY, T - DAY), (T - DAY, "filed")),
        ("first_routed_or_filed", (T, T - DAY, None), (T - DAY, "first_event")),
        ("first_routed_or_filed", (T, None, None), (T, "first_event")),
        ("first_event", (T, T + DAY, T - DAY), (T, "first_event")),
        ("audit_date", (T, T - DAY, T - DAY), (T, "audit_date")),
        ("first_routed_or_filed", (None, None, None), (None, "unclocked")),
        ("first_event", (None, T, None), (T, "first_event")),
        ("audit_date", (None, T, T), (None, "unclocked")),
    ],
)
def test_the_clock_start_ladder(
    mode: str,
    times: tuple[datetime | None, datetime | None, datetime | None],
    expected: tuple[datetime | None, str],
) -> None:
    reported, decided, filed = times
    clock = FindingClock.model_construct(reported_at=reported, decided_at=decided, filed_at=filed)
    assert _clock_start(clock, SlaClockStart(mode)) == expected
