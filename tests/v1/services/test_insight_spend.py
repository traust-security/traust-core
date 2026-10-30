"""The spend view (harnessing/financial-tracking build_financial_report.py) and spend priced on
the model registry, through Context on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.providers.test_model_catalog import REGISTRY
from tests.v1.repositories.tables.conftest import T0, Seed
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.operations import ModelUsage, SpendDimension, SpendFilter, SpendSource
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight_spend import SpendDashboard

DAY = timedelta(days=1)
WINDOW = TimeWindow(start=datetime(2026, 9, 1, tzinfo=UTC), end=datetime(2026, 11, 1, tzinfo=UTC))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    ctx.register_model_catalog(REGISTRY)
    return ctx


def register(context: Context, slug: str, unit: str) -> Any:
    product, _ = context.services().portfolio.register_corpus_product(
        ProductSlug.parse(slug), slug.title(), OwnershipClass.OWNED, unit
    )
    return product


def seed_spend(context: Context, engine: Engine) -> None:
    """`svc` ships in payments' product; `split` ships in two units' products; `orphan` in
    none; one order has no repository and some spend has no order at all."""
    alpha, beta = register(context, "alpha", "payments"), register(context, "beta", "identity")
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc, split, orphan = (
            s.repository(url=f"https://github.com/example-org/{n}")
            for n in ("svc", "split", "orphan")
        )
        s.component(s.release(alpha), s.repository_ref(svc))
        split_ref = s.repository_ref(split)
        s.component(s.release(alpha), split_ref)
        s.component(s.release(beta), split_ref)

        def spent(usd: str, model: str = "claude-opus-5-5", **kw: Any) -> None:
            s.spend_event(model=model, cost_usd=Decimal(usd), **kw)

        for repository, usd in ((svc, "2"), (orphan, "1"), (split, "0.25")):
            order = s.run_order(repository_id=repository.id, lane="full-audit")
            spent(usd, run_order_id=order.id, lane="full-audit", skill="audit")
        spent("0.5", run_order_id=s.run_order().id)
        spent("4", model="claude-opus-5")  # unverified rate
        spent("0.1", model="claude-legacy")  # not in the registry
        spent("3", skill="triage", occurred_at=T0 - 10 * DAY)  # September
        spent("9", occurred_at=WINDOW.end)  # past the window
        uow.commit()


def build(context: Context, **kw: Any) -> SpendDashboard:
    model = context.services().insight.build(ViewName.SPEND, ViewFilter(window=WINDOW, **kw))
    assert isinstance(model, SpendDashboard)
    return model


def keyed(rows: Any) -> dict[str | None, Decimal]:
    return {r.key: r.cost_usd for r in rows}


def test_the_spend_view_splits_each_month_and_derives_business_units(
    context: Context, engine: Engine
) -> None:
    seed_spend(context, engine)
    model = build(context)
    september, october = model.months
    assert (september.month, september.total.cost_usd, october.total.cost_usd) == (
        "2026-09",
        Decimal(3),
        Decimal("7.85"),
    )
    assert keyed(october.by_business_unit) == {"payments": Decimal(2), None: Decimal("5.85")}
    assert keyed(september.by_business_unit) == {None: Decimal(3)}
    assert october.business_unit_coverage == Decimal("25.5")
    assert keyed(october.by_skill) == {"audit": Decimal("3.25"), None: Decimal("4.6")}
    assert october.skill_usd == Decimal("3.25")
    assert keyed(october.by_lane) == {"full-audit": Decimal("3.25"), None: Decimal("4.6")}
    assert keyed(september.by_model) == {"claude-opus-5-5": Decimal(3)}
    assert (model.unverified_models, model.unregistered_models, model.unverified_usd) == (
        ("claude-opus-5",),
        ("claude-legacy",),
        Decimal(4),
    )
    assert model.invoices == ()
    ue = model.unit_economics
    assert ue is not None and (ue.month, ue.spend_usd, ue.repositories) == (
        "2026-10",
        Decimal("3.25"),
        3,
    )
    assert ue.per(ue.findings) is None


def test_the_spend_report_leads_with_its_limits(context: Context, engine: Engine) -> None:
    seed_spend(context, engine)
    md = context.services().insight.publish(ViewName.SPEND, ViewFilter(window=WINDOW)).markdown
    preamble = md.split("## Trend")[0]
    assert "**These are list-price estimates, not invoiced actuals.**" in preamble
    assert "The rate for `claude-opus-5` is **unverified**" in preamble
    assert "$4.00 (36.9%) of the window's spend" in preamble
    assert "`claude-legacy` isn't in the model registry" in preamble
    assert "Business-unit coverage: 18.4% of the window's cost" in preamble
    assert "never redistributed" in preamble
    assert "nothing here has been checked against real billing" in preamble
    assert "| 2026-10 | $3.25 | $4.60 | $7.85 | +0.25 |" in md
    assert "| 2026-10 | payments | 1 | $2.00 | 25.5% |" in md
    assert "| 2026-10 | unattributed | 5 | $5.85 | 74.5% |" in md
    assert "| cost per finding | n/a |" in md


def test_invoices_reconcile_the_months_they_bill(
    context: Context, engine: Engine, tmp_path: Path
) -> None:
    seed_spend(context, engine)
    bills = tmp_path / "invoices.csv"
    bills.write_text("period,amount_usd,note\n2026-10,8.00,October bill\n2025-01,1,\n")
    context.register_invoices(bills)
    model = build(context)
    [checked] = model.invoices
    assert (checked.period, checked.estimate_usd, checked.variance_usd, checked.variance_pct) == (
        "2026-10",
        Decimal("7.85"),
        Decimal("0.15"),
        Decimal("1.9"),
    )
    md = context.services().insight.publish(ViewName.SPEND, ViewFilter(window=WINDOW)).markdown
    assert "Invoice 2026-10: estimate $7.85 vs invoiced $8.00, variance $0.15 (+1.9%)" in md


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("period,amount_usd\n2026-13,1\n", "invoices"),
        ("period,amount_usd\n2026-10,lots\n", "invoices"),
        ("period,amount_usd\n2026-10,1\n2026-10,2\n", "more than one row per period"),
        ("period,amount_usd,extra\n2026-10,1,x\n", "invoices"),
    ],
)
def test_a_malformed_invoice_file_is_a_config_error(tmp_path: Path, text: str, match: str) -> None:
    bills = tmp_path / "invoices.csv"
    bills.write_text(text)
    with pytest.raises(ConfigError, match=match):
        Context(Config(home=tmp_path)).register_invoices(bills)


def test_an_empty_window_says_so(context: Context) -> None:
    model = build(context)
    assert [m.total.events for m in model.months] == [0, 0]
    assert model.unit_economics is None
    md = context.services().insight.publish(ViewName.SPEND, ViewFilter(window=WINDOW)).markdown
    assert "Business-unit coverage: - of the window's cost" in md
    assert "_No spend._" in md


@pytest.mark.parametrize(
    ("filter", "match"),
    [
        (ViewFilter(), "needs a window"),
        (
            ViewFilter(window=WINDOW, team_ids=(T0.timestamp() and __import__("uuid").uuid4(),)),
            "fleet-wide",
        ),
    ],
)
def test_the_spend_view_needs_a_fleet_wide_window(
    context: Context, filter: ViewFilter, match: str
) -> None:
    with pytest.raises(ValidationError, match=match):
        context.services().insight.build(ViewName.SPEND, filter)


def test_the_spend_view_without_a_model_registry_names_the_file(
    engine: Engine, tmp_path: Path
) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.__dict__["database"] = engine
    with pytest.raises(NotFoundError, match="no model registry"):
        ctx.services().insight.build(ViewName.SPEND, ViewFilter(window=WINDOW))


def test_spend_by_repository_follows_the_run_order(context: Context, engine: Engine) -> None:
    seed_spend(context, engine)
    rollups = context.services().spend.summary(
        SpendFilter(window=TimeWindow.month_of(T0)), SpendDimension.REPOSITORY
    )
    assert sorted(r.cost_usd for r in rollups if r.key) == [Decimal("0.25"), 1, 2]
    assert [r.cost_usd for r in rollups if r.key is None] == [Decimal("4.6")]


def test_collect_prices_on_the_registry_and_adds_nothing_again(context: Context) -> None:
    def usage(hours: int, **kw: Any) -> ModelUsage:
        values = {"provider": "anthropic", "model": "claude-opus-5-5", "skill": "triage"}
        return ModelUsage(
            **{**values, **kw},
            occurred_at=T0 + timedelta(hours=hours),
            tokens_in=10**6,
            tokens_out=0,
        )

    source = SpendSource(name="sessions", usages=(usage(1), usage(2), usage(3, skill=None)))
    spend = context.services().spend
    window = TimeWindow.month_of(T0)
    assert spend.collect(source, window) == 2
    assert spend.collect(source, window) == 0
    split = spend.attribute_by(SpendFilter(window=window), SpendDimension.SKILL)
    assert split.lossless
    assert [(r.key, r.cost_usd) for r in split.rows] == [("triage", Decimal(8))]
    assert split.unattributed.cost_usd == Decimal(4)


def test_collect_refuses_a_model_the_registry_cannot_price(context: Context) -> None:
    usage = ModelUsage(
        provider="anthropic", model="claude-unpriced", occurred_at=T0, tokens_in=1, tokens_out=1
    )
    with pytest.raises(ConfigError, match="has no price"):
        context.services().spend.collect(
            SpendSource(name="sessions", usages=(usage,)), TimeWindow.month_of(T0)
        )
