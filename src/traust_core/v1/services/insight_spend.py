from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Sequence
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import computed_field

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.corpus import CorpusRegistry
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.operations import (
    Invoice,
    ModelName,
    SpendDimension,
    SpendFilter,
    SpendRollup,
)
from traust_core.v1.providers.model_catalog import ModelCatalog
from traust_core.v1.rendering import Report, Section, Table
from traust_core.v1.services.insight import _table_section, _usd

if TYPE_CHECKING:
    from traust_core.v1.services.insight import FindingsRollupView
    from traust_core.v1.services.operations import SpendService
    from traust_core.v1.services.portfolio import PortfolioService


def _pct(part: Decimal, whole: Decimal) -> Decimal | None:
    return None if not whole else round(100 * part / whole, 1)


def _claimed(rows: Sequence[SpendRollup]) -> Decimal:
    return sum((r.cost_usd for r in rows if r.key is not None), Decimal(0))


class SpendMonth(Model):
    """One month's spend, split by skill, lane, model and business unit; each split's None row
    is what nothing in that dimension claims."""

    month: str
    total: SpendRollup
    by_skill: tuple[SpendRollup, ...] = ()
    by_lane: tuple[SpendRollup, ...] = ()
    by_model: tuple[SpendRollup, ...] = ()
    by_business_unit: tuple[SpendRollup, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skill_usd(self) -> Decimal:
        """Spend a skill claims (the harness lanes); the rest is workstation sessions."""
        return _claimed(self.by_skill)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def business_unit_coverage(self) -> Decimal | None:
        """The share (%) of the month's cost that resolves to a business unit."""
        return _pct(_claimed(self.by_business_unit), self.total.cost_usd)


class InvoiceCheck(Model):
    period: str
    estimate_usd: Decimal
    invoiced_usd: Decimal
    note: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def variance_usd(self) -> Decimal:
        return self.invoiced_usd - self.estimate_usd

    @computed_field  # type: ignore[prop-decorator]
    @property
    def variance_pct(self) -> Decimal | None:
        return _pct(self.variance_usd, self.estimate_usd)


class UnitEconomics(Model):
    """One month's skill spend over the all-time counts as of the view's point in time."""

    month: str
    spend_usd: Decimal
    repositories: int
    findings: int
    critical_high: int

    def per(self, count: int) -> Decimal | None:
        return None if not count else round(self.spend_usd / count, 2)


class SpendDashboard(ViewModel):
    """Spend per month over a window, list-priced estimates with their limits named: rates the
    registry doesn't confirm, models it doesn't know, business-unit coverage, invoices."""

    window: TimeWindow
    months: tuple[SpendMonth, ...]
    unverified_models: tuple[str, ...] = ()
    unregistered_models: tuple[str, ...] = ()
    unverified_usd: Decimal = Decimal(0)
    invoices: tuple[InvoiceCheck, ...] = ()
    unit_economics: UnitEconomics | None = None

    @property
    def total_usd(self) -> Decimal:
        return sum((m.total.cost_usd for m in self.months), Decimal(0))


class SpendView:
    """financial-tracking: what spend cost, by month and skill, lane, model and business unit
    (run order -> repository -> product -> corpus registry), derived on demand; spend no
    business unit claims stays `unattributed`, never redistributed."""

    name = ViewName.SPEND

    def __init__(
        self,
        spend: SpendService,
        portfolio: PortfolioService,
        rollup: FindingsRollupView,
        models: ModelCatalog | None,
        invoices: Sequence[Invoice] = (),
    ) -> None:
        self._spend = spend
        self._portfolio = portfolio
        self._rollup = rollup
        self._models = models
        self._invoices = {i.period: i for i in invoices}

    def build(self, filter: ViewFilter) -> SpendDashboard:
        self._require_models()
        window = filter.window
        if window is None:
            raise ValidationError("the spend view needs a window")
        if filter.product_ids or filter.team_ids:
            raise ValidationError("the spend view is fleet-wide: no product or team scope")
        by_repo = {
            m: self._spend.summary(SpendFilter(window=w), SpendDimension.REPOSITORY)
            for m, w in _months(window)
        }
        units = self._business_units({r.key for rows in by_repo.values() for r in rows}, filter)
        months = tuple(self._month(m, w, by_repo[m], units) for m, w in _months(window))
        unverified, unregistered, unverified_usd = self._rates(months)
        last = next((m for m in reversed(months) if m.total.events), None)
        return SpendDashboard(
            window=window,
            months=months,
            unverified_models=unverified,
            unregistered_models=unregistered,
            unverified_usd=unverified_usd,
            invoices=tuple(
                InvoiceCheck(
                    period=m.month,
                    estimate_usd=m.total.cost_usd,
                    invoiced_usd=i.amount_usd,
                    note=i.note,
                )
                for m in months
                if (i := self._invoices.get(m.month)) is not None
            ),
            unit_economics=None if last is None else self._unit_economics(last, filter),
        )

    def _month(
        self, month: str, window: TimeWindow, by_repo: Sequence[SpendRollup], units: dict[str, str]
    ) -> SpendMonth:
        spent = SpendFilter(window=window)
        by_model = tuple(self._spend.summary(spent, SpendDimension.MODEL))
        return SpendMonth(
            month=month,
            total=_summed(None, by_model),  # every event names its model
            by_skill=tuple(self._spend.summary(spent, SpendDimension.SKILL)),
            by_lane=tuple(self._spend.summary(spent, SpendDimension.LANE)),
            by_model=by_model,
            by_business_unit=_by_unit(by_repo, units),
        )

    def _business_units(self, keys: set[str | None], filter: ViewFilter) -> dict[str, str]:
        """Repository id -> its products' one business unit; a repository with none, or whose
        products sit in different units, resolves to nothing."""
        doc = self._portfolio.corpus_registry(filter.as_of)
        registry = CorpusRegistry() if doc is None else CorpusRegistry.of(doc)
        units = {}
        for key in sorted(k for k in keys if k is not None):
            found = {
                s.business_unit
                for p in self._portfolio.list_products_of(UUID(key))
                if (s := registry.subject(str(p.id))) is not None
            }
            if len(found) == 1:
                units[key] = found.pop()
        return units

    def _require_models(self) -> ModelCatalog:
        # NotFoundError, as the SLA view: a batch refresh records it per view, a direct build
        # raises it to the caller.
        if self._models is None:
            raise NotFoundError(
                "no model registry: register one (Context.register_model_catalog; traust "
                "ships config/model-registry.yaml)"
            )
        return self._models

    def _rates(
        self, months: Sequence[SpendMonth]
    ) -> tuple[tuple[str, ...], tuple[str, ...], Decimal]:
        models = self._require_models()
        costs: defaultdict[str, Decimal] = defaultdict(Decimal)
        for m in months:
            for r in m.by_model:
                costs[r.key or ""] += r.cost_usd
        unverified, unregistered = [], []
        for model in sorted(costs):
            try:
                if not models.resolve(ModelName(model)).price_verified:
                    unverified.append(model)
            except NotFoundError:
                unregistered.append(model)
        return (
            tuple(unverified),
            tuple(unregistered),
            sum((costs[m] for m in unverified), Decimal(0)),
        )

    def _unit_economics(self, month: SpendMonth, filter: ViewFilter) -> UnitEconomics:
        rollup = self._rollup.build(ViewFilter(as_of=filter.as_of))
        t = rollup.total
        return UnitEconomics(
            month=month.month,
            spend_usd=month.skill_usd,
            repositories=len(rollup.repositories),
            findings=t.tracked,
            critical_high=t.open.critical + t.open.high + t.remediated.critical + t.remediated.high,
        )

    def report(self, model: SpendDashboard, generated_at: datetime) -> Report:
        sections = [Section(heading="Read this first", body=_preamble(model))]
        sections.append(
            _table_section(
                "Trend",
                ("month", "skills", "unattributed", "total", "change in skills"),
                [
                    (
                        m.month,
                        _usd(m.skill_usd),
                        _usd(m.total.cost_usd - m.skill_usd),
                        _usd(m.total.cost_usd),
                        "-" if prev is None else f"{m.skill_usd - prev.skill_usd:+,.2f}",
                    )
                    for prev, m in zip((None, *model.months), model.months, strict=False)
                ],
                "_No months in the window._",
            )
        )
        for heading, rows in (
            ("Spend by skill", lambda m: m.by_skill),
            ("Spend by lane", lambda m: m.by_lane),
            ("Spend by model", lambda m: m.by_model),
            ("Spend by business unit", lambda m: m.by_business_unit),
        ):
            sections.append(
                _table_section(
                    heading,
                    ("month", "key", "events", "cost usd", "share"),
                    [
                        (
                            m.month,
                            r.key or "unattributed",
                            str(r.events),
                            _usd(r.cost_usd),
                            _share(r.cost_usd, m.total.cost_usd),
                        )
                        for m in model.months
                        for r in sorted(rows(m), key=lambda r: (r.key is None, -r.cost_usd))
                    ],
                    "_No spend._",
                )
            )
        sections[-1] = sections[-1].model_copy(
            update={"body": (sections[-1].body + "\n\n" + _BU_NOTE).strip()}
        )
        if (ue := model.unit_economics) is not None:
            sections.append(
                Section(
                    heading="Unit economics",
                    body=(
                        f"{ue.month} skill spend {_usd(ue.spend_usd)} over all-time counts: "
                        f"{ue.repositories:,} repositories, {ue.findings:,} findings that aren't "
                        f"false positives, {ue.critical_high:,} critical/high. A month's cost over "
                        "an all-time count understates true unit cost; these are internal cost "
                        "ratios, not coverage claims."
                    ),
                    table=_ratio_table(ue),
                )
            )
        return Report(title="Spend", generated_at=generated_at, sections=tuple(sections))


_BU_NOTE = (
    "Business units come from the run order each spend was recorded against (repository, its "
    "products, the corpus registry). This table and *Spend by skill* split the same total along "
    "different axes, so their rows don't line up."
)


def _months(window: TimeWindow) -> Iterator[tuple[str, TimeWindow]]:
    """Each UTC calendar month the window touches, clipped to the window."""
    month = TimeWindow.month_of(window.start)
    while month.start < window.end:
        clipped = TimeWindow(start=max(month.start, window.start), end=min(month.end, window.end))
        yield month.start.strftime("%Y-%m"), clipped
        month = TimeWindow.month_of(month.end)


def _by_unit(by_repo: Sequence[SpendRollup], units: dict[str, str]) -> tuple[SpendRollup, ...]:
    summed: defaultdict[str | None, list[SpendRollup]] = defaultdict(list)
    for r in by_repo:
        summed[units.get(r.key or "")].append(r)
    return tuple(
        _summed(unit, rows)
        for unit, rows in sorted(summed.items(), key=lambda kv: (kv[0] is None, kv[0] or ""))
    )


def _summed(key: str | None, rows: Sequence[SpendRollup]) -> SpendRollup:
    return SpendRollup(
        key=key,
        events=sum(r.events for r in rows),
        tokens_in=sum(r.tokens_in for r in rows),
        tokens_out=sum(r.tokens_out for r in rows),
        cost_usd=sum((r.cost_usd for r in rows), Decimal(0)),
    )


def _share(part: Decimal, whole: Decimal) -> str:
    pct = _pct(part, whole)
    return "-" if pct is None else f"{pct}%"


def _ratio_table(ue: UnitEconomics) -> Table:
    return Table(
        columns=("metric", "value"),
        rows=tuple(
            (label, "n/a" if (v := ue.per(n)) is None else _usd(v))
            for label, n in (
                ("cost per repository", ue.repositories),
                ("cost per finding", ue.findings),
                ("cost per critical/high", ue.critical_high),
            )
        ),
    )


def _preamble(model: SpendDashboard) -> str:
    total = model.total_usd
    lines = ["**These are list-price estimates, not invoiced actuals.**"]
    if model.unverified_models:
        named = ", ".join(f"`{m}`" for m in model.unverified_models)
        lines.append(
            f"The rate for {named} is **unverified** (not on the published rate card); "
            f"those models carry {_usd(model.unverified_usd)} "
            f"({_share(model.unverified_usd, total)}) of the window's spend."
        )
    else:
        lines.append("Every model with spend in the window has a confirmed rate in the registry.")
    if model.unregistered_models:
        named = ", ".join(f"`{m}`" for m in model.unregistered_models)
        lines.append(f"{named} isn't in the model registry; its spend is shown as recorded.")
    resolved = sum((_claimed(m.by_business_unit) for m in model.months), Decimal(0))
    lines.append(
        f"Business-unit coverage: {_share(resolved, total)} of the window's cost resolves to a "
        "business unit; the rest is `unattributed`, shown and never redistributed."
    )
    if model.invoices:
        lines += [
            f"Invoice {i.period}: estimate {_usd(i.estimate_usd)} vs invoiced "
            f"{_usd(i.invoiced_usd)}, variance {_usd(i.variance_usd)}"
            + ("" if i.variance_pct is None else f" ({i.variance_pct:+}%)")
            + (f" ({i.note})" if i.note else "")
            + "."
            for i in model.invoices
        ]
    else:
        lines.append("No invoice supplied, so nothing here has been checked against real billing.")
    return "\n\n".join(lines)
