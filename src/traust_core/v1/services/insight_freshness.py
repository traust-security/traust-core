from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    AssessmentFilter,
    AssessmentKind,
    Coverage,
    Freshness,
    Population,
)
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.operations import Freshness as Status
from traust_core.v1.models.operations import StaleItem
from traust_core.v1.providers.clock import Clock
from traust_core.v1.rendering import Report, Section
from traust_core.v1.services.insight import _scope, _table_section
from traust_core.v1.services.provider_catalog import ProviderCatalog, ToolchainStamp

if TYPE_CHECKING:
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.operations import FreshnessQuery
    from traust_core.v1.services.portfolio import PortfolioService

# The quarterly re-model cadence: a model older than this means the threat-model lane stalled.
THREAT_MODEL_MAX_AGE = timedelta(days=92)
_OLDEST_SHOWN = 3


class FreshnessDashboard(ViewModel):
    """Every checked input and assessment cadence (worst first), the toolchain that would run,
    and what the scope's latest audits could not examine."""

    items: tuple[StaleItem, ...]
    toolchain: ToolchainStamp | None = None
    coverage: Coverage


class FreshnessView:
    """drift-watch: is anything stale, derived now from feeds, providers, tool databases and
    the scope's assessments; never a stored report."""

    name = ViewName.FRESHNESS

    def __init__(
        self,
        freshness: FreshnessQuery,
        catalog: ProviderCatalog,
        assessment: AssessmentService,
        portfolio: PortfolioService,
        clock: Clock,
    ) -> None:
        self._freshness = freshness
        self._catalog = catalog
        self._assessment = assessment
        self._portfolio = portfolio
        self._clock = clock

    def build(self, filter: ViewFilter) -> FreshnessDashboard:
        if filter.as_of is not None:
            raise ValidationError(
                "the freshness view reads inputs as they stand; it takes no as_of"
            )
        now = self._clock.now()
        urls = {r.id: r.url for r in _scope(self._portfolio, filter)[2] if r.id}
        completed = AssessmentFilter(status=ASSESSMENT_COMPLETED)
        population = self._assessment.population(now, completed, urls)
        items = [
            *self._freshness.stale(),
            _audit_item(_ages(population, AssessmentKind.SECURE_CODE, urls, now), len(urls)),
            _threat_model_item(_ages(population, AssessmentKind.THREAT_MODEL, urls, now)),
        ]
        try:
            toolchain = self._catalog.stamp()
        except ConfigError as e:
            toolchain = None
            items.append(StaleItem(item="toolchain", status=Status.UNAVAILABLE, detail=str(e)))
        order = list(Status)
        return FreshnessDashboard(
            items=tuple(sorted(items, key=lambda i: (order.index(i.status), i.item))),
            toolchain=toolchain,
            coverage=self._assessment.coverage(AssessmentFilter(), list(urls)),  # type: ignore[arg-type]
        )

    def report(self, model: FreshnessDashboard, generated_at: datetime) -> Report:
        counts = Counter(i.status for i in model.items)
        summary = ", ".join(f"{counts[s]} {s}" for s in Status if counts[s]) or "nothing checked"
        tools = model.toolchain.tools if model.toolchain else ()
        return Report(
            title="Freshness",
            generated_at=generated_at,
            sections=(
                Section(heading="Summary", body=f"{summary}. Routes attention, never concludes."),
                _table_section(
                    "Items",
                    ("status", "item", "detail"),
                    [(i.status.value, i.item, i.detail) for i in model.items],
                    "_Nothing checked._",
                ),
                _table_section(
                    "Refresh queue",
                    ("item", "refresh"),
                    [(i.item, i.refresh) for i in model.items if i.refresh],
                    "_Nothing to refresh._",
                ),
                _table_section(
                    "Toolchain",
                    ("tool", "stamp"),
                    [(t.tool, t.render()) for t in tools],
                    "_No toolchain inspected._",
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
                        for g in model.coverage.gaps
                    ],
                    "_No gaps reported._",
                ),
            ),
        )


def _ages(
    population: Population, kind: AssessmentKind, urls: Mapping[UUID, str], now: datetime
) -> list[tuple[int, str]]:
    """(age in days, repository URL) of each repository's latest default-line `kind`, oldest
    first."""
    found = [
        (Freshness(last_assessed_at=r.latest.occurred_at).age_days(now) or 0, urls[r.repository_id])
        for r in population.rows
        if r.kind == kind and r.latest is not None
    ]
    return sorted(found, reverse=True)


def _oldest(ages: list[tuple[int, str]]) -> str:
    return ", ".join(f"{r} ({a}d)" for a, r in ages[:_OLDEST_SHOWN])


def _audit_item(ages: list[tuple[int, str]], repositories: int) -> StaleItem:
    item, never = "assessments:secure-code", repositories - len(ages)
    if never:
        return StaleItem(
            item=item,
            status=Status.PENDING,
            detail=f"{never} of {repositories} repositories never audited"
            + (f"; oldest audits: {_oldest(ages)}" if ages else ""),
            refresh="run /secure-code-audit on the never-audited repositories",
        )
    detail = f"{len(ages)} repositories audited; oldest: {_oldest(ages)}"
    return StaleItem(item=item, status=Status.FRESH, detail=detail if ages else "no repositories")


def _threat_model_item(ages: list[tuple[int, str]]) -> StaleItem:
    item, limit = "assessments:threat-model", THREAT_MODEL_MAX_AGE.days
    if not ages:
        return StaleItem(item=item, status=Status.PENDING, detail="no threat models recorded yet")
    stale = [a for a in ages if a[0] > limit]
    if stale:
        return StaleItem(
            item=item,
            status=Status.STALE,
            detail=f"{len(stale)} of {len(ages)} models exceed the {limit}d quarterly cadence; "
            f"oldest: {_oldest(stale)}",
            refresh="the threat-model quarterly lane is not draining; re-model the oldest",
        )
    return StaleItem(
        item=item, status=Status.FRESH, detail=f"{len(ages)} models, none older than {limit}d"
    )
