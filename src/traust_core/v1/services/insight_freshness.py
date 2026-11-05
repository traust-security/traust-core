from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime, time, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    AssessmentFilter,
    AssessmentKind,
    Coverage,
    Freshness,
    Population,
)
from traust_core.v1.models.insight import ViewFilter, ViewModel, ViewName
from traust_core.v1.models.language_coverage import LanguageCoverage, LanguageCoverageRow
from traust_core.v1.models.operations import Freshness as Status
from traust_core.v1.models.operations import StaleItem
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.language_coverage import (
    LanguageCoverageCatalog,
    ReachabilityReviewFile,
)
from traust_core.v1.rendering import Report, Section
from traust_core.v1.services.insight import _scope, _table_section
from traust_core.v1.services.provider_catalog import ProviderCatalog, ToolchainStamp

if TYPE_CHECKING:
    from traust_core.v1.services.assessment import AssessmentService
    from traust_core.v1.services.code_facts import CodeFactsService
    from traust_core.v1.services.operations import FreshnessQuery
    from traust_core.v1.services.portfolio import PortfolioService

# The quarterly re-model cadence: a model older than this means the threat-model lane stalled.
THREAT_MODEL_MAX_AGE = timedelta(days=92)
LANGUAGE_COVERAGE_THRESHOLD = 10
REACHABILITY_COVERAGE_THRESHOLD = 50
_OLDEST_SHOWN = 3


class FreshnessDashboard(ViewModel):
    """Every checked input and assessment cadence (worst first), the toolchain that would run,
    and what the scope's latest audits could not examine."""

    items: tuple[StaleItem, ...]
    toolchain: ToolchainStamp | None = None
    coverage: Coverage
    language_coverage: LanguageCoverage


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
        *,
        code_facts: CodeFactsService,
        language_coverage: LanguageCoverageCatalog,
        reachability_review: ReachabilityReviewFile,
    ) -> None:
        self._freshness = freshness
        self._catalog = catalog
        self._assessment = assessment
        self._portfolio = portfolio
        self._clock = clock
        self._code_facts = code_facts
        self._language_coverage = language_coverage
        self._reachability_review = reachability_review

    def build(self, filter: ViewFilter) -> FreshnessDashboard:
        if filter.as_of is not None:
            raise ValidationError(
                "the freshness view reads inputs as they stand; it takes no as_of"
            )
        now = self._clock.now()
        urls = {r.id: r.url for r in _scope(self._portfolio, filter)[2] if r.id}
        completed = AssessmentFilter(status=ASSESSMENT_COMPLETED)
        population = self._assessment.population(now, completed, urls)
        languages, language_items = self._language_items(list(urls))
        items = [
            *self._freshness.stale(),
            _audit_item(
                _ages(population, AssessmentKind.SECURE_CODE_CANONICAL, urls, now), len(urls)
            ),
            _threat_model_item(_ages(population, AssessmentKind.THREAT_MODEL_CANONICAL, urls, now)),
            *language_items,
            self._review_item(now),
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
            language_coverage=languages,
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
                    "Measured language coverage (current default refs; no audit required)",
                    (
                        "language",
                        "dominant",
                        "present",
                        "dependency ecosystem",
                        "reachability",
                        "exception",
                    ),
                    [
                        (
                            row.language,
                            str(row.dominant),
                            str(row.present),
                            row.dependency_ecosystem or "-",
                            ", ".join(row.reachability_engines) or "-",
                            row.no_dependencies_reason or "-",
                        )
                        for row in model.language_coverage.languages
                    ],
                    "_No dominant-language measurements._",
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

    def _language_items(
        self, repository_ids: list[UUID]
    ) -> tuple[LanguageCoverage, list[StaleItem]]:
        refs = self._portfolio.default_refs(repository_ids) if repository_ids else {}
        dominant: Counter[str] = Counter()
        present: Counter[str] = Counter()
        measured = unknown = unavailable = 0
        unmeasured = len(repository_ids) - len(refs)
        errors: list[str] = []
        for repository_id in repository_ids:
            ref = refs.get(repository_id)
            if ref is None or ref.id is None:
                if ref is not None:
                    unmeasured += 1
                continue
            try:
                stats = self._code_facts.language_stats(ref.id)
            except NotFoundError:
                unmeasured += 1
                continue
            except (IntegrityError, ValidationError, ConfigError) as e:
                unavailable += 1
                errors.append(f"{repository_id}: {e}")
                continue
            measured += 1
            counts: Counter[str] = Counter()
            for language in stats.languages:
                if language.code > 0:
                    counts[self._language_coverage.canonical_language(language.name)] += (
                        language.code
                    )
            if not counts:
                unknown += 1
                continue
            present.update(counts.keys())
            dominant[min(counts, key=lambda name: (-counts[name], name))] += 1
        coverage = LanguageCoverage(
            repositories=len(repository_ids),
            measured=measured,
            unmeasured=unmeasured,
            unknown=unknown,
            unavailable=unavailable,
            languages=tuple(
                LanguageCoverageRow(
                    language=language,
                    dominant=dominant[language],
                    present=present[language],
                    dependency_ecosystem=self._language_coverage.dependency_ecosystem(language),
                    reachability_engines=self._language_coverage.reachability_engines(language),
                    no_dependencies_reason=self._language_coverage.no_dependencies_reason(language),
                )
                for language in sorted(present, key=lambda name: (-dominant[name], name))
            ),
        )
        items: list[StaleItem] = []
        for prefix, threshold in (
            ("language-coverage", LANGUAGE_COVERAGE_THRESHOLD),
            ("reachability-coverage", REACHABILITY_COVERAGE_THRESHOLD),
        ):
            incomplete = unmeasured + unknown + unavailable
            items.append(
                StaleItem(
                    item=prefix,
                    status=Status.UNAVAILABLE
                    if unavailable
                    else Status.PENDING
                    if incomplete
                    else Status.FRESH,
                    detail=f"{measured} of {len(repository_ids)} current default refs measured; "
                    f"{unmeasured} unmeasured, {unknown} measured without a dominant language, "
                    f"{unavailable} unreadable; threshold {threshold} dominant repositories"
                    + (f"; {'; '.join(errors[:_OLDEST_SHOWN])}" if errors else ""),
                    refresh="record code-facts languages at the current default refs"
                    if incomplete
                    else None,
                )
            )
            for row in coverage.languages:
                if row.dominant < threshold:
                    continue
                supported = (
                    row.dependency_ecosystem
                    if prefix == "language-coverage"
                    else ", ".join(row.reachability_engines)
                )
                detail = (
                    f"{row.language} dominant in {row.dominant} repositories, present in "
                    f"{row.present}; threshold {threshold}; "
                )
                if row.no_dependencies_reason:
                    detail += f"no-dependency exception: {row.no_dependencies_reason}"
                elif supported:
                    detail += f"covered by {supported}"
                else:
                    detail += (
                        "no native dependency-ingestion ecosystem"
                        if prefix == "language-coverage"
                        else "no wired symbol-tier reachability engine"
                    )
                missing = not (supported or row.no_dependencies_reason)
                items.append(
                    StaleItem(
                        item=f"{prefix}:{row.language}",
                        status=Status.STALE if missing else Status.FRESH,
                        detail=detail,
                        refresh="review and wire a supported native dependency-ingestion lane"
                        if missing and prefix == "language-coverage"
                        else "review and validate a symbol-tier reachability engine; "
                        "record revisit triggers in reachability-watch.yaml"
                        if missing
                        else None,
                    )
                )
        return coverage, items

    def _review_item(self, now: datetime) -> StaleItem:
        item = "reachability-watch:review"
        refresh = (
            "have a human review reachability-watch.yaml questions, update checked/last_answer, "
            "act on fired triggers, then set reviewed to that actual review date"
        )
        try:
            review = self._reachability_review.read()
        except ConfigError as e:
            return StaleItem(item=item, status=Status.UNAVAILABLE, detail=str(e), refresh=refresh)
        if review is None:
            return StaleItem(
                item=item,
                status=Status.PENDING,
                detail="no human reachability review reference recorded",
                refresh=refresh,
            )
        if review.reviewed is None:
            return StaleItem(
                item=item,
                status=Status.PENDING,
                detail="reachability reference has no human-reviewed timestamp",
                refresh=refresh,
            )
        reviewed = review.reviewed
        stamp = (
            reviewed
            if isinstance(reviewed, datetime)
            else datetime.combine(reviewed, time(), tzinfo=UTC)
        )
        age = now - stamp
        if age < timedelta():
            return StaleItem(
                item=item,
                status=Status.UNAVAILABLE,
                detail="reachability review timestamp is in the future",
                refresh=refresh,
            )
        stale = age > timedelta(days=review.review_cadence_days)
        return StaleItem(
            item=item,
            status=Status.STALE if stale else Status.FRESH,
            detail=f"{len(review.watch)} watch conditions reviewed {stamp.isoformat()}"
            + (f" by {review.reviewer}" if review.reviewer else "")
            + f"; age {age.total_seconds() / 86400:.1f}d; cadence {review.review_cadence_days}d",
            refresh=refresh if stale else None,
        )


def _ages(
    population: Population, kind: AssessmentKind, urls: Mapping[UUID, str], now: datetime
) -> list[tuple[int, str]]:
    """Canonical UTC calendar-day ages of each repository's latest default-line assessment."""
    as_of = now.astimezone(UTC)
    found = [
        (
            Freshness(last_assessed_at=r.latest.occurred_at.astimezone(UTC)).age_days(as_of) or 0,
            urls[r.repository_id],
        )
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
