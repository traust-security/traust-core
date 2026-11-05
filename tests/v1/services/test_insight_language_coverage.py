from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest

from tests.v1.services.test_insight import FakePortfolio
from tests.v1.services.test_insight_freshness import NOW, FakeCatalog, FakeFreshness
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import IntegrityError, NotFoundError
from traust_core.v1.models.assessment import AssessmentFilter, Coverage, Population
from traust_core.v1.models.code_facts import LanguageCount, LanguageStats
from traust_core.v1.models.insight import ViewFilter
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import Freshness
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.impact import GovulncheckAnalyzer, SourceScanAnalyzer
from traust_core.v1.providers.language_coverage import (
    LanguageCoverageCatalog,
    ReachabilityReviewFile,
)
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.services.insight_freshness import FreshnessDashboard, FreshnessView


class NoAudits:
    def population(
        self, as_of: object, filter: AssessmentFilter, repository_ids: Collection[UUID]
    ) -> Population:
        return Population(as_of=as_of, rows=())

    def coverage(self, filter: AssessmentFilter, repository_ids: list[UUID]) -> Coverage:
        return Coverage(examined=0, total=len(repository_ids), gaps=())


@dataclass
class CurrentPortfolio(FakePortfolio):
    heads: dict[UUID, RepositoryRef] = field(default_factory=dict)
    requested: list[set[UUID]] = field(default_factory=list)

    def default_refs(self, repository_ids: Collection[UUID]) -> dict[UUID, RepositoryRef]:
        self.requested.append(set(repository_ids))
        return {r: self.heads[r] for r in repository_ids if r in self.heads}


@dataclass
class MeasuredFacts:
    values: dict[UUID, LanguageStats | Exception]
    requested: list[UUID] = field(default_factory=list)

    def language_stats(self, repository_ref_id: UUID) -> LanguageStats:
        self.requested.append(repository_ref_id)
        result = self.values.get(repository_ref_id)
        if result is None:
            raise NotFoundError(f"ref {repository_ref_id}: languages not measured")
        if isinstance(result, Exception):
            raise result
        return result


def stats(**languages: int) -> LanguageStats:
    return LanguageStats(
        languages=tuple(
            LanguageCount(name=name, files=None, code=code, comments=None, blanks=None)
            for name, code in languages.items()
        )
    )


def language_view(
    measurements: list[LanguageStats | Exception | None],
    review_path: Path | None = None,
    *,
    symbol_engine: bool = True,
) -> tuple[FreshnessView, CurrentPortfolio, MeasuredFacts]:
    repositories = {uuid4(): f"https://forge.example/o/r{i}" for i in range(len(measurements))}
    heads = {
        repository_id: RepositoryRef(
            id=uuid4(), repository_id=repository_id, sha="a" * 40, name="main", is_default=True
        )
        for repository_id in repositories
    }
    facts = MeasuredFacts(
        {
            ref.id: measurement
            for ref, measurement in zip(heads.values(), measurements, strict=True)
            if ref.id is not None and measurement is not None
        }
    )
    portfolio = CurrentPortfolio(repositories=repositories, heads=heads)
    clock = FixedClock(NOW)
    process = Mock(spec=ProcessRunner)
    analyzers = (SourceScanAnalyzer(clock),)
    if symbol_engine:
        analyzers = (GovulncheckAnalyzer(process, clock), *analyzers)
    view = FreshnessView(
        FakeFreshness(),  # type: ignore[arg-type]
        FakeCatalog(),  # type: ignore[arg-type]
        NoAudits(),  # type: ignore[arg-type]
        portfolio,  # type: ignore[arg-type]
        clock,
        code_facts=facts,  # type: ignore[arg-type]
        language_coverage=LanguageCoverageCatalog(analyzers),
        reachability_review=ReachabilityReviewFile(review_path, yaml_documents),
    )
    return view, portfolio, facts


def item_statuses(model: FreshnessDashboard) -> dict[str, Freshness]:
    return {item.item: item.status for item in model.items}


@pytest.mark.parametrize(
    ("count", "dependency_warns", "reachability_warns"),
    [(9, False, False), (10, True, False), (49, True, False), (50, True, True)],
)
def test_unsupported_mass_warns_at_inclusive_thresholds_without_any_audit(
    count: int, dependency_warns: bool, reachability_warns: bool
) -> None:
    view, _, _ = language_view([stats(Swift=100)] * count)
    model = view.build(ViewFilter())
    statuses = item_statuses(model)
    assert model.coverage.examined == 0 and model.coverage.gaps == ()
    assert (statuses.get("language-coverage:Swift") is Freshness.STALE) == dependency_warns
    assert (statuses.get("reachability-coverage:Swift") is Freshness.STALE) == reachability_warns
    assert model.language_coverage.languages[0].dominant == count
    assert model.language_coverage.measured == count


@pytest.mark.parametrize(
    ("language", "dependency_status", "reachability_status", "exception"),
    [
        ("Go", Freshness.FRESH, Freshness.FRESH, False),
        ("Python", Freshness.FRESH, Freshness.STALE, False),
        ("Java", Freshness.FRESH, Freshness.STALE, False),
        ("Swift", Freshness.STALE, Freshness.STALE, False),
        ("Shell", Freshness.FRESH, Freshness.FRESH, True),
        ("YAML", Freshness.FRESH, Freshness.FRESH, True),
    ],
)
def test_dependency_support_reachability_and_explained_exceptions_are_independent(
    language: str,
    dependency_status: Freshness,
    reachability_status: Freshness,
    exception: bool,
) -> None:
    view, _, _ = language_view([stats(**{language: 100})] * 50)
    model = view.build(ViewFilter())
    statuses = item_statuses(model)
    assert statuses[f"language-coverage:{language}"] is dependency_status
    assert statuses[f"reachability-coverage:{language}"] is reachability_status
    row = model.language_coverage.languages[0]
    assert (row.no_dependencies_reason is not None) == exception
    assert row.reachability_engines == (("govulncheck",) if language == "Go" else ())


def test_unwired_engine_is_not_covered_because_its_tool_exists() -> None:
    view, _, _ = language_view([stats(Go=100)] * 50, symbol_engine=False)
    assert item_statuses(view.build(ViewFilter()))["reachability-coverage:Go"] is Freshness.STALE


def test_only_current_default_refs_are_measured_and_scope_is_respected() -> None:
    view, portfolio, facts = language_view([stats(Swift=100)] * 50)
    repository_ids = list(portfolio.repositories)
    team_id = uuid4()
    portfolio.teams[team_id] = set(repository_ids[:9])
    old_ref_id = uuid4()
    facts.values[old_ref_id] = stats(Swift=10000)
    current = portfolio.heads[repository_ids[0]]
    facts.values[current.id] = stats(Go=200)  # type: ignore[index]
    model = view.build(ViewFilter(team_ids=(team_id,)))
    assert portfolio.requested == [set(repository_ids[:9])]
    assert set(facts.requested) == {portfolio.heads[r].id for r in repository_ids[:9]}
    assert old_ref_id not in facts.requested
    assert model.language_coverage.repositories == 9
    assert {r.language: r.dominant for r in model.language_coverage.languages} == {
        "Swift": 8,
        "Go": 1,
    }
    assert "language-coverage:Swift" not in item_statuses(model)


def test_presence_does_not_count_as_dominance_and_aliases_share_mass() -> None:
    view, _, _ = language_view([stats(Swift=1, Python=10)] * 10)
    model = view.build(ViewFilter())
    rows = {r.language: r for r in model.language_coverage.languages}
    assert rows["Swift"].present == 10 and rows["Swift"].dominant == 0
    assert "language-coverage:Swift" not in item_statuses(model)
    view, _, _ = language_view([stats(BASH=10)] * 25 + [stats(Shell=10)] * 25)
    shell = view.build(ViewFilter()).language_coverage.languages[0]
    assert shell.language == "Shell" and shell.dominant == 50
    assert shell.no_dependencies_reason is not None


def test_unknown_measured_data_and_missing_measurements_are_not_zero_coverage() -> None:
    view, portfolio, _ = language_view([stats(), stats(Python=0), None, stats(Go=100)])
    portfolio.heads.pop(next(reversed(portfolio.heads)))
    model = view.build(ViewFilter())
    coverage = model.language_coverage
    assert (coverage.repositories, coverage.measured, coverage.unknown, coverage.unmeasured) == (
        4,
        2,
        2,
        2,
    )
    assert coverage.languages == ()
    assert item_statuses(model)["language-coverage"] is Freshness.PENDING
    assert item_statuses(model)["reachability-coverage"] is Freshness.PENDING


def test_unreadable_measurements_remain_unavailable_while_known_mass_warns() -> None:
    view, _, _ = language_view([stats(Swift=100)] * 10 + [IntegrityError("bad digest")])
    model = view.build(ViewFilter())
    assert model.language_coverage.unavailable == 1
    assert model.language_coverage.unmeasured == 0
    assert item_statuses(model)["language-coverage"] is Freshness.UNAVAILABLE
    assert item_statuses(model)["language-coverage:Swift"] is Freshness.STALE


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(days=92), Freshness.FRESH),
        (timedelta(days=92, seconds=1), Freshness.STALE),
        (timedelta(days=93), Freshness.STALE),
        (timedelta(days=-1), Freshness.UNAVAILABLE),
    ],
)
def test_review_clock_ages_independently_of_audits_languages_or_roster(
    tmp_path: Path, age: timedelta, expected: Freshness
) -> None:
    path = tmp_path / "reachability-watch.yaml"
    path.write_text(
        f"reviewed: '{(NOW - age).isoformat()}'\nreview_cadence_days: 92\nwatch: []\n",
        encoding="utf-8",
    )
    view, _, _ = language_view([], path)
    assert item_statuses(view.build(ViewFilter()))["reachability-watch:review"] is expected


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        (None, Freshness.PENDING),
        ("[", Freshness.UNAVAILABLE),
        ("reviewed: null", Freshness.PENDING),
    ],
)
def test_absent_malformed_and_unreviewed_references_are_not_fresh(
    tmp_path: Path, contents: str | None, expected: Freshness
) -> None:
    path = tmp_path / "reachability-watch.yaml"
    if contents is not None:
        path.write_text(contents, encoding="utf-8")
    view, _, _ = language_view([stats(Go=100)] * 50, path)
    model = view.build(ViewFilter())
    assert item_statuses(model)["reachability-coverage:Go"] is Freshness.FRESH
    assert item_statuses(model)["reachability-watch:review"] is expected


def test_empty_scope_is_measured_empty_not_unknown() -> None:
    view, _, _ = language_view([])
    model = view.build(ViewFilter())
    assert model.language_coverage.repositories == model.language_coverage.measured == 0
    assert model.language_coverage.unknown == model.language_coverage.unmeasured == 0
    assert item_statuses(model)["language-coverage"] is Freshness.FRESH
