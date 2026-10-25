"""The freshness view (drift-watch): stale inputs, assessment cadences, toolchain, coverage."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import FakePortfolio
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    Assessment,
    Coverage,
    CoverageGap,
    Population,
    PopulationRow,
)
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.operations import Freshness, StaleItem
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight_freshness import FreshnessView
from traust_core.v1.services.provider_catalog import ToolchainStamp, ToolStamp

NOW = T0 + timedelta(days=200)
A, B = uuid4(), uuid4()


def assessed(repository_id: UUID, kind: str, days_old: int) -> PopulationRow:
    latest = Assessment(
        repository_ref_id=uuid4(),
        kind=kind,
        status=ASSESSMENT_COMPLETED,
        assessor="skill:test",
        assessor_version="1",
        occurred_at=NOW - timedelta(days=days_old),
    )
    return PopulationRow(repository_id=repository_id, kind=kind, latest=latest, default_line=1)


@dataclass
class FakeFreshness:
    items: list[StaleItem] = field(default_factory=list)

    def stale(self) -> list[StaleItem]:
        return self.items


@dataclass
class FakeCatalog:
    stamp_error: str | None = None

    def stamp(self) -> ToolchainStamp:
        if self.stamp_error:
            raise ConfigError(self.stamp_error)
        return ToolchainStamp(core_version="1.0", tools=(ToolStamp(tool="grype", version="0.1"),))


@dataclass
class FakeAssessment:
    rows: tuple[PopulationRow, ...] = ()
    asked: list[Any] = field(default_factory=list)

    def population(self, as_of: Any, filter: Any, repository_ids: Any) -> Population:
        self.asked.append((as_of, filter.status, sorted(repository_ids, key=str)))
        return Population(as_of=as_of, rows=self.rows)

    def coverage(self, filter: Any, repository_ids: Any) -> Coverage:
        gap = CoverageGap(tool="opengrep", system="kotlin", repositories=1, signals={})
        return Coverage(examined=1, total=2, gaps=(gap,))


def view(
    rows: tuple[PopulationRow, ...] = (),
    items: list[StaleItem] | None = None,
    stamp_error: str | None = None,
    repositories: dict[UUID, str] | None = None,
) -> tuple[FreshnessView, FakeAssessment]:
    assessment = FakeAssessment(rows)
    portfolio = FakePortfolio(
        repositories={A: "https://forge.example/o/a", B: "https://forge.example/o/b"}
        if repositories is None
        else repositories
    )
    found = FreshnessView(
        FakeFreshness(items or []),  # type: ignore[arg-type]
        FakeCatalog(stamp_error),  # type: ignore[arg-type]
        assessment,  # type: ignore[arg-type]
        portfolio,  # type: ignore[arg-type]
        FixedClock(NOW),
    )
    return found, assessment


def statuses(v: FreshnessView) -> dict[str, Freshness]:
    return {i.item: i.status for i in v.build(ViewFilter()).items}


def md(v: FreshnessView) -> str:
    return MarkdownRenderer().render(v.report(v.build(ViewFilter()), NOW)).decode()


def test_reads_the_scopes_completed_assessments_now() -> None:
    v, assessment = view()
    v.build(ViewFilter())
    assert assessment.asked == [(NOW, ASSESSMENT_COMPLETED, sorted([A, B], key=str))]


def test_refuses_a_point_in_time() -> None:
    with pytest.raises(ValidationError, match="no as_of"):
        view()[0].build(ViewFilter(as_of=T0))


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ((), Freshness.PENDING),
        ((assessed(A, "threat-model", 92), assessed(B, "threat-model", 10)), Freshness.FRESH),
        ((assessed(A, "threat-model", 93), assessed(B, "threat-model", 10)), Freshness.STALE),
        ((assessed(A, "secure-code", 400),), Freshness.PENDING),
    ],
)
def test_threat_models_go_stale_past_the_quarterly_cadence(
    rows: tuple[PopulationRow, ...], expected: Freshness
) -> None:
    assert statuses(view(rows)[0])["assessments:threat-model"] is expected


def test_a_stale_threat_model_names_the_oldest_and_a_refresh() -> None:
    v = view((assessed(A, "threat-model", 120), assessed(B, "threat-model", 100)))[0]
    text = md(v)
    assert "2 of 2 models exceed the 92d quarterly cadence" in text
    assert "https://forge.example/o/a (120d), https://forge.example/o/b (100d)" in text
    assert "| assessments:threat-model | the threat-model quarterly lane" in text


@pytest.mark.parametrize(
    ("rows", "expected", "detail"),
    [
        ((), Freshness.PENDING, "2 of 2 repositories never audited"),
        ((assessed(A, "secure-code", 5),), Freshness.PENDING, "1 of 2 repositories never"),
        (
            (assessed(A, "secure-code", 5), assessed(B, "secure-code", 400)),
            Freshness.FRESH,
            "2 repositories audited; oldest: https://forge.example/o/b (400d)",
        ),
    ],
)
def test_never_audited_repositories_are_pending(
    rows: tuple[PopulationRow, ...], expected: Freshness, detail: str
) -> None:
    item = next(
        i for i in view(rows)[0].build(ViewFilter()).items if i.item == "assessments:secure-code"
    )
    assert item.status is expected and detail in item.detail


def test_an_empty_scope_has_nothing_to_audit() -> None:
    v = view(repositories={})[0]
    assert statuses(v)["assessments:secure-code"] is Freshness.FRESH


def test_items_lead_with_the_worst() -> None:
    inputs = [
        StaleItem(item="feeds:kev", status=Freshness.FRESH),
        StaleItem(item="feeds:epss", status=Freshness.STALE, refresh="fetch feed epss"),
        StaleItem(item="database:grype", status=Freshness.UNAVAILABLE),
    ]
    model = view(items=inputs)[0].build(ViewFilter())
    order = [i.status for i in model.items]
    assert order == sorted(order, key=list(Freshness).index)
    assert model.items[0].item == "feeds:epss"


def test_the_toolchain_is_stamped_and_rendered() -> None:
    v = view()[0]
    assert v.build(ViewFilter()).toolchain is not None
    text = md(v)
    assert "| grype | grype 0.1 |" in text and "| opengrep | kotlin | 1 | - |" in text


def test_no_toolchain_inspector_is_an_unavailable_row_not_an_error() -> None:
    v = view(stamp_error="stamp needs a ToolInspector")[0]
    model = v.build(ViewFilter())
    assert model.toolchain is None
    assert statuses(v)["toolchain"] is Freshness.UNAVAILABLE
    assert "_No toolchain inspected._" in md(v)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(NOW))
    ctx.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository(url="https://github.com/example-org/svc")
        main = seed.repository_ref(repo, is_default=True)
        seed.assessment(main, kind="secure-code", occurred_at=NOW - timedelta(days=3))
        seed.assessment(main, kind="threat-model", occurred_at=NOW - timedelta(days=150))
        seed.assessment(main, kind="threat-model", status="failed", occurred_at=NOW)
        uow.commit()
    result = ctx.services().insight.refresh([ViewName.FRESHNESS], ViewFilter())
    assert result.failed == {}
    text = result.rendered[ViewName.FRESHNESS].markdown
    assert "| stale | assessments:threat-model | 1 of 1 models exceed" in text
    assert "(150d)" in text
    assert "| fresh | assessments:secure-code | 1 repositories audited" in text
    assert "| unavailable | toolchain |" in text
