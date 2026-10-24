"""Coverage, exposure, PQC and compliance views: thin regroupings of each domain's rollups."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_insight import FakePortfolio
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.assessment import Coverage, CoverageGap, Population, PopulationRow
from traust_core.v1.models.compliance import ComplianceDimension, ComplianceRollup
from traust_core.v1.models.dependencies import ExposureDimension, ExposureFilter, ExposureRollup
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.pqc import PqcDimension, PqcRollup
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import (
    ComplianceDashboardView,
    CoverageView,
    ExposureView,
    PqcView,
)


def md(view: Any, filter: ViewFilter | None = None) -> str:
    return MarkdownRenderer().render(view.report(view.build(filter or ViewFilter()), T0)).decode()


@dataclass
class FakeExposure:
    asked: list[ExposureDimension] = field(default_factory=list)

    def summary(self, filter: Any, group_by: ExposureDimension) -> list[ExposureRollup]:
        self.asked.append(group_by)
        none: dict[Any, int] = {}
        return [
            ExposureRollup(
                key=f"{group_by}-a", commits=3, exposed=2, affected=1, by_classification=none
            ),
            ExposureRollup(key=None, commits=1, exposed=0, affected=0, by_classification=none),
        ]


def test_exposure_groups_by_advisory_product_and_verdict() -> None:
    exposure = FakeExposure()
    model = ExposureView(exposure).build(ViewFilter())  # type: ignore[arg-type]
    assert exposure.asked == [
        ExposureDimension.ADVISORY,
        ExposureDimension.PRODUCT,
        ExposureDimension.CLASSIFICATION,
    ]
    assert model.by_product[0].key == "product-a"
    text = md(ExposureView(exposure))  # type: ignore[arg-type]
    assert "| advisory-a | 3 | 2 | 1 |" in text and "| - | 1 | 0 | 0 |" in text


@dataclass
class FakePqc:
    asked: list[tuple[UUID | None, PqcDimension]] = field(default_factory=list)

    def summary(self, filter: Any, group_by: PqcDimension) -> list[PqcRollup]:
        self.asked.append((filter.product_id, group_by))
        return [
            PqcRollup(key=str(group_by), repositories=2, mean_overall=61.5, clock_2030=1,
                      hndl_priority=0, blocked=1)
        ]  # fmt: skip


@pytest.mark.parametrize("products", [(), (uuid4(), uuid4())])
def test_pqc_rolls_up_each_named_product_else_every_commit(products: tuple[UUID, ...]) -> None:
    pqc = FakePqc()
    model = PqcView(pqc).build(ViewFilter(product_ids=(*products, *products)))  # type: ignore[arg-type]
    expected = list(products) or [None]
    assert [s.product_id for s in model.scopes] == expected
    assert pqc.asked == [(p, d) for p in expected for d in PqcDimension]
    assert "| bucket | 2 | 61.5 | 1 | 0 | 1 |" in md(PqcView(FakePqc()))  # type: ignore[arg-type]


@dataclass
class FakeCompliance:
    def summary(self, filter: Any, group_by: ComplianceDimension) -> list[ComplianceRollup]:
        coverage = {"nist-800-53": {"pass": 4, "fail": 1}}
        return [ComplianceRollup(key=str(group_by), pairs=2, assessed=1, coverage=coverage)]


def test_compliance_posture_per_framework_and_boundary() -> None:
    model = ComplianceDashboardView(FakeCompliance()).build(ViewFilter())  # type: ignore[arg-type]
    assert [r.key for r in (*model.by_framework, *model.by_scope)] == ["framework", "scope"]
    text = md(ComplianceDashboardView(FakeCompliance()))  # type: ignore[arg-type]
    assert "| framework | 2 | 1 | nist-800-53: fail 1, pass 4 |" in text


@pytest.mark.parametrize(
    ("view", "filter", "error"),
    [
        (ExposureView(FakeExposure()), ViewFilter(product_ids=(uuid4(),)), "fleet-wide"),  # type: ignore[arg-type]
        (ComplianceDashboardView(FakeCompliance()), ViewFilter(team_ids=(uuid4(),)), "fleet-wide"),  # type: ignore[arg-type]
        (PqcView(FakePqc()), ViewFilter(team_ids=(uuid4(),)), "not team"),  # type: ignore[arg-type]
    ],
)
def test_views_refuse_a_scope_their_domain_cannot_cut(
    view: Any, filter: ViewFilter, error: str
) -> None:
    with pytest.raises(ValidationError, match=error):
        view.build(filter)


@dataclass
class FakeAssessment:
    asked: list[tuple[Any, list[UUID]]] = field(default_factory=list)

    def population(self, as_of: Any, filter: Any, repository_ids: Any) -> Population:
        self.asked.append((as_of, list(repository_ids)))
        ids = list(repository_ids)
        return Population(
            as_of=as_of,
            rows=(PopulationRow(repository_id=ids[0], kind="secure-code", latest=None),),
            never_assessed_repository_ids=tuple(ids),
        )

    def coverage(self, filter: Any, repository_ids: Any) -> Coverage:
        gap = CoverageGap(tool="opengrep", system="kotlin", repositories=1, signals={})
        return Coverage(examined=1, total=2, gaps=(gap,))


def test_coverage_counts_the_scope_as_of_its_point_in_time() -> None:
    a, b = uuid4(), uuid4()
    portfolio = FakePortfolio(
        repositories={a: "https://forge.example/o/a", b: "https://forge.example/o/b"}
    )
    assessment = FakeAssessment()
    view = CoverageView(assessment, portfolio, FixedClock(T0))  # type: ignore[arg-type]
    model = view.build(ViewFilter())
    assert model.repositories == 2
    assert assessment.asked == [(T0, [a, b])]
    view.build(ViewFilter(as_of=T0.replace(year=2025)))
    assert assessment.asked[-1][0].year == 2025
    text = md(view)
    assert "2 never assessed" in text and "| opengrep | kotlin | 1 | - |" in text
    assert "_Nothing assessed._" in text


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def test_each_domain_view_renders_through_context(engine: Engine, tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0))
    ctx.__dict__["database"] = engine
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).repository(url="https://github.com/example-org/svc")
        uow.commit()
    views = [ViewName.COVERAGE, ViewName.EXPOSURE, ViewName.PQC, ViewName.COMPLIANCE]
    result = ctx.services().insight.refresh(views, ViewFilter())
    assert result.failed == {}
    assert set(result.rendered) == set(views)
    assert "1 never assessed" in result.rendered[ViewName.COVERAGE].markdown
    assert "_No impact analyses recorded._" in result.rendered[ViewName.EXPOSURE].markdown


def test_exposure_reads_the_analyses_as_of_the_views_point_in_time() -> None:
    seen: list[ExposureFilter] = []

    class AsOf(FakeExposure):
        def summary(self, filter: Any, group_by: ExposureDimension) -> list[ExposureRollup]:
            seen.append(filter)
            return []

    ExposureView(AsOf()).build(ViewFilter(as_of=T0))  # type: ignore[arg-type]
    assert seen and {f.as_of for f in seen} == {T0}
