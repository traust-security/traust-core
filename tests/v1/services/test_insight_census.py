"""The census view (harnessing/census build_census.py, traust fabdb13): distinct vulnerabilities
per corpus ownership class over the population, through Context on SQLite and Postgres."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.context import Config, Context
from traust_core.v1.models.insight import (
    Census,
    CensusCut,
    CensusLayer,
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
OWNED, UPSTREAM, EXTERNAL = (
    OwnershipClass.OWNED,
    OwnershipClass.UPSTREAM,
    OwnershipClass.EXTERNAL_BU,
)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    ctx = Context(Config(home=tmp_path), clock=FixedClock(T0 + 20 * DAY))
    ctx.__dict__["database"] = engine
    return ctx


def register(context: Context, slug: str, ownership: OwnershipClass) -> Any:
    product, _ = context.services().portfolio.register_corpus_product(
        ProductSlug.parse(slug), slug.title(), ownership, f"{slug} unit"
    )
    return product


def corpus(context: Context, engine: Engine) -> dict[str, Any]:
    """Owned `svc` (two default-line audits, a branch re-audit, IaC and image scans), upstream
    `lib`, an external-BU audit with nothing found, and a repository no product ships."""
    core, oss, partner = (
        register(context, "core", OWNED),
        register(context, "oss", UPSTREAM),
        register(context, "partner", EXTERNAL),
    )
    with SqlTraustUnitOfWork(engine) as uow:
        s = Seed(uow)
        svc = s.repository(url="https://github.com/example-org/svc")
        head = s.repository_ref(svc, is_default=True)
        branch = s.repository_ref(svc, name="release-1", sha="b" * 40)
        s.component(s.release(core), head)
        first = s.assessment(head, kind="secure-code", occurred_at=T0)
        second = s.assessment(head, kind="secure-code", occurred_at=T0 + 2 * DAY)
        reaudit = s.assessment(branch, kind="secure-code", occurred_at=T0 + 2 * DAY)
        iac = s.assessment(head, kind="cloud-config", occurred_at=T0)
        image = s.assessment(head, kind="container", occurred_at=T0)

        def found(title: str, severity: str, *where: Any, **decided: Any) -> None:
            finding = s.finding(svc, title=title)
            for assessment in where:
                s.occurrence(finding, assessment, severity=severity)
            if decided:
                s.decision(finding, actor=HUMAN, occurred_at=T0 + DAY, **decided)

        found("Restated", "high", first, second, reaudit)
        found("Fixed", "critical", first, validity="confirmed", resolution="resolved")
        found("Not real", "high", first, validity="false_positive")
        found("Posture", "medium", first, validity="hardening")
        found("Branch only", "low", reaudit)
        found("Open bucket", "medium", iac)
        found("Image noise", "high", image, validity="false_positive")

        lib = s.repository(url="https://github.com/example-org/lib")
        lib_head = s.repository_ref(lib, is_default=True)
        s.component(s.release(oss), lib_head)
        upstream = s.finding(lib, title="Upstream")
        s.occurrence(upstream, s.assessment(lib_head, kind="secure-code"), severity="low")

        ext = s.repository(url="https://github.com/example-org/ext")
        ext_head = s.repository_ref(ext, is_default=True)
        s.component(s.release(partner), ext_head)
        s.assessment(ext_head, kind="secure-code")

        s.repository(url="https://github.com/example-org/stray")
        team = s.team()
        s.ownership(lib, team, valid_from=T0 - DAY)
        uow.commit()
    return {"core": core, "team": team}


def census(context: Context, scope: ViewFilter | None = None) -> Census:
    built = context.services().insight.build(ViewName.CENSUS, scope or ViewFilter())
    assert isinstance(built, Census)
    return built


def test_the_census_cuts_distinct_vulnerabilities_by_ownership(
    context: Context, engine: Engine
) -> None:
    corpus(context, engine)
    model = census(context)

    by = {c.ownership: c for c in model.cuts}
    assert by[OWNED] == CensusCut(
        ownership=OWNED,
        products=1,
        repositories=1,
        audited=1,
        audits=2,
        branch_audits=1,
        distinct=SeverityCounts(critical=1, high=1),
        open=SeverityCounts(high=1),
        occurrences=3,
        hardening=1,
        false_positives=1,
        dispositioned=1,
        branch_confirmed=1,
        branch_only=1,
    )
    assert (by[UPSTREAM].distinct, by[UPSTREAM].open) == (SeverityCounts(low=1),) * 2
    assert (by[EXTERNAL].audits, by[EXTERNAL].distinct.total) == (1, 0)
    assert by[None].repositories == 1 and by[None].audits == 0
    assert list(by) == [OWNED, UPSTREAM, EXTERNAL, None]
    assert model.cloud_config == CensusLayer(findings=SeverityCounts(medium=1))
    assert model.container == CensusLayer(false_positives=1)
    assert model.unregistered == ("https://github.com/example-org/stray",)
    assert (model.repositories, model.reported, model.never_assessed) == (4, 2, 1)
    assert [(p.slug, p.ownership, p.business_unit, p.repositories) for p in model.products] == [
        ("core", OWNED, "core unit", 1),
        ("oss", UPSTREAM, "oss unit", 1),
        ("partner", EXTERNAL, "partner unit", 1),
    ]


def test_the_census_reads_assessments_and_ownership_as_of(context: Context, engine: Engine) -> None:
    corpus(context, engine)
    (before,) = census(context, ViewFilter(as_of=T0 + DAY)).cuts  # the registry came later
    assert before.ownership is None
    assert (before.audits, before.branch_audits, before.occurrences) == (3, 0, 3)
    assert (before.branch_confirmed, before.branch_only) == (0, 0)

    registered = datetime.now(UTC)
    apart()
    context.services().portfolio.update_corpus_product(
        ProductSlug.parse("core"), ownership=UPSTREAM
    )
    now = census(context)
    then = census(context, ViewFilter(as_of=registered))
    assert next(c for c in now.cuts if c.ownership is UPSTREAM).repositories == 2
    assert next(c for c in then.cuts if c.ownership is OWNED).repositories == 1


def test_a_product_or_team_scope_narrows_the_population(context: Context, engine: Engine) -> None:
    seeded = corpus(context, engine)
    product = census(context, ViewFilter(product_ids=(seeded["core"].id,)))
    assert [c.ownership for c in product.cuts] == [OWNED]
    assert [p.slug for p in product.products] == ["core"]

    team = census(context, ViewFilter(team_ids=(seeded["team"].id,)))
    assert [(c.ownership, c.repositories) for c in team.cuts] == [(UPSTREAM, 1)]
    assert [p.slug for p in team.products] == ["oss"]
    assert team.unregistered == ()


def test_an_empty_corpus_renders(context: Context) -> None:
    rendered = context.services().insight.publish(ViewName.CENSUS, ViewFilter())
    model = rendered.model
    assert isinstance(model, Census)
    assert (model.repositories, model.cuts, model.products) == (0, (), ())
    assert rendered.stem == "census"
    assert "**0 distinct owned vulnerabilities**" in rendered.markdown
    assert "_No repositories in scope._" in rendered.markdown


def test_the_census_report_carries_the_headline_and_the_cuts(
    context: Context, engine: Engine
) -> None:
    corpus(context, engine)
    md = context.services().insight.publish(ViewName.CENSUS, ViewFilter()).markdown
    assert "**2 distinct owned vulnerabilities**, 1 open (0 critical, 1 high" in md
    assert "Upstream, adjacent and never folded in: 1 distinct, 1 open" in md
    assert "External business units, work performed only: 1 secure-code audits" in md
    assert "| owned | 1 | 1 | 2 | 2 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 3 |" in md
    assert "| owned | 1 | 1 | 1 |" in md
    assert "| cloud-config (declared IaC) | 1 | 0 | 0 | 1 | 0 | 0 | 0 |" in md
    assert "| https://github.com/example-org/stray |" in md
