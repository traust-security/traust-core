"""The pqc-portfolio view over real PqcService reads on SQLite and Postgres: ranked repositories,
clock items, harvest risk, sites, crypto packages and the per-product index."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_pqc import (
    PROVENANCE,
    REPORT,
    URL,
    World,
    engine,  # noqa: F401
    report,
)
from tests.v1.services.test_pqc_rules import STAMPS, census, hit, scan
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import CryptoProbeId
from traust_core.v1.models.insight import ViewFilter
from traust_core.v1.models.pqc import PqcSiteKind
from traust_core.v1.rendering import MarkdownRenderer
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.insight import PqcPortfolioView
from traust_core.v1.services.pqc import facts as pqc_facts

HNDL = {"has_2030_clock_items": False, "hndl_priority": True, "runtime_verification_required": True}
FIPS = {"verdict": "blocked-by-provider-version", "fact_ids": ["F0001"]}


def meta(url: str) -> dict[str, object]:
    return {**REPORT["metadata"], "repository": url}


def test_the_portfolio_ranks_each_scope_worst_first(engine: Engine) -> None:  # noqa: F811
    world = World(engine, None)
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        product, idle = seed.product(), seed.product()
        release = seed.release(product)
        uow.commit()
    shipped, risky = world.ref(), world.ref(url=f"{URL}-b", sbom=None)
    unscored = world.ref(url=f"{URL}-c")
    with SqlTraustUnitOfWork(engine) as uow:
        Seed(uow).component(release, uow.repository_refs.get(shipped))
        uow.commit()
    world.pqc.record(shipped, report(), PROVENANCE)
    worse = report(
        metadata=meta(f"{URL}-b"), flags=HNDL, fips_interaction=FIPS, clock_items=[],
        scores={**REPORT["scores"], "overall": 31}, readiness_bucket="blocked-external",
    )  # fmt: skip
    world.pqc.record(risky, worse, PROVENANCE)
    pins = scan(hit("HP_GROUPS_GO_CURVEPREFERENCES", "pkg/server/tls.go", 88))
    go = [census(CryptoProbeId.GO_TOOLCHAIN, "go 1.21", version="1.21")]
    doc = pqc_facts.facts_document(f"{URL}-c", STAMPS, pqc_facts.source_facts(pins, go), pins)
    world.pqc.record(unscored, doc, PROVENANCE)
    view = PqcPortfolioView(world.pqc, world.code_facts, world.portfolio)

    fleet = view.build(ViewFilter())
    [scope] = fleet.scopes
    assert [r.repository_url for r in scope.repositories] == [f"{URL}-b", URL]
    assert [(s.repository_url, s.site.kind) for s in scope.sites] == [
        (f"{URL}-c", PqcSiteKind.GROUP_PIN),
        (f"{URL}-c", PqcSiteKind.TOOLCHAIN),
    ]
    assert scope.without_sbom == 1
    assert scope.packages and all(p.repositories == 1 for p in scope.packages)
    assert [(p.product, p.repositories, p.worst_url) for p in fleet.products] == [
        (product.slug, 1, URL)
    ]
    assert idle.slug not in {p.product for p in fleet.products}

    text = MarkdownRenderer().render(view.report(fleet, T0)).decode()
    for expected in (
        f"| {URL}-b | Blocked on upstream | 31 | yes | 0 |",
        f"| {URL} | RSA-2048 | moderate |",
        "| Blocked: crypto library too old for PQC+FIPS | Blocked on upstream | 1 |",
        f"| {URL}-c | HP_GROUPS_GO_CURVEPREFERENCES | pkg/server/tls.go:88 |",
        f"| {URL}-c | go 1.21 | go.mod:1 |",
        "| this repo's own code | 0 | 2 |",
        f"Blocked on upstream (1 repos)\n\n{URL}-b",
        "1 repositories.",
        f"| {product.slug} | 1 | 0 | 0 | 1 | {URL} (57.5) |",
    ):
        assert expected in text, expected

    assert product.id is not None
    only = view.build(ViewFilter(product_ids=(product.id, product.id)))
    assert only.products == ()
    assert [r.repository_url for r in only.scopes[0].repositories] == [URL]
    assert only.scopes[0].sites == ()


def test_an_empty_portfolio_says_so(engine: Engine) -> None:  # noqa: F811
    world = World(engine, None)
    view = PqcPortfolioView(world.pqc, world.code_facts, world.portfolio)
    model = view.build(ViewFilter())
    assert model.scopes[0].repositories == () and model.products == ()
    text = MarkdownRenderer().render(view.report(model, T0)).decode()
    assert "_No readiness recorded._" in text and "Without a manifest SBOM" not in text


@pytest.mark.parametrize(
    ("filter", "error"),
    [(ViewFilter(team_ids=(uuid4(),)), "not team"), (ViewFilter(as_of=T0), "no as_of")],
)
def test_the_portfolio_refuses_a_scope_it_cannot_cut(
    engine: Engine,  # noqa: F811
    filter: ViewFilter,
    error: str,
) -> None:
    world = World(engine, None)
    with pytest.raises(ValidationError, match=error):
        PqcPortfolioView(world.pqc, world.code_facts, world.portfolio).build(filter)
