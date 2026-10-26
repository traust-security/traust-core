"""PortfolioService.list_products_of: the products shipping any commit of a repository, the
question repo-graph's `ships` edges answered for fleet-fix reach and CVE enrichment."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


def test_products_shipping_any_commit_come_back_once_by_slug(
    service: PortfolioService, seed: Seed
) -> None:
    repo, other = seed.repository(), seed.repository()
    main = seed.repository_ref(repo, is_default=True)
    tag = seed.repository_ref(repo, name="v1", kind="tag", sha="b" * 40)
    zeta, alpha, elsewhere = (seed.product(slug=s) for s in ("zeta", "alpha", "elsewhere"))
    for release, ref in (
        (seed.release(zeta, version="1"), main),
        (seed.release(zeta, version="2"), tag),
        (seed.release(alpha, version="1"), tag),
        (seed.release(elsewhere, version="1"), seed.repository_ref(other)),
    ):
        seed.component(release, ref)
    assert [p.slug for p in service.list_products_of(repo.id)] == ["alpha", "zeta"]


@pytest.mark.parametrize("refs", [0, 1], ids=["no refs", "unshipped ref"])
def test_a_repository_nothing_ships_has_no_products(
    service: PortfolioService, seed: Seed, refs: int
) -> None:
    repo = seed.repository()
    for _ in range(refs):
        seed.repository_ref(repo)
    assert service.list_products_of(repo.id) == []


def test_an_unknown_repository_is_not_found(service: PortfolioService) -> None:
    with pytest.raises(NotFoundError):
        service.list_products_of(uuid4())
