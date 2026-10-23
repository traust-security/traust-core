from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.models.inventory import ProductSlug
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


@pytest.mark.parametrize("slug", ["a", "contoso", "contoso-findings", "v4.16_x", "9lives"])
def test_register_product_accepts_slugs(service: PortfolioService, slug: str) -> None:
    assert service.register_product(ProductSlug(slug), "Name").slug == slug


@pytest.mark.parametrize(
    "slug", [".hidden", "-flag", "_x", "has space", "bad/name", "ünicode", "tab\t", "a\n"]
)
def test_register_product_rejects_slugs_outside_the_name_syntax(
    service: PortfolioService, uow: SqlTraustUnitOfWork, slug: str
) -> None:
    with pytest.raises(ValidationError, match=r"product\.slug"):
        service.register_product(ProductSlug(slug), "Name")
    assert uow.products.list_after(None, 10) == []


def test_find_product_by_slug(service: PortfolioService, seed: Seed) -> None:
    product = seed.product(slug="contoso")
    assert service.find_product(ProductSlug("contoso")) == product
    assert service.find_product(ProductSlug("missing")) is None


def test_update_product_renames_and_keeps_the_slug(
    service: PortfolioService, uow: SqlTraustUnitOfWork
) -> None:
    product = service.register_product(ProductSlug("contoso"), "Contoso")
    renamed = service.update_product(product.id, "Contoso OSS Initiative")
    assert (renamed.id, renamed.slug, renamed.name) == (
        product.id,
        "contoso",
        "Contoso OSS Initiative",
    )
    assert uow.products.get(product.id) == renamed
    assert service.register_product(ProductSlug("contoso"), "Other") == renamed


def test_update_product_refuses_unknown_ids_and_blank_names(
    service: PortfolioService, seed: Seed
) -> None:
    product = seed.product()
    with pytest.raises(NotFoundError):
        service.update_product(uuid4(), "Name")
    for name in ("", "  ", None):
        with pytest.raises(ValidationError):
            service.update_product(product.id, name)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        service.update_product("not-a-uuid", "Name")  # type: ignore[arg-type]
    assert seed.uow.products.get(product.id) == product


def test_failed_rename_commit_rolls_back(engine: object, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = SqlTraustUnitOfWork(engine)  # type: ignore[arg-type]
    product = PortfolioService(unit, PortfolioPolicy()).register_product(
        ProductSlug("rollback"), "Before"
    )
    monkeypatch.setattr(unit, "commit", Mock(side_effect=RepositoryError("commit failed")))
    with pytest.raises(RepositoryError, match="commit failed"):
        PortfolioService(unit, PortfolioPolicy()).update_product(product.id, "After")
    with unit:
        assert unit.products.get(product.id).name == "Before"


def test_list_products_pages_by_slug(service: PortfolioService, seed: Seed) -> None:
    c, a, b = (seed.product(slug=s) for s in ("c", "a", "b"))
    first = service.list_products(PageRequest(limit=2))
    assert (first.items, first.next) == ((a, b), Cursor("b"))
    last = service.list_products(PageRequest(limit=2, cursor=first.next))
    assert (last.items, last.next) == ((c,), None)
    exact = service.list_products(PageRequest(limit=3))
    assert (exact.items, exact.next) == ((a, b, c), None)


def test_list_products_is_empty_without_products(service: PortfolioService) -> None:
    page = service.list_products(PageRequest())
    assert (page.items, page.next) == ((), None)


@pytest.mark.parametrize("limit", [0, -1])
def test_list_products_refuses_a_non_positive_limit(service: PortfolioService, limit: int) -> None:
    with pytest.raises(ValidationError):
        service.list_products(PageRequest(limit=limit))
