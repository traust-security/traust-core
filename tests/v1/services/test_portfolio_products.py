from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.artifacts import CorpusRegistryArtifact
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.models.inventory import Product, ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass
from traust_core.v1.repositories import InMemoryObjectStore
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import ArtifactPublisher, PublishSpec, PublishSpecs
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


class StepClock:
    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        self.at += timedelta(minutes=1)
        return self.at


@pytest.fixture
def registry(uow: SqlTraustUnitOfWork) -> PortfolioService:
    publisher = ArtifactPublisher(
        PublishSpecs(PublishSpec(CorpusRegistryArtifact)), InMemoryObjectStore(), uow
    )
    return PortfolioService(uow, PortfolioPolicy(), clock=StepClock(), publisher=publisher)


def subjects(service: PortfolioService) -> list[tuple[str, str, str, str]]:
    doc = service.corpus_registry()
    assert doc is not None
    return [(s.subject_id, s.tree, s.ownership, s.business_unit) for s in doc.subjects]


def registries(uow: SqlTraustUnitOfWork) -> int:
    table = uow.artifacts.table
    rows = uow.connection.execute(table.select().where(table.c.kind == "corpus-registry"))
    return len(rows.all())


def test_corpus_registry_is_empty_until_ownership_is_set(registry: PortfolioService) -> None:
    assert registry.corpus_registry() is None


def test_set_corpus_ownership_publishes_one_subject_per_product(
    registry: PortfolioService, seed: Seed, uow: SqlTraustUnitOfWork
) -> None:
    contoso, ansible = seed.product(slug="contoso"), seed.product(slug="ansible")
    doc = registry.set_corpus_ownership(contoso.id, OwnershipClass("external-bu"), "Contoso")
    assert doc.subjects[0].label is None and doc.subjects[0].product is None
    apart()
    registry.set_corpus_ownership(ansible.id, OwnershipClass("owned"), "Ansible")
    expected = sorted(
        [
            (str(contoso.id), "contoso", "external-bu", "Contoso"),
            (str(ansible.id), "ansible", "owned", "Ansible"),
        ]
    )
    assert subjects(registry) == expected
    assert registries(uow) == 2


def test_unchanged_ownership_publishes_nothing(
    registry: PortfolioService, seed: Seed, uow: SqlTraustUnitOfWork
) -> None:
    product = seed.product()
    first = registry.set_corpus_ownership(product.id, OwnershipClass("owned"), "BU")
    again = registry.set_corpus_ownership(product.id, OwnershipClass("owned"), "BU")
    assert again.payload == first.payload
    assert registries(uow) == 1


def test_reverting_ownership_makes_the_old_values_latest_again(
    registry: PortfolioService, seed: Seed, uow: SqlTraustUnitOfWork
) -> None:
    product = seed.product(slug="contoso")
    for ownership, unit in (("owned", "A"), ("upstream", "B"), ("owned", "A")):
        registry.set_corpus_ownership(product.id, OwnershipClass(ownership), unit)
        apart()
    assert subjects(registry) == [(str(product.id), "contoso", "owned", "A")]
    assert registries(uow) == 3


@pytest.mark.parametrize("ownership", ["owned", "external", "", None])
def test_set_corpus_ownership_requires_the_contracts_enum(
    registry: PortfolioService, seed: Seed, ownership: object
) -> None:
    with pytest.raises(ValidationError, match="ownership"):
        registry.set_corpus_ownership(seed.product().id, ownership, "BU")  # type: ignore[arg-type]
    assert registry.corpus_registry() is None


@pytest.mark.parametrize("business_unit", ["", "  ", None])
def test_set_corpus_ownership_requires_a_business_unit(
    registry: PortfolioService, seed: Seed, business_unit: object
) -> None:
    with pytest.raises(ValidationError, match="business_unit"):
        registry.set_corpus_ownership(
            seed.product().id,
            OwnershipClass("owned"),
            business_unit,  # type: ignore[arg-type]
        )
    assert registry.corpus_registry() is None


def test_set_corpus_ownership_refuses_an_unknown_product(registry: PortfolioService) -> None:
    with pytest.raises(NotFoundError):
        registry.set_corpus_ownership(uuid4(), OwnershipClass("owned"), "BU")
    assert registry.corpus_registry() is None


def test_corpus_registry_needs_a_publisher(service: PortfolioService, seed: Seed) -> None:
    with pytest.raises(ConfigError):
        service.corpus_registry()
    with pytest.raises(ConfigError):
        service.set_corpus_ownership(seed.product().id, OwnershipClass("owned"), "BU")


def test_context_wires_the_corpus_registry(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path), object_store=InMemoryObjectStore())
    portfolio = context.services().portfolio
    product: Product = portfolio.register_product(ProductSlug("contoso"), "Contoso")
    portfolio.set_corpus_ownership(product.id, OwnershipClass("harness-qa"), "QA")
    assert subjects(portfolio) == [(str(product.id), "contoso", "harness-qa", "QA")]
