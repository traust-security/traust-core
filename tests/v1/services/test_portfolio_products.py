from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import (
    ConfigError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    RepositoryError,
    ValidationError,
)
from traust_core.v1.models.artifacts import CorpusRegistryArtifact
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.models.inventory import Product, ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass
from traust_core.v1.providers.clock import Clock, FixedClock
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


def corpus_publisher(uow: SqlTraustUnitOfWork) -> ArtifactPublisher:
    return ArtifactPublisher(
        PublishSpecs(PublishSpec(CorpusRegistryArtifact)), InMemoryObjectStore(), uow
    )


def corpus_service(
    uow: SqlTraustUnitOfWork, publisher: ArtifactPublisher, clock: Clock | None = None
) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy(), clock=clock or StepClock(), publisher=publisher)


def test_set_corpus_ownership_requires_a_product_uuid(registry: PortfolioService) -> None:
    with pytest.raises(ValidationError, match=r"product\.id"):
        registry.set_corpus_ownership("not-a-uuid", OwnershipClass("owned"), "BU")  # type: ignore[arg-type]
    assert registry.corpus_registry() is None


@pytest.mark.parametrize("existing", [False, True])
def test_a_write_interleaved_after_the_read_raises_conflict(
    uow: SqlTraustUnitOfWork, seed: Seed, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    contoso, ansible = seed.product(slug="contoso"), seed.product(slug="ansible")
    publisher = corpus_publisher(uow)
    first, second = corpus_service(uow, publisher), corpus_service(uow, publisher)
    if existing:
        first.set_corpus_ownership(contoso.id, OwnershipClass("upstream"), "Before")
        apart()
    read = publisher.latest_imported

    def read_then_interleave(artifact: type[CorpusRegistryArtifact]) -> object:
        seen = read(artifact)
        monkeypatch.setattr(publisher, "latest_imported", read)
        second.set_corpus_ownership(ansible.id, OwnershipClass("owned"), "Ansible")
        apart()
        return seen

    monkeypatch.setattr(publisher, "latest_imported", read_then_interleave)
    with pytest.raises(ConflictError, match="another writer"):
        first.set_corpus_ownership(contoso.id, OwnershipClass("external-bu"), "Contoso")
    kept = [(str(ansible.id), "ansible", "owned", "Ansible")]
    if existing:
        kept = sorted([*kept, (str(contoso.id), "contoso", "upstream", "Before")])
    assert subjects(first) == kept
    assert registries(uow) == (2 if existing else 1)


def test_editing_one_product_keeps_every_other_subject_and_the_note_as_stored(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    contoso, ansible = seed.product(slug="contoso"), seed.product(slug="ansible")
    publisher = corpus_publisher(uow)
    stored = {
        "subject_id": str(contoso.id),
        "tree": "contoso",
        "ownership": "external-bu",
        "business_unit": "Contoso",
        "label": "Contoso OSS",
        "repo_url": "https://github.com/contoso/app",
        "ref_kind": "tag",
        "is_branch_audit": False,
    }
    publisher.publish_artifact(
        CorpusRegistryArtifact.from_document(
            {"version": 1, "note": "declared by the deployment", "subjects": [stored]}
        )
    )
    apart()
    doc = corpus_service(uow, publisher).set_corpus_ownership(
        ansible.id, OwnershipClass("owned"), "Ansible"
    )
    published = json.loads(doc.payload)
    assert published["note"] == "declared by the deployment"
    assert stored in published["subjects"]
    assert {
        "subject_id": str(ansible.id),
        "tree": "ansible",
        "ownership": "owned",
        "business_unit": "Ansible",
    } in published["subjects"]
    latest = publisher.latest(CorpusRegistryArtifact)
    assert latest is not None and latest.payload == doc.payload


def test_editing_a_product_keeps_its_own_stored_fields_this_door_does_not_write(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    contoso = seed.product(slug="contoso")
    publisher = corpus_publisher(uow)
    publisher.publish_artifact(
        CorpusRegistryArtifact.from_document(
            {
                "version": 1,
                "subjects": [
                    {
                        "subject_id": str(contoso.id),
                        "tree": "contoso",
                        "ownership": "owned",
                        "business_unit": "A",
                        "label": "Contoso OSS",
                    }
                ],
            }
        )
    )
    apart()
    doc = corpus_service(uow, publisher).set_corpus_ownership(
        contoso.id, OwnershipClass("upstream"), "B"
    )
    (subject,) = doc.subjects
    assert (subject.ownership, subject.business_unit, subject.label) == (
        "upstream",
        "B",
        "Contoso OSS",
    )


def test_a_revert_under_a_fixed_clock_refuses_to_resurrect_the_old_row(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    product = seed.product(slug="contoso")
    publisher = corpus_publisher(uow)
    service = corpus_service(uow, publisher, FixedClock(T0))
    service.set_corpus_ownership(product.id, OwnershipClass("owned"), "A")
    apart()
    service.set_corpus_ownership(product.id, OwnershipClass("upstream"), "B")
    apart()
    with pytest.raises(IntegrityError, match="not the newest"):
        service.set_corpus_ownership(product.id, OwnershipClass("owned"), "A")
    assert subjects(service) == [(str(product.id), "contoso", "upstream", "B")]
    assert registries(uow) == 2


def owned(service: PortfolioService, slug: str) -> tuple[str, str | None, str | None]:
    product = service.find_product(ProductSlug.parse(slug))
    assert product is not None
    doc = service.corpus_registry()
    subject = (
        None
        if doc is None
        else next((s for s in doc.subjects if s.subject_id == str(product.id)), None)
    )
    return (
        product.name,
        None if subject is None else str(subject.ownership),
        None if subject is None else subject.business_unit,
    )


def test_register_corpus_product_records_the_product_and_its_ownership(
    registry: PortfolioService, uow: SqlTraustUnitOfWork
) -> None:
    product, subject = registry.register_corpus_product(
        ProductSlug.parse("contoso"), "Contoso", OwnershipClass("external-bu"), "Contoso BU"
    )
    assert (product.slug, product.name) == ("contoso", "Contoso")
    assert (subject.tree, subject.ownership, subject.business_unit) == (
        "contoso",
        "external-bu",
        "Contoso BU",
    )
    assert subjects(registry) == [(str(product.id), "contoso", "external-bu", "Contoso BU")]
    assert registries(uow) == 1


def test_register_corpus_product_again_with_the_same_fields_writes_nothing(
    registry: PortfolioService, uow: SqlTraustUnitOfWork
) -> None:
    args = (ProductSlug.parse("contoso"), "Contoso", OwnershipClass("owned"), "BU")
    first = registry.register_corpus_product(*args)
    apart()
    assert registry.register_corpus_product(*args) == first
    assert registries(uow) == 1


@pytest.mark.parametrize(
    ("label", "ownership", "business_unit"),
    [("Renamed", "owned", "BU"), ("Contoso", "upstream", "BU"), ("Contoso", "owned", "Other")],
    ids=["label", "ownership", "business_unit"],
)
def test_register_corpus_product_with_different_fields_is_a_conflict_naming_update(
    registry: PortfolioService,
    uow: SqlTraustUnitOfWork,
    label: str,
    ownership: str,
    business_unit: str,
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_corpus_product(slug, "Contoso", OwnershipClass("owned"), "BU")
    apart()
    with pytest.raises(ConflictError, match=r"already registered.*with update"):
        registry.register_corpus_product(slug, label, OwnershipClass(ownership), business_unit)
    assert owned(registry, "contoso") == ("Contoso", "owned", "BU")
    assert registries(uow) == 1


def test_register_corpus_product_completes_a_product_without_ownership(
    registry: PortfolioService, uow: SqlTraustUnitOfWork
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_product(slug, "Contoso")
    registry.register_corpus_product(slug, "Contoso", OwnershipClass("upstream"), "BU")
    assert owned(registry, "contoso") == ("Contoso", "upstream", "BU")
    assert registries(uow) == 1


def test_register_corpus_product_refuses_another_label_for_a_product_without_ownership(
    registry: PortfolioService,
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_product(slug, "Contoso")
    with pytest.raises(ConflictError, match="with update"):
        registry.register_corpus_product(slug, "Other", OwnershipClass("owned"), "BU")
    assert owned(registry, "contoso") == ("Contoso", None, None)
    assert registry.corpus_registry() is None


@pytest.mark.parametrize(
    ("label", "ownership", "business_unit", "error"),
    [
        ("", OwnershipClass("owned"), "BU", r"product\.name"),
        ("Contoso", "owned", "BU", "corpus ownership"),
        ("Contoso", None, "BU", "corpus ownership"),
        ("Contoso", OwnershipClass("owned"), " ", r"corpus\.business_unit"),
    ],
)
def test_register_corpus_product_validates_before_any_write(
    registry: PortfolioService, label: str, ownership: object, business_unit: str, error: str
) -> None:
    slug = ProductSlug.parse("contoso")
    with pytest.raises(ValidationError, match=error):
        registry.register_corpus_product(slug, label, ownership, business_unit)  # type: ignore[arg-type]
    assert registry.find_product(slug) is None
    assert registry.corpus_registry() is None


@pytest.mark.parametrize(
    ("change", "after"),
    [
        ({}, ("Contoso", "owned", "BU")),
        ({"label": "Renamed"}, ("Renamed", "owned", "BU")),
        ({"ownership": OwnershipClass("upstream")}, ("Contoso", "upstream", "BU")),
        ({"business_unit": "Other"}, ("Contoso", "owned", "Other")),
        (
            {"label": "Renamed", "ownership": OwnershipClass("harness-qa"), "business_unit": "QA"},
            ("Renamed", "harness-qa", "QA"),
        ),
        ({"label": "Contoso", "ownership": OwnershipClass("owned")}, ("Contoso", "owned", "BU")),
    ],
    ids=["nothing", "label", "ownership", "business_unit", "all", "same"],
)
def test_update_corpus_product_changes_only_the_fields_given(
    registry: PortfolioService,
    uow: SqlTraustUnitOfWork,
    change: dict[str, object],
    after: tuple[str, str, str],
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_corpus_product(slug, "Contoso", OwnershipClass("owned"), "BU")
    apart()
    product, subject = registry.update_corpus_product(slug, **change)  # type: ignore[arg-type]
    assert subject is not None
    assert (product.name, str(subject.ownership), subject.business_unit) == after
    assert owned(registry, "contoso") == after
    assert registries(uow) == (1 if after[1:] == ("owned", "BU") else 2)


def test_update_corpus_product_refuses_an_unknown_slug(registry: PortfolioService) -> None:
    with pytest.raises(NotFoundError, match="no product named 'nope'"):
        registry.update_corpus_product(ProductSlug.parse("nope"), ownership=OwnershipClass("owned"))


@pytest.mark.parametrize(
    "change",
    [{"ownership": OwnershipClass("owned")}, {"business_unit": "BU"}],
    ids=["ownership", "business_unit"],
)
def test_update_corpus_product_without_ownership_needs_both_fields_and_writes_nothing(
    registry: PortfolioService, change: dict[str, object]
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_product(slug, "Contoso")
    with pytest.raises(ValidationError, match="give both fields"):
        registry.update_corpus_product(slug, **{"label": "Renamed", **change})  # type: ignore[arg-type]
    assert owned(registry, "contoso") == ("Contoso", None, None)


def test_update_corpus_product_gives_ownership_to_a_product_without_it(
    registry: PortfolioService,
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_product(slug, "Contoso")
    product, subject = registry.update_corpus_product(slug, label="Renamed")
    assert (product.name, subject) == ("Renamed", None)
    registry.update_corpus_product(slug, ownership=OwnershipClass("owned"), business_unit="BU")
    assert owned(registry, "contoso") == ("Renamed", "owned", "BU")


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"label": " "}, r"product\.name"),
        ({"ownership": "owned"}, "corpus ownership"),
        ({"business_unit": ""}, r"corpus\.business_unit"),
    ],
)
def test_update_corpus_product_validates_before_any_write(
    registry: PortfolioService, uow: SqlTraustUnitOfWork, change: dict[str, object], error: str
) -> None:
    slug = ProductSlug.parse("contoso")
    registry.register_corpus_product(slug, "Contoso", OwnershipClass("owned"), "BU")
    with pytest.raises(ValidationError, match=error):
        registry.update_corpus_product(slug, **{"label": "Renamed", **change})  # type: ignore[arg-type]
    assert owned(registry, "contoso") == ("Contoso", "owned", "BU")
    assert registries(uow) == 1


@pytest.mark.parametrize("door", ["register", "update"])
def test_a_concurrent_corpus_product_write_raises_conflict_instead_of_overwriting(
    uow: SqlTraustUnitOfWork, monkeypatch: pytest.MonkeyPatch, door: str
) -> None:
    publisher = corpus_publisher(uow)
    first, second = corpus_service(uow, publisher), corpus_service(uow, publisher)
    slug = ProductSlug.parse("contoso")
    if door == "update":
        first.register_corpus_product(slug, "Contoso", OwnershipClass("owned"), "A")
        apart()
    read = publisher.latest_imported

    def read_then_interleave(artifact: type[CorpusRegistryArtifact]) -> object:
        seen = read(artifact)
        monkeypatch.setattr(publisher, "latest_imported", read)
        if door == "update":
            second.update_corpus_product(slug, business_unit="X")
        else:
            second.register_corpus_product(
                ProductSlug.parse("ansible"), "Ansible", OwnershipClass("owned"), "Ansible"
            )
        apart()
        return seen

    monkeypatch.setattr(publisher, "latest_imported", read_then_interleave)
    with pytest.raises(ConflictError, match="another writer"):
        if door == "update":
            first.update_corpus_product(slug, ownership=OwnershipClass("upstream"))
        else:
            first.register_corpus_product(slug, "Contoso", OwnershipClass("upstream"), "A")
    if door == "update":
        assert owned(first, "contoso") == ("Contoso", "owned", "X")
    else:
        assert owned(first, "ansible") == ("Ansible", "owned", "Ansible")
        assert owned(first, "contoso") == ("Contoso", None, None)
        first.register_corpus_product(slug, "Contoso", OwnershipClass("upstream"), "A")
        assert owned(first, "contoso") == ("Contoso", "upstream", "A")


def test_corpus_product_doors_need_a_publisher(service: PortfolioService) -> None:
    slug = ProductSlug.parse("contoso")
    with pytest.raises(ConfigError):
        service.register_corpus_product(slug, "Contoso", OwnershipClass("owned"), "BU")
    with pytest.raises(ConfigError):
        service.update_corpus_product(slug, label="Renamed")
    assert service.find_product(slug) is None
