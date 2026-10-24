from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed, apart
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import Cursor, PageRequest, every_item
from traust_core.v1.models.inventory import ComponentFilter, ProductSlug, RefName, VersionLabel
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


def test_product_reads_select_the_requested_record(service: PortfolioService, seed: Seed) -> None:
    first = seed.product(slug="first")
    second = seed.product(slug="second")
    assert service.get_product(first.id) == first
    assert service.find_product(ProductSlug(second.slug)) == second


def test_missing_product_get_raises_and_find_returns_none(service: PortfolioService) -> None:
    with pytest.raises(NotFoundError):
        service.get_product(uuid4())
    assert service.find_product(ProductSlug("missing")) is None


@pytest.mark.parametrize(
    "method,value",
    [
        ("get_product", None),
        ("get_product", "bad"),
        ("find_product", ""),
        ("find_product", "  "),
        ("find_product", None),
    ],
)
def test_product_reads_reject_invalid_inputs(
    service: PortfolioService, method: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        getattr(service, method)(value)


def test_components_empty_page(service: PortfolioService) -> None:
    page = service.list_components(ComponentFilter(), PageRequest())
    assert page.items == () and page.next is None


@pytest.mark.parametrize("limit", [1, 2, 3, 5])
def test_component_pages_are_newest_first_without_duplicates(
    service: PortfolioService, seed: Seed, limit: int
) -> None:
    records = []
    for _ in range(3):
        records.append(seed.component())
        apart()
    pages = []
    request = PageRequest(limit=limit)
    while True:
        page = service.list_components(ComponentFilter(), request)
        assert len(page.items) <= limit
        pages.extend(page.items)
        if page.next is None:
            break
        request = PageRequest(limit=limit, cursor=page.next)
    assert pages == list(reversed(records))


def test_component_pages_break_timestamp_ties_by_id(
    service: PortfolioService, seed: Seed, uow: SqlTraustUnitOfWork
) -> None:
    release = seed.release()
    refs = [seed.repository_ref() for _ in range(5)]
    table = uow.components.table
    # One statement gives every row the same database-generated creation timestamp.
    uow.connection.execute(
        sa.insert(table).values(
            [{"release_id": release.id, "repository_ref_id": ref.id} for ref in refs]
        )
    )
    rows = list(every_item(lambda p: service.list_components(ComponentFilter(), p), 2))
    assert len(rows) == 5
    assert len({row.created_at for row in rows}) == 1
    assert [row.id for row in rows] == sorted({row.id for row in rows}, reverse=True)


def test_new_component_does_not_shift_a_started_page(service: PortfolioService, seed: Seed) -> None:
    old = seed.component()
    apart()
    newest = seed.component()
    first = service.list_components(ComponentFilter(), PageRequest(limit=1))
    apart()
    seed.component()
    rest = service.list_components(ComponentFilter(), PageRequest(limit=1, cursor=first.next))
    assert first.items == (newest,)
    assert rest.items == (old,) and rest.next is None
    empty = service.list_components(
        ComponentFilter(), PageRequest(cursor=Cursor(f"{old.created_at.isoformat()}|{old.id}"))
    )
    assert empty.items == () and empty.next is None


@pytest.mark.parametrize(
    "page", [PageRequest(limit=0), PageRequest(limit=-1), PageRequest(cursor=Cursor("invalid"))]
)
def test_component_reads_reject_invalid_pages(service: PortfolioService, page: PageRequest) -> None:
    with pytest.raises(ValidationError):
        service.list_components(ComponentFilter(), page)


def test_inventory_reads_do_not_commit_the_callers_transaction(
    service: PortfolioService, seed: Seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    product = seed.product()
    seed.component()
    commit = Mock(wraps=seed.uow.commit)
    monkeypatch.setattr(seed.uow, "commit", commit)
    service.get_product(product.id)
    service.find_product(ProductSlug(product.slug))
    service.list_components(ComponentFilter(), PageRequest())
    commit.assert_not_called()


def test_sanitized_inventory_is_readable_after_reopening(engine: sa.Engine) -> None:
    data = json.loads((Path(__file__).parents[2] / "fixtures/inventory/intake.json").read_text())
    writer = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    product = writer.register_product(ProductSlug(data["product"]["slug"]), data["product"]["name"])
    release = writer.record_release(product.id, VersionLabel(data["product"]["version"]))
    expected = []
    for row in data["repositories"]:
        repository = writer.register_repository(
            HttpsRepoUrl.parse(row["url"], ["github.com"]), public=True
        )
        ref = writer.register_ref(
            repository.id, GitSha.parse(row["sha"]), RefName(row["ref"]), RefKind.BRANCH
        )
        expected.append(writer.add_component(release.id, ref.id))
    reader = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())
    assert reader.get_product(product.id) == product
    assert reader.find_product(ProductSlug(product.slug)) == product
    assert list(every_item(lambda p: reader.list_components(ComponentFilter(), p), 2)) == sorted(
        expected, key=lambda row: (row.created_at, row.id), reverse=True
    )
