"""Repository reads on SQLite and Postgres: by id, by URL, and paged."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed, apart
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import Cursor, PageRequest, every_item
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


def test_get_and_find_a_repository(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = seed.repository(url="https://github.com/example/operator")
    portfolio = PortfolioService(uow, PortfolioPolicy())
    assert portfolio.get_repository(repo.id) == repo  # type: ignore[arg-type]
    url = HttpsRepoUrl.parse("https://github.com/example/operator", ["github.com"])
    assert portfolio.find_repository(url) == repo


def test_an_unknown_repository(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    portfolio = PortfolioService(uow, PortfolioPolicy())
    with pytest.raises(NotFoundError):
        portfolio.get_repository(uuid4())
    url = HttpsRepoUrl.parse("https://github.com/example/missing", ["github.com"])
    assert portfolio.find_repository(url) is None


def test_list_repositories_pages_the_fleet_newest_first(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    older = seed.repository()
    uow.commit()
    apart()
    newer = seed.repository()
    uow.commit()
    portfolio = PortfolioService(uow, PortfolioPolicy())
    first = portfolio.list_repositories(RepositoryFilter(), PageRequest(limit=1))
    assert first.items == (newer,) and first.next is not None
    rest = portfolio.list_repositories(RepositoryFilter(), PageRequest(limit=1, cursor=first.next))
    assert rest.items == (older,) and rest.next is None


def test_list_repositories_of_an_empty_fleet(uow: SqlTraustUnitOfWork) -> None:
    page = PortfolioService(uow, PortfolioPolicy()).list_repositories(
        RepositoryFilter(), PageRequest()
    )
    assert page.items == () and page.next is None


@pytest.mark.parametrize(
    "page", [PageRequest(limit=0), PageRequest(cursor=Cursor("nope"))], ids=["zero", "cursor"]
)
def test_list_repositories_rejects_a_bad_page(uow: SqlTraustUnitOfWork, page: PageRequest) -> None:
    with pytest.raises(ValidationError):
        PortfolioService(uow, PortfolioPolicy()).list_repositories(RepositoryFilter(), page)


def test_every_item_follows_the_cursor_across_pages(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repos = {seed.repository().id for _ in range(5)}
    uow.commit()
    portfolio = PortfolioService(uow, PortfolioPolicy())
    seen = [
        r.id for r in every_item(lambda p: portfolio.list_repositories(RepositoryFilter(), p), 2)
    ]
    assert len(seen) == 5 and set(seen) == repos
