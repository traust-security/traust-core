"""PortfolioService.tracked_refs: the commits an impact answer covers."""

from __future__ import annotations

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import SHA, Seed, apart, same_rows
from traust_core.v1.errors import ValidationError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

MOVED = "b" * 40


def portfolio(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


def test_no_repositories_track_nothing(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    assert portfolio(uow).tracked_refs() == []


def test_tracked_refs_are_default_heads_and_component_commits(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo, other = seed.repository(), seed.repository()
    head = seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    seed.repository_ref(repo, name="dev", sha=MOVED)  # a branch nothing links: untracked
    shipped = seed.repository_ref(other, name="release-4.16", sha=SHA)
    seed.component(seed.release(), shipped)
    uow.commit()
    assert same_rows(portfolio(uow).tracked_refs(), [head, shipped])


def test_a_moved_default_head_tracks_its_latest_commit(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo = seed.repository()
    seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    uow.commit()
    apart()
    moved = seed.repository_ref(repo, name="main", sha=MOVED, is_default=True)
    uow.commit()
    assert portfolio(uow).tracked_refs() == [moved]


def test_one_commit_linked_twice_is_tracked_once(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = seed.repository()
    head = seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    seed.component(seed.release(), head)
    seed.component(seed.release(), head)
    uow.commit()
    assert portfolio(uow).tracked_refs() == [head]


def test_tracked_refs_refuse_an_unbounded_fleet(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    ref = seed.repository_ref(is_default=True)
    seed.component(seed.release(), ref)
    seed.component(seed.release(), seed.repository_ref())
    uow.commit()
    with pytest.raises(ValidationError):
        portfolio(uow).tracked_refs(max_records=1)
