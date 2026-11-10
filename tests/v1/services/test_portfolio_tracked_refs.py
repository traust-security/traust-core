"""PortfolioService.tracked_refs: the commits an impact answer covers — the latest commit of
every attached branch line (registration is the attachment)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import SHA, Seed, apart, same_rows
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

MOVED = "b" * 40


def portfolio(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


def test_no_repositories_track_nothing(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    assert portfolio(uow).tracked_refs() == []


def test_tracked_refs_are_each_attached_lines_latest_commit(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    repo, other = seed.repository(), seed.repository()
    head = seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    dev = seed.repository_ref(repo, name="dev", sha=MOVED)  # attached by its ref row alone
    shipped = seed.repository_ref(other, name="release-4.16", sha=SHA)
    seed.component(seed.release(), shipped)
    uow.commit()
    assert portfolio(uow).tracked_refs_of(repo.id) == [dev, head]  # type: ignore[arg-type]
    assert same_rows(portfolio(uow).tracked_refs(), [dev, head, shipped])


def test_bare_commits_and_tags_are_not_lines(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = seed.repository()
    seed.repository_ref(repo, name=None, kind=None, sha=SHA)
    seed.repository_ref(repo, name="v1.0", kind="tag", sha=SHA)
    uow.commit()
    assert portfolio(uow).tracked_refs() == []
    assert portfolio(uow).tracked_refs_of(repo.id) == []  # type: ignore[arg-type]


def test_a_moved_line_tracks_its_latest_commit(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    repo = seed.repository()
    seed.repository_ref(repo, name="main", sha=SHA, is_default=True)
    uow.commit()
    apart()
    moved = seed.repository_ref(repo, name="main", sha=MOVED, is_default=True)
    uow.commit()
    assert portfolio(uow).tracked_refs() == [moved]


def test_tracked_refs_refuse_an_unbounded_fleet(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    seed.repository_ref(is_default=True)
    seed.repository_ref(name="dev")
    uow.commit()
    with pytest.raises(ValidationError):
        portfolio(uow).tracked_refs(max_records=1)


def test_an_unknown_repository_has_no_tracked_refs(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    with pytest.raises(NotFoundError):
        portfolio(uow).tracked_refs_of(uuid4())
