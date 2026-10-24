"""PortfolioService.release_changes on SQLite and Postgres: the version bump and the commits a
release ships against an earlier one of its product."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.inventory import ReleaseBump
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


@pytest.mark.parametrize(
    ("version", "previous", "bump"),
    [
        ("5.0", "4.19", ReleaseBump.MAJOR),
        ("4.20", "4.19", ReleaseBump.MINOR),
        ("4.19.2", "4.19", ReleaseBump.PATCH),
        ("v4.19.1", "4.19.0", ReleaseBump.PATCH),
        ("4.18", "4.19", ReleaseBump.BACKFILL),
        ("4.19.0", "4.19", ReleaseBump.NONE),
        ("2026-10", "4.19", ReleaseBump.UNKNOWN),
        ("4.19", "latest", ReleaseBump.UNKNOWN),
    ],
)
def test_the_version_bump(
    uow: SqlTraustUnitOfWork, seed: Seed, version: str, previous: str, bump: ReleaseBump
) -> None:
    product = seed.product()
    old, new = seed.release(product, version=previous), seed.release(product, version=version)
    uow.commit()
    change = PortfolioService(uow, PortfolioPolicy()).release_changes(new.id, old.id)  # type: ignore[arg-type]
    assert (change.version, change.previous_version, change.bump) == (version, previous, bump)
    assert change.remodels() == (bump in (ReleaseBump.MAJOR, ReleaseBump.MINOR))


def test_the_commits_added_and_removed(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    product = seed.product()
    old, new = seed.release(product, version="4.19"), seed.release(product, version="4.20")
    kept, dropped, moved_from, moved_to, fresh = (seed.repository_ref() for _ in range(5))
    for ref in (kept, dropped, moved_from):
        seed.component(old, ref)
    for ref in (kept, moved_to, fresh):
        seed.component(new, ref)
    uow.commit()
    change = PortfolioService(uow, PortfolioPolicy()).release_changes(new.id, old.id)  # type: ignore[arg-type]
    assert set(change.added) == {moved_to.id, fresh.id}
    assert set(change.removed) == {dropped.id, moved_from.id}
    back = PortfolioService(uow, PortfolioPolicy()).release_changes(old.id, new.id)  # type: ignore[arg-type]
    assert (set(back.added), set(back.removed), back.bump) == (
        set(change.removed),
        set(change.added),
        ReleaseBump.BACKFILL,
    )


def test_releases_without_components(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    product = seed.product()
    old, new = seed.release(product, version="1.0"), seed.release(product, version="1.1")
    uow.commit()
    change = PortfolioService(uow, PortfolioPolicy()).release_changes(new.id, old.id)  # type: ignore[arg-type]
    assert (change.added, change.removed) == ((), ())


def test_what_cannot_be_compared(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    one, other = seed.release(seed.product()), seed.release(seed.product())
    uow.commit()
    portfolio = PortfolioService(uow, PortfolioPolicy())
    with pytest.raises(ValidationError, match="different products"):
        portfolio.release_changes(one.id, other.id)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="itself"):
        portfolio.release_changes(one.id, one.id)  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        portfolio.release_changes(one.id, uuid4())  # type: ignore[arg-type]
