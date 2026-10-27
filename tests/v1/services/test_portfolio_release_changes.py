"""PortfolioService.release_changes and recorded_release on SQLite and Postgres: the version bump
and the commits a release ships against an earlier one of its product (by default its high-water
mark), and the repositories it ships."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.inventory import Release, ReleaseBump, VersionLabel
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


def _recorded(uow: SqlTraustUnitOfWork, release: Release, day: int) -> Release:
    """`release` as if recorded on 2026-10-`day` (the database stamps created_at on insert)."""
    table = uow.releases.table  # type: ignore[attr-defined]
    at = datetime(2026, 10, day, tzinfo=UTC)
    uow.connection.execute(sa.update(table).where(table.c.id == release.id).values(created_at=at))
    return release


@pytest.mark.parametrize(
    ("recorded", "bump", "previous"),
    [
        ([("4.19", 1), ("4.20", 2)], ReleaseBump.MINOR, "4.19"),
        ([("4.18", 1), ("4.20", 2), ("4.19.3", 3)], ReleaseBump.BACKFILL, "4.20"),
        ([("4.20", 1), ("4.18", 2), ("5.0", 3)], ReleaseBump.MAJOR, "4.20"),
        ([("latest", 1), ("4.19", 2), ("4.19.1", 3)], ReleaseBump.PATCH, "4.19"),
        ([("latest", 1), ("4.19", 2)], ReleaseBump.UNKNOWN, "latest"),
        ([("4.19", 1), ("4.21", 2), ("4.20", 3)], ReleaseBump.BACKFILL, "4.21"),
        ([("4.19", 1), ("4.20", 1)], ReleaseBump.MINOR, "4.19"),
    ],
)
def test_by_default_against_the_highest_version_recorded_before(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    recorded: list[tuple[str, int]],
    bump: ReleaseBump,
    previous: str,
) -> None:
    product = seed.product()
    *_, last = [_recorded(uow, seed.release(product, version=v), d) for v, d in recorded]
    uow.commit()
    change = PortfolioService(uow, PortfolioPolicy()).release_changes(last.id)  # type: ignore[arg-type]
    assert (change.previous_version, change.bump) == (previous, bump)


def test_by_default_ignores_other_products_and_later_releases(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    product = seed.product()
    _recorded(uow, seed.release(seed.product(), version="4.19"), 1)
    first = _recorded(uow, seed.release(product, version="4.20"), 2)
    _recorded(uow, seed.release(product, version="4.21"), 3)
    uow.commit()
    with pytest.raises(NotFoundError, match="first recorded release"):
        PortfolioService(uow, PortfolioPolicy()).release_changes(first.id)  # type: ignore[arg-type]


def test_find_release(uow: SqlTraustUnitOfWork, seed: Seed) -> None:
    product = seed.product()
    release = seed.release(product, version="4.20")
    uow.commit()
    portfolio = PortfolioService(uow, PortfolioPolicy())
    assert portfolio.find_release(product.id, VersionLabel("4.20")) == release  # type: ignore[arg-type]
    assert portfolio.find_release(product.id, VersionLabel("4.21")) is None  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        portfolio.find_release(product.id, VersionLabel(" "))  # type: ignore[arg-type]


def test_a_recorded_release_names_the_repositories_it_ships_once_each(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    product = seed.product()
    old = _recorded(uow, seed.release(product, version="4.19"), 1)
    new = _recorded(uow, seed.release(product, version="4.20"), 2)
    repo, other = seed.repository(), seed.repository()
    seed.component(old, seed.repository_ref(seed.repository()))
    for ref in (seed.repository_ref(repo), seed.repository_ref(repo, name="release-4.20")):
        seed.component(new, ref)
    seed.component(new, seed.repository_ref(other))
    uow.commit()
    recorded = PortfolioService(uow, PortfolioPolicy()).recorded_release(new.id)  # type: ignore[arg-type]
    assert recorded.release.id == new.id
    assert set(recorded.repository_ids) == {repo.id, other.id}
    assert len(recorded.repository_ids) == 2
    assert recorded.change is not None
    assert (recorded.change.previous_version, recorded.change.bump) == ("4.19", ReleaseBump.MINOR)
    assert recorded.change.remodels()


def test_a_products_first_recorded_release_has_no_change(
    uow: SqlTraustUnitOfWork, seed: Seed
) -> None:
    product = seed.product()
    _recorded(uow, seed.release(seed.product(), version="4.19"), 1)
    first = _recorded(uow, seed.release(product, version="5.0"), 2)
    _recorded(uow, seed.release(product, version="4.0"), 3)
    uow.commit()
    recorded = PortfolioService(uow, PortfolioPolicy()).recorded_release(first.id)  # type: ignore[arg-type]
    assert (recorded.release.id, recorded.repository_ids, recorded.change) == (first.id, (), None)


def test_a_recorded_release_that_does_not_exist(uow: SqlTraustUnitOfWork) -> None:
    with pytest.raises(NotFoundError):
        PortfolioService(uow, PortfolioPolicy()).recorded_release(uuid4())
