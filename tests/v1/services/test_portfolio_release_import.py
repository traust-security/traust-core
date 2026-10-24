"""PortfolioService.import_release on SQLite and Postgres: a payload version becomes a release
with a component per commit, in one transaction."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.inventory import RefName, ReleaseCommit, VersionLabel
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed

ETCD = "https://github.com/example-org/cluster-etcd-operator"
KUBE = "https://github.com/example-org/kubernetes"
STRAY = "https://github.com/example-org/never-onboarded"
V = VersionLabel("4.20.1")


def commit(url: str, sha: str, branch: str | None = "release-4.20") -> ReleaseCommit:
    return ReleaseCommit(
        HttpsRepoUrl.parse(url, ("github.com",)),
        GitSha.parse(sha * 40),
        None if branch is None else RefName(branch),
    )


PAYLOAD = (commit(ETCD, "a"), commit(KUBE, "b"), commit(KUBE, "c", None))


def shipped(uow: SqlTraustUnitOfWork, release_id: object) -> set[tuple[str, str | None]]:
    with uow:
        return {
            (ref.sha[0], ref.name)
            for c in uow.components.list_for_release(release_id)  # type: ignore[arg-type]
            for ref in [uow.repository_refs.get(c.repository_ref_id)]
        }


def held_refs(engine: Engine) -> int:
    with SqlTraustUnitOfWork(engine) as fresh:
        ids = [r.id for u in (ETCD, KUBE) if (r := fresh.repositories.find_by_url(u)) and r.id]
        return len(fresh.repository_refs.list_for_repositories(ids))


@pytest.fixture
def portfolio(engine: Engine, uow: SqlTraustUnitOfWork, seed: Seed) -> PortfolioService:
    seed.repository(url=ETCD)
    seed.repository(url=KUBE)
    uow.commit()
    return PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())


def test_a_payload_becomes_a_release_with_a_component_per_commit(
    uow: SqlTraustUnitOfWork, seed: Seed, portfolio: PortfolioService
) -> None:
    product = seed.product()
    uow.commit()
    release = portfolio.import_release(product.id, V, PAYLOAD)  # type: ignore[arg-type]
    assert (release.product_id, release.version) == (product.id, V)
    assert shipped(uow, release.id) == {("a", "release-4.20"), ("b", "release-4.20"), ("c", None)}
    with uow:
        ref = uow.repository_refs.find(
            uow.repositories.find_by_url(ETCD).id,  # type: ignore[union-attr]
            "release-4.20",
            "a" * 40,
        )
    assert ref is not None and ref.id is not None
    assert [p.id for p in portfolio.list_products_shipping(ref.id)] == [product.id]


@pytest.mark.parametrize("order", [PAYLOAD, tuple(reversed(PAYLOAD)), PAYLOAD + PAYLOAD[:1]])
def test_reimporting_the_same_commits_changes_nothing(
    uow: SqlTraustUnitOfWork, seed: Seed, portfolio: PortfolioService, order: tuple
) -> None:
    product = seed.product()
    uow.commit()
    first = portfolio.import_release(product.id, V, PAYLOAD)  # type: ignore[arg-type]
    assert portfolio.import_release(product.id, V, order) == first  # type: ignore[arg-type]
    with uow:
        assert len(uow.components.list_for_release(first.id)) == 3  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("again", "error", "match"),
    [
        (PAYLOAD[:2], ConflictError, "already ships 3 commits"),
        ((*PAYLOAD, commit(ETCD, "d")), ConflictError, "names 4"),
        ((*PAYLOAD, commit(STRAY, "e")), NotFoundError, "never-onboarded"),
        ((), ValidationError, "no commits"),
    ],
)
def test_a_changed_or_unknown_payload_is_refused_and_nothing_is_written(
    engine: Engine,
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    portfolio: PortfolioService,
    again: tuple,
    error: type[Exception],
    match: str,
) -> None:
    product = seed.product()
    uow.commit()
    release = portfolio.import_release(product.id, V, PAYLOAD)  # type: ignore[arg-type]
    refs_before = held_refs(engine)
    with pytest.raises(error, match=match):
        portfolio.import_release(product.id, V, again)  # type: ignore[arg-type]
    assert len(shipped(uow, release.id)) == 3
    refs_after = held_refs(engine)
    assert refs_after == refs_before


def test_a_first_import_naming_an_unregistered_repository_writes_no_release(
    uow: SqlTraustUnitOfWork, seed: Seed, portfolio: PortfolioService
) -> None:
    product = seed.product()
    uow.commit()
    with pytest.raises(NotFoundError, match="never-onboarded"):
        portfolio.import_release(product.id, V, (*PAYLOAD, commit(STRAY, "e")))  # type: ignore[arg-type]
    with uow:
        assert uow.releases.find(product.id, V) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("product_known", "version", "error"),
    [(False, V, NotFoundError), (True, VersionLabel(" "), ValidationError)],
)
def test_the_product_and_version_are_checked(
    uow: SqlTraustUnitOfWork,
    seed: Seed,
    portfolio: PortfolioService,
    product_known: bool,
    version: VersionLabel,
    error: type[Exception],
) -> None:
    product_id = seed.product().id if product_known else uuid4()
    uow.commit()
    with pytest.raises(error):
        portfolio.import_release(product_id, version, PAYLOAD)  # type: ignore[arg-type]
