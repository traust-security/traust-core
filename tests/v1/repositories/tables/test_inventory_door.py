"""The repository/ref door (`Inventory`) and `AssessmentService.list_for_repository` over the
contract tables (SQLite + Postgres), on the caller's open unit of work."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from tests.v1.repositories.tables.conftest import SHA, T0, Seed
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.findings import SubjectRef
from traust_core.v1.models.inventory import Component, Repository, RepositoryRef
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.assessment import AssessmentService
from traust_core.v1.services.portfolio import Inventory, PortfolioPolicy, PortfolioService

OTHER = "b" * 40
MISSING = uuid4()


@dataclass(frozen=True)
class World:
    repo: Repository
    main: RepositoryRef
    feature: RepositoryRef
    twin: RepositoryRef
    mirror: Repository
    bare: Repository
    component: Component


@pytest.fixture
def world(seed: Seed) -> World:
    repo = seed.repository(url="https://github.com/org/door")
    main = seed.repository_ref(repository=repo, name="main", is_default=True, sha=SHA)
    feature = seed.repository_ref(repository=repo, name="feature", sha=OTHER)
    twin = seed.repository_ref(repository=repo, name="release", sha=OTHER)
    mirror = seed.repository(
        url="https://github.com/mirrors/door", public=False, upstream_id=repo.id
    )
    return World(
        repo=repo,
        main=main,
        feature=feature,
        twin=twin,
        mirror=mirror,
        bare=seed.repository(url="https://github.com/org/bare"),
        component=seed.component(ref=main),
    )


Call = Callable[[Inventory, World], Any]

FOUND: list[tuple[str, Call, Callable[[World], Any]]] = [
    ("get_repository", lambda i, w: i.get_repository(w.repo.id), lambda w: w.repo),
    ("get_ref", lambda i, w: i.get_ref(w.feature.id), lambda w: w.feature),
    ("resolve", lambda i, w: i.resolve(w.feature.id), lambda w: (w.feature, w.repo)),
    (
        "subject without assessment",
        lambda i, w: i.subject(w.main.id),
        lambda w: SubjectRef(
            repository_id=w.repo.id,
            repository_url=w.repo.url,
            repository_ref_id=w.main.id,
            sha=SHA,
        ),
    ),
    (
        "subject with assessment",
        lambda i, w: i.subject(w.feature.id, w.bare.id),
        lambda w: SubjectRef(
            repository_id=w.repo.id,
            repository_url=w.repo.url,
            repository_ref_id=w.feature.id,
            sha=OTHER,
            assessment_id=w.bare.id,
        ),
    ),
    ("find_repository hit", lambda i, w: i.find_repository(w.repo.url), lambda w: w.repo),
    (
        "find_repository miss",
        lambda i, w: i.find_repository("https://github.com/org/absent"),
        lambda w: None,
    ),
    (
        "list_refs",
        lambda i, w: sorted(i.list_refs(w.repo.id), key=lambda r: str(r.id)),
        lambda w: sorted([w.main, w.feature, w.twin], key=lambda r: str(r.id)),
    ),
    ("list_refs of a bare repository", lambda i, w: i.list_refs(w.bare.id), lambda w: []),
    ("default_ref", lambda i, w: i.default_ref(w.repo.id), lambda w: w.main),
    ("default_ref unset", lambda i, w: i.default_ref(w.bare.id), lambda w: None),
    ("find_ref by name", lambda i, w: i.find_ref(w.repo.id, OTHER, "release"), lambda w: w.twin),
    ("find_ref by its one sha", lambda i, w: i.find_ref(w.repo.id, SHA), lambda w: w.main),
    ("private_mirror", lambda i, w: i.private_mirror(w.repo.id), lambda w: w.mirror),
    ("private_mirror none", lambda i, w: i.private_mirror(w.bare.id), lambda w: None),
    ("get_component", lambda i, w: i.get_component(w.component.id), lambda w: w.component),
]

REFUSED: list[tuple[str, Call, type[Exception], str]] = [
    ("get_repository", lambda i, w: i.get_repository(MISSING), NotFoundError, "repository "),
    ("get_ref", lambda i, w: i.get_ref(MISSING), NotFoundError, "repository_ref "),
    ("resolve", lambda i, w: i.resolve(MISSING), NotFoundError, "repository_ref "),
    ("subject", lambda i, w: i.subject(MISSING), NotFoundError, "repository_ref "),
    ("get_component", lambda i, w: i.get_component(MISSING), NotFoundError, "component "),
    (
        "find_ref unregistered name",
        lambda i, w: i.find_ref(w.repo.id, SHA, "nope"),
        NotFoundError,
        "nope@a+ is not a registered ref",
    ),
    (
        "find_ref sha on two refs",
        lambda i, w: i.find_ref(w.repo.id, OTHER),
        ValidationError,
        "has 2 registered refs",
    ),
    (
        "find_ref sha on no ref",
        lambda i, w: i.find_ref(w.bare.id, SHA),
        ValidationError,
        "has 0 registered refs",
    ),
]


@pytest.mark.parametrize(("case", "call", "expected"), FOUND, ids=[c[0] for c in FOUND])
def test_inventory_reads(uow: SqlTraustUnitOfWork, world: World, case, call, expected) -> None:
    assert call(Inventory(uow), world) == expected(world)


@pytest.mark.parametrize(("case", "call", "error", "match"), REFUSED, ids=[c[0] for c in REFUSED])
def test_inventory_refuses_with_typed_errors(
    uow: SqlTraustUnitOfWork, world: World, case, call, error, match
) -> None:
    with pytest.raises(error, match=match):
        call(Inventory(uow), world)


def test_portfolio_reads_go_through_its_inventory(uow: SqlTraustUnitOfWork, world: World) -> None:
    portfolio = PortfolioService(uow, PortfolioPolicy())
    assert portfolio.get_repository(world.repo.id) == portfolio.inventory.get_repository(
        world.repo.id
    )
    assert portfolio.find_repository(world.repo.url) == world.repo  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kind", "wanted"),
    [(None, ["remediation", "audit", "audit"]), (AssessmentKind.REMEDIATION, ["remediation"])],
    ids=["every kind", "one kind"],
)
def test_assessments_across_a_repositorys_refs_oldest_first(
    uow: SqlTraustUnitOfWork, seed: Seed, world: World, kind, wanted
) -> None:
    for days, ref, k in [(2, world.feature, "audit"), (1, world.main, "remediation")]:
        seed.assessment(ref=ref, kind=k, occurred_at=T0 + timedelta(days=days))
    seed.assessment(ref=world.twin, kind="audit", occurred_at=T0 + timedelta(days=3))
    seed.assessment(ref=seed.repository_ref(), occurred_at=T0)  # another repository's
    found = AssessmentService(uow).list_for_repository(world.repo.id, kind)
    assert [a.kind for a in found] == wanted
    assert {a.repository_ref_id for a in found} <= {world.main.id, world.feature.id, world.twin.id}


@pytest.mark.parametrize("repository", ["bare", "unknown"])
def test_a_repository_without_refs_has_no_assessments(
    uow: SqlTraustUnitOfWork, world: World, repository: str
) -> None:
    repository_id: UUID = world.bare.id if repository == "bare" else MISSING  # type: ignore[assignment]
    assert AssessmentService(uow).list_for_repository(repository_id) == []
