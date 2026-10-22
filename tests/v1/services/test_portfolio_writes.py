from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, timezone
from pathlib import Path
from threading import Barrier
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from tests.v1.repositories.tables import conftest as table_fixtures
from tests.v1.repositories.tables.conftest import SHA, T0, Seed
from traust_core.v1.errors import ConflictError, RepositoryError, ValidationError
from traust_core.v1.models.base import Entity
from traust_core.v1.models.inventory import ProductSlug, RefName, VersionLabel
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

engine, uow, seed = table_fixtures.engine, table_fixtures.uow, table_fixtures.seed


def portfolio(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return PortfolioService(uow, PortfolioPolicy())


@pytest.fixture
def service(uow: SqlTraustUnitOfWork) -> PortfolioService:
    return portfolio(uow)


@pytest.fixture
def commits(uow: SqlTraustUnitOfWork, monkeypatch: pytest.MonkeyPatch) -> Mock:
    commit = Mock(wraps=uow.commit)
    monkeypatch.setattr(uow, "commit", commit)
    return commit


def test_register_product_returns_existing_without_rewriting_it(
    service: PortfolioService, uow: SqlTraustUnitOfWork, commits: Mock
) -> None:
    product = service.register_product(ProductSlug("example"), "Example")
    assert product.id is not None
    assert uow.products.get(product.id) == product
    assert service.register_product(ProductSlug("example"), "Changed name") == product
    assert commits.call_count == 2


def test_register_repository_uses_the_parsed_url_and_preserves_existing_visibility(
    service: PortfolioService, uow: SqlTraustUnitOfWork, commits: Mock
) -> None:
    url = HttpsRepoUrl.parse("https://GITHUB.COM/example/repo.git/", ["github.com"])
    repository = service.register_repository(url, public=False)
    assert repository.url == "https://github.com/example/repo"
    assert repository.id is not None
    assert uow.repositories.get(repository.id) == repository
    assert (
        service.register_repository(HttpsRepoUrl.parse(repository.url, ["github.com"]), public=True)
        == repository
    )
    assert commits.call_count == 2


@pytest.mark.parametrize(
    "name,kind",
    [
        (None, None),
        ("main", RefKind.BRANCH),
        ("v1", RefKind.TAG),
        ("main", RefKind.DEFAULT),
        ("stable", RefKind.STREAM),
    ],
)
def test_register_ref_reuses_its_natural_key_and_keeps_distinct_commits(
    service: PortfolioService, seed: Seed, commits: Mock, name: str | None, kind: RefKind | None
) -> None:
    repository = seed.repository()
    ref_name = RefName(name) if name is not None else None
    ref = service.register_ref(repository.id, GitSha.parse(SHA), ref_name, kind)
    assert ref.id is not None
    assert seed.uow.repository_refs.get(ref.id) == ref
    assert service.get_ref(ref.id) == ref
    assert service.register_ref(repository.id, GitSha.parse(SHA), ref_name, kind) == ref
    later = service.register_ref(repository.id, GitSha.parse("b" * 40), ref_name, kind)
    assert later.id != ref.id
    assert len(seed.uow.repository_refs.list_for(repository.id)) == 2
    assert commits.call_count == 3


def test_ref_identity_includes_repository_and_name(service: PortfolioService, seed: Seed) -> None:
    first, second = seed.repository(), seed.repository()
    refs = [
        service.register_ref(repo.id, GitSha.parse(SHA), RefName(name), RefKind.BRANCH)
        for repo, name in ((first, "main"), (first, "stable"), (second, "main"))
    ]
    assert len({ref.id for ref in refs}) == 3


@pytest.mark.parametrize("name,kind", [(None, RefKind.BRANCH), (RefName("main"), None)])
def test_register_ref_rejects_unpaired_name_and_kind(
    service: PortfolioService, seed: Seed, commits: Mock, name: RefName | None, kind: RefKind | None
) -> None:
    repo = seed.repository()
    with pytest.raises(ValidationError, match="name and kind"):
        service.register_ref(repo.id, GitSha.parse(SHA), name, kind)
    assert seed.uow.repository_refs.list_for(repo.id) == []
    commits.assert_not_called()


def test_record_release_is_idempotent_within_its_product(
    service: PortfolioService, seed: Seed, commits: Mock
) -> None:
    product, other = seed.product(), seed.product()
    version = VersionLabel("1.0")
    release = service.record_release(product.id, version)
    assert release.id is not None
    assert seed.uow.releases.get(release.id) == release
    assert service.record_release(product.id, version) == release
    assert service.record_release(other.id, version).id != release.id
    assert commits.call_count == 3


def test_add_component_is_idempotent_within_its_release(
    service: PortfolioService, seed: Seed, commits: Mock
) -> None:
    release, other = seed.release(), seed.release()
    ref = seed.repository_ref()
    component = service.add_component(release.id, ref.id)
    assert component.id is not None
    assert seed.uow.components.get(component.id) == component
    assert service.add_component(release.id, ref.id) == component
    assert service.add_component(other.id, ref.id).id != component.id
    assert commits.call_count == 3


def test_assign_owner_preserves_first_observation_and_other_teams(
    service: PortfolioService, seed: Seed, commits: Mock
) -> None:
    repo = seed.repository()
    existing = seed.ownership(repo)
    assignment = service.assign_owner(repo.id, "platform", T0)
    assert assignment.id is not None
    assert seed.uow.ownerships.get(assignment.id) == assignment
    assert seed.uow.teams.get(assignment.team_id).name == "platform"
    assert service.assign_owner(repo.id, "platform", T0 + timedelta(days=1)) == assignment
    assert {row.id for row in seed.uow.ownerships.current(repo.id)} == {existing.id, assignment.id}
    assert commits.call_count == 2


def test_assign_owner_reuses_team_across_repositories(
    service: PortfolioService, seed: Seed
) -> None:
    first, second = seed.repository(), seed.repository()
    one = service.assign_owner(first.id, "platform", T0)
    two = service.assign_owner(second.id, "platform", T0)
    assert one.team_id == two.team_id
    assert one.id != two.id


def test_assign_owner_starts_a_new_period_after_a_closed_one(
    service: PortfolioService, seed: Seed
) -> None:
    repo, team = seed.repository(), seed.team(name="platform")
    end = T0 + timedelta(days=1)
    old = seed.ownership(repo, team, valid_from=T0, valid_to=end)
    new = service.assign_owner(repo.id, team.name, end)
    assert new.id != old.id
    assert new.valid_from == end
    assert seed.uow.ownerships.get(old.id) == old
    assert seed.uow.ownerships.as_of(repo.id, T0) == [old]
    assert seed.uow.ownerships.as_of(repo.id, end) == [new]


@pytest.mark.parametrize("operation", ["ref", "release", "component", "ownership"])
def test_missing_parent_is_rejected_without_partial_writes(
    engine: sa.Engine, operation: str
) -> None:
    unit = SqlTraustUnitOfWork(engine)
    service = portfolio(unit)
    missing = uuid4()
    with pytest.raises(ConflictError):
        match operation:
            case "ref":
                service.register_ref(missing, GitSha.parse(SHA), None, None)
            case "release":
                service.record_release(missing, VersionLabel("1.0"))
            case "component":
                service.add_component(missing, uuid4())
            case "ownership":
                service.assign_owner(missing, "must-rollback", T0)
    with unit:
        assert unit.teams.find_by_name("must-rollback") is None
        for repository in (unit.repository_refs, unit.releases, unit.components, unit.ownerships):
            count = sa.select(sa.func.count()).select_from(repository.table)
            assert unit.connection.scalar(count) == 0


def test_failed_commit_rolls_back_team_and_ownership(
    engine: sa.Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    unit = SqlTraustUnitOfWork(engine)
    with unit:
        repo = Seed(unit).repository()
        unit.commit()
    commit = Mock(side_effect=RepositoryError("commit failed"))
    monkeypatch.setattr(unit, "commit", commit)
    with pytest.raises(RepositoryError, match="commit failed"):
        portfolio(unit).assign_owner(repo.id, "must-rollback", T0)
    commit.assert_called_once()
    with unit:
        assert unit.teams.find_by_name("must-rollback") is None
        assert unit.ownerships.current(repo.id) == []


def test_sanitized_inventory_intake_replays_and_survives_reopening(engine: sa.Engine) -> None:
    fixture = Path(__file__).parents[2] / "fixtures/inventory/intake.json"
    data = json.loads(fixture.read_text())
    unit = SqlTraustUnitOfWork(engine)
    service = portfolio(unit)
    ids: list[UUID] = []
    for attempt in range(2):
        product = service.register_product(
            ProductSlug(data["product"]["slug"]), data["product"]["name"]
        )
        release = service.record_release(product.id, VersionLabel(data["product"]["version"]))
        recorded = [product.id, release.id]
        for row in data["repositories"]:
            repository = service.register_repository(
                HttpsRepoUrl.parse(row["url"], ["github.com"]), public=True
            )
            ref = service.register_ref(
                repository.id, GitSha.parse(row["sha"]), RefName(row["ref"]), RefKind.BRANCH
            )
            component = service.add_component(release.id, ref.id)
            ownership = service.assign_owner(repository.id, row["team"], T0)
            recorded.extend((repository.id, ref.id, component.id, ownership.id))
        if attempt:
            assert recorded == ids
        ids = recorded
    with SqlTraustUnitOfWork(engine) as reopened:
        assert reopened.products.get(product.id) == product
        assert reopened.releases.get(release.id) == release
        assert len(reopened.components.list_for_release(release.id)) == len(data["repositories"])
        assert reopened.ownerships.find_current(repository.id, ownership.team_id) == ownership


def write_calls(seed: Seed) -> dict[str, dict[str, object]]:
    product, repo = seed.product(), seed.repository()
    release, ref = seed.release(product), seed.repository_ref(repo)
    seed.uow.commit()
    return {
        "register_product": {"slug": ProductSlug("new-product"), "name": "New Product"},
        "register_repository": {
            "url": HttpsRepoUrl.parse("https://github.com/example/new", ["github.com"]),
            "public": False,
        },
        "register_ref": {
            "repository_id": repo.id,
            "sha": GitSha.parse("b" * 40),
            "name": RefName("main"),
            "kind": RefKind.BRANCH,
        },
        "record_release": {"product_id": product.id, "version": VersionLabel("2.0")},
        "add_component": {"release_id": release.id, "repository_ref_id": ref.id},
        "assign_owner": {"repository_id": repo.id, "team": "new-team", "at": T0},
    }


INVALID_INPUTS = (
    [
        (operation, field, value)
        for operation, field in (
            ("register_product", "slug"),
            ("register_product", "name"),
            ("record_release", "version"),
            ("register_ref", "name"),
            ("assign_owner", "team"),
        )
        for value in (None, "", " \t\n", "\u2003", 123)
    ]
    + [
        (operation, field, value)
        for operation, field in (
            ("register_ref", "repository_id"),
            ("record_release", "product_id"),
            ("add_component", "release_id"),
            ("add_component", "repository_ref_id"),
            ("assign_owner", "repository_id"),
        )
        for value in (None, "")
    ]
    + [
        ("register_repository", "url", None),
        ("register_repository", "url", ""),
        ("register_repository", "url", HttpsRepoUrl("github.com", "")),
        ("register_repository", "url", HttpsRepoUrl("github.com", "org/../repo")),
        ("register_repository", "public", None),
        ("register_repository", "public", 0),
        ("register_ref", "sha", None),
        ("register_ref", "sha", GitSha("")),
        ("register_ref", "sha", GitSha(None)),
        ("register_ref", "sha", GitSha("short")),
        ("register_ref", "kind", "unknown"),
        ("register_ref", "kind", "branch"),
        ("assign_owner", "at", None),
        ("assign_owner", "at", T0.replace(tzinfo=None)),
        ("assign_owner", "at", "2026-10-05T00:00:00"),
    ]
)


@pytest.mark.parametrize("existing", [False, True], ids=["new", "retry"])
@pytest.mark.parametrize("operation,field,value", INVALID_INPUTS)
def test_invalid_inputs_fail_before_any_write_even_on_retry(
    service: PortfolioService,
    seed: Seed,
    commits: Mock,
    operation: str,
    field: str,
    value: object,
    existing: bool,
) -> None:
    args = write_calls(seed)[operation]
    saved = getattr(service, operation)(**args) if existing else None
    commits.reset_mock()
    repos = (
        seed.uow.products,
        seed.uow.repositories,
        seed.uow.repository_refs,
        seed.uow.releases,
        seed.uow.components,
        seed.uow.teams,
        seed.uow.ownerships,
    )
    before = [seed.uow.connection.execute(sa.select(r.table)).all() for r in repos]
    with pytest.raises(ValidationError):
        getattr(service, operation)(**{**args, field: value})
    commits.assert_not_called()
    assert before == [seed.uow.connection.execute(sa.select(r.table)).all() for r in repos]
    if existing:
        assert getattr(service, operation)(**args) == saved


@pytest.mark.parametrize("missing_parent", ["release_id", "repository_ref_id"])
def test_component_rejects_each_missing_parent_independently(
    engine: sa.Engine,
    missing_parent: str,
) -> None:
    unit = SqlTraustUnitOfWork(engine)
    with unit:
        args = write_calls(Seed(unit))["add_component"]
    with pytest.raises(ConflictError):
        portfolio(unit).add_component(**{**args, missing_parent: uuid4()})
    with unit:
        assert unit.components.find(**args) is None


def test_named_and_bare_refs_at_the_same_sha_remain_distinct(
    service: PortfolioService,
    seed: Seed,
) -> None:
    repo = seed.repository()
    sha = GitSha.parse(SHA)
    bare = service.register_ref(repo.id, sha, None, None)
    named = service.register_ref(repo.id, sha, RefName("main"), RefKind.BRANCH)
    assert bare.id != named.id
    assert service.register_ref(repo.id, sha, None, None) == bare
    assert service.register_ref(repo.id, sha, RefName("main"), RefKind.BRANCH) == named


@pytest.mark.parametrize("offset", [timedelta(hours=5, minutes=30), timedelta(hours=-7)])
def test_ownership_preserves_the_instant_across_timezone_round_trips(
    service: PortfolioService,
    seed: Seed,
    engine: sa.Engine,
    offset: timedelta,
) -> None:
    repo = seed.repository()
    at = T0.astimezone(timezone(offset))
    saved = service.assign_owner(repo.id, "timezone-team", at)
    assert saved.valid_from == T0
    seed.uow.commit()
    with SqlTraustUnitOfWork(engine) as reopened:
        assert reopened.ownerships.get(saved.id).valid_from == T0
        assert reopened.ownerships.as_of(repo.id, T0) == [saved]
        assert reopened.ownerships.as_of(repo.id, T0 - timedelta(milliseconds=1)) == []
    assert service.assign_owner(repo.id, "timezone-team", T0) == saved


def test_failed_assignment_preserves_existing_team_and_can_be_retried(engine: sa.Engine) -> None:
    unit = SqlTraustUnitOfWork(engine)
    with unit:
        seed = Seed(unit)
        team = seed.team(name="existing-team")
        owned = seed.ownership(team=team)
        unit.commit()
    service = portfolio(unit)
    with pytest.raises(ConflictError):
        service.assign_owner(uuid4(), team.name, T0)
    with unit:
        assert unit.teams.get(team.id) == team
        assert unit.ownerships.list_for_team(team.id) == [owned]
        repo = Seed(unit).repository(url="https://github.com/example/retry")
        unit.commit()
    saved = service.assign_owner(repo.id, team.name, T0)
    with unit:
        assert saved.team_id == team.id
        assert unit.teams.get(team.id) == team
        assert len(unit.ownerships.list_for_team(team.id)) == 2


@pytest.mark.parametrize(
    "operation,target",
    [
        ("register_product", "product"),
        ("register_repository", "repository"),
        ("register_ref", "repository_ref"),
        ("bare_ref", "repository_ref"),
        ("record_release", "release"),
        ("add_component", "component"),
        ("assign_owner", "team"),
        ("existing_team", "team"),
    ],
)
def test_simultaneous_registrations_return_the_same_unchanged_record(
    engine: sa.Engine,
    operation: str,
    target: str,
) -> None:
    unit = SqlTraustUnitOfWork(engine)
    with unit:
        calls = write_calls(Seed(unit))
        if operation == "existing_team":
            Seed(unit).team(name="new-team")
            unit.commit()
    method = {"bare_ref": "register_ref", "existing_team": "assign_owner"}.get(operation, operation)
    args = calls[method]
    if operation == "bare_ref":
        args = {**args, "name": None, "kind": None}
    barrier = Barrier(2, timeout=15)

    def synchronize(
        _conn: sa.Connection,
        _cursor: object,
        _sql: str,
        _params: object,
        context: sa.ExecutionContext,
        _many: bool,
    ) -> None:
        if context.isinsert and context.compiled.statement.table.name == target:
            barrier.wait()

    def register(worker: int) -> Entity:
        supplied = dict(args)
        if method == "register_product":
            supplied["name"] = f"Writer {worker}"
        elif method == "register_repository":
            supplied["public"] = bool(worker)
        elif method == "assign_owner":
            supplied["at"] = T0 + timedelta(days=worker)
        return getattr(portfolio(SqlTraustUnitOfWork(engine)), method)(**supplied)

    sa.event.listen(engine, "before_cursor_execute", synchronize)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(register, range(2)))
    finally:
        sa.event.remove(engine, "before_cursor_execute", synchronize)
    assert results[0] == results[1]
    assert getattr(portfolio(unit), method)(**args) == results[0]
    with unit:
        if method == "assign_owner":
            assert len(unit.ownerships.current(args["repository_id"])) == 1
        repository = getattr(
            unit,
            {
                "register_product": "products",
                "register_repository": "repositories",
                "register_ref": "repository_refs",
                "record_release": "releases",
                "add_component": "components",
                "assign_owner": "ownerships",
            }[method],
        )
        assert repository.get(results[0].id) == results[0]
