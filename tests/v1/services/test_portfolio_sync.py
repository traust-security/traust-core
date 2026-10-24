"""PortfolioSync: forge listings and the declared ownership source into the portfolio, on SQLite
and Postgres."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0
from traust_core.v1.errors import NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.inventory import (
    OrgName,
    OwnerAssignment,
    OwnershipSource,
    RefName,
    SyncReport,
    TeamName,
)
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoPath
from traust_core.v1.models.vocabulary import RefKind
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import OwnerHint, OwnerOrigin, RepoInfo, SourceError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService, PortfolioSync

HOSTS = ("github.com", "gitlab.com")


def url(path: str, host: str = "github.com") -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(f"https://{host}/{path}", HOSTS)


class Forge:
    name = "fake-forge"

    def __init__(
        self,
        listing: Sequence[RepoInfo] = (),
        visibility: str | None = "public",
        heads: dict[str, str] | None = None,
        error: SourceError | None = None,
    ) -> None:
        self.listing, self.visibility, self.heads, self.error = listing, visibility, heads, error
        self.calls: list[str] = []

    def _result(self, data):
        return Result(data, Acquisition(provider=self.name, acquired_at=T0))

    def list_org(self, org: OrgName, host: str) -> Result[list[RepoInfo]]:
        self.calls.append(f"list_org {host}/{org}")
        if self.error:
            raise self.error
        return self._result(list(self.listing))

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]:
        self.calls.append(f"info {repo}")
        return self._result(RepoInfo(repo=repo, visibility=self.visibility))

    def head(self, repo: HttpsRepoUrl, branch: str) -> Result[GitSha]:
        assert self.heads is not None
        return self._result(GitSha.parse(self.heads[branch]))

    def owners(self, repo: HttpsRepoUrl) -> Result[list[OwnerHint]]:
        return self._result([OwnerHint(handle="approver-a", origin=OwnerOrigin.OWNERS_FILE)])

    def file(self, repo: HttpsRepoUrl, path: RepoPath, sha: GitSha) -> Result[str | None]:
        self.calls.append(f"file {repo} {path}@{sha}")
        return self._result("kind: ClusterServiceVersion\n" if str(path) == "csv.yaml" else None)


def listed(*paths: str, visibility: str = "public") -> list[RepoInfo]:
    return [RepoInfo(repo=url(p), visibility=visibility) for p in paths]


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def portfolio(engine: Engine) -> PortfolioService:
    return PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())


def sync(portfolio: PortfolioService, forge: Forge, at: datetime = T0) -> PortfolioSync:
    return PortfolioSync(portfolio, forge, clock=FixedClock(at))  # type: ignore[arg-type]


def ownerships(engine: Engine, repo: HttpsRepoUrl) -> list[tuple[str, datetime, datetime | None]]:
    with SqlTraustUnitOfWork(engine) as uow:
        repository = uow.repositories.find_by_url(str(repo))
        assert repository is not None and repository.id is not None
        rows = uow.ownerships.current(repository.id) + [
            o
            for at in (T0 - timedelta(days=1), T0)
            for o in uow.ownerships.as_of(repository.id, at)
        ]
        teams = {o.team_id: uow.teams.get(o.team_id).name for o in rows}
    unique = {o.id: o for o in rows}.values()
    return sorted((teams[o.team_id], o.valid_from, o.valid_to) for o in unique)


def test_import_org_registers_new_repositories_and_keeps_registered_ones(
    portfolio: PortfolioService,
) -> None:
    kept = portfolio.register_repository(url("example-org/api"), public=False)
    forge = Forge(listed("example-org/api", "example-org/cli", "example-org/web"))
    report = sync(portfolio, forge).import_org(OrgName("example-org"), "github.com")
    assert report.unchanged == (kept.id,) and len(report.added) == 2
    assert portfolio.find_repository(url("example-org/api")) == kept
    added = [portfolio.get_repository(i) for i in report.added]
    assert [(r.url, r.public) for r in added] == [
        ("https://github.com/example-org/cli", True),
        ("https://github.com/example-org/web", True),
    ]
    assert forge.calls == ["list_org github.com/example-org"]
    again = sync(portfolio, forge).import_org(OrgName("example-org"), "github.com")
    assert again == SyncReport(unchanged=(kept.id, *report.added))


@pytest.mark.parametrize("visibility", ["private", "internal"])
def test_a_repository_the_forge_does_not_call_public_is_registered_private(
    portfolio: PortfolioService, visibility: str
) -> None:
    forge = Forge(listed("example-org/secret", visibility=visibility))
    report = sync(portfolio, forge).import_org(OrgName("example-org"), "github.com")
    assert portfolio.get_repository(report.added[0]).public is False


def test_an_empty_org_imports_nothing(portfolio: PortfolioService) -> None:
    assert sync(portfolio, Forge()).import_org(OrgName("empty"), "github.com") == SyncReport()


def test_a_forge_failure_imports_nothing(portfolio: PortfolioService) -> None:
    forge = Forge(error=SourceError("HTTP 403 rate limit", ComparisonStatus.ERROR))
    with pytest.raises(SourceError):
        sync(portfolio, forge).import_org(OrgName("example-org"), "github.com")


@pytest.mark.parametrize(("visibility", "public"), [("public", True), (None, False)])
def test_import_repository_asks_the_forge_only_for_a_new_repository(
    portfolio: PortfolioService, visibility: str | None, public: bool
) -> None:
    forge = Forge(visibility=visibility)
    repo = url("example-group/sub/api", "gitlab.com")
    added = sync(portfolio, forge).import_repository(repo)
    assert portfolio.get_repository(added.added[0]).public is public
    assert sync(portfolio, forge).import_repository(repo) == SyncReport(unchanged=added.added)
    assert forge.calls == [f"info {repo}"]


def test_import_branch_registers_the_commit_the_branch_points_at(
    portfolio: PortfolioService,
) -> None:
    repository = portfolio.register_repository(url("example-org/api"), public=True)
    assert repository.id is not None
    forge = Forge(heads={"main": "c" * 40})
    ref = sync(portfolio, forge).import_branch(
        repository.id, url("example-org/api"), RefName("main")
    )
    assert (ref.name, ref.kind, ref.sha) == ("main", RefKind.BRANCH, "c" * 40)
    again = sync(portfolio, forge).import_branch(
        repository.id, url("example-org/api"), RefName("main")
    )
    assert again == ref


def test_owner_hints_are_the_forge_answer(portfolio: PortfolioService) -> None:
    hints = sync(portfolio, Forge()).owner_hints(url("example-org/api"))
    assert [h.handle for h in hints] == ["approver-a"]


@pytest.mark.parametrize(
    ("path", "text"), [("csv.yaml", "kind: ClusterServiceVersion\n"), ("absent.yaml", None)]
)
def test_find_file_is_the_forge_answer_at_the_pinned_commit(
    portfolio: PortfolioService, path: str, text: str | None
) -> None:
    forge, sha = Forge(), GitSha("c" * 40)
    assert sync(portfolio, forge).find_file(url("example-org/api"), RepoPath(path), sha) == text
    assert forge.calls == [f"file https://github.com/example-org/api {path}@{sha}"]


def test_import_owners_mirrors_the_declared_source(
    portfolio: PortfolioService, engine: Engine
) -> None:
    api, cli, web, other = (
        url(p) for p in ("example-org/api", "example-org/cli", "example-org/web", "other/lib")
    )
    for repo in (api, cli, web, other):
        portfolio.register_repository(repo, public=True)
    web_id = portfolio.find_repository(web).id  # type: ignore[union-attr]
    assert web_id is not None
    portfolio.assign_owner(web_id, "Old Team", T0 - timedelta(days=30))
    source = OwnershipSource(
        assignments=(
            OwnerAssignment(repo=api, teams=(TeamName("API Team"),)),
            OwnerAssignment(repo=api, teams=(TeamName("Security"),)),
            OwnerAssignment(repo=url("example-org/gone"), teams=(TeamName("API Team"),)),
        ),
        org_teams={OrgName("example-org"): TeamName("Platform Team")},
    )
    report = sync(portfolio, Forge()).import_owners(source)
    assert len(report.added) == 4 and len(report.removed) == 1 and report.unchanged == ()
    assert report.skipped == ("https://github.com/example-org/gone",)
    assert ownerships(engine, api) == [("API Team", T0, None), ("Security", T0, None)]
    assert ownerships(engine, cli) == [("Platform Team", T0, None)]
    assert ownerships(engine, web) == [
        ("Old Team", T0 - timedelta(days=30), T0),
        ("Platform Team", T0, None),
    ]
    assert ownerships(engine, other) == []

    later = T0 + timedelta(days=1)
    again = sync(portfolio, Forge(), later).import_owners(source)
    assert again.added == again.removed == () and len(again.unchanged) == 4

    moved = OwnershipSource(assignments=(OwnerAssignment(repo=api, teams=(TeamName("Security"),)),))
    changed = sync(portfolio, Forge(), later).import_owners(moved)
    assert changed.added == () and len(changed.removed) == 3 and len(changed.unchanged) == 1
    assert ownerships(engine, api)[0] == ("API Team", T0, later)


def test_import_owners_on_an_empty_inventory_skips_every_assignment(
    portfolio: PortfolioService,
) -> None:
    source = OwnershipSource(
        assignments=(OwnerAssignment(repo=url("example-org/api"), teams=(TeamName("T"),)),)
    )
    assert sync(portfolio, Forge()).import_owners(source) == SyncReport(
        skipped=("https://github.com/example-org/api",)
    )


@pytest.mark.parametrize(
    ("teams", "at", "error"),
    [
        (["  "], T0, ValidationError),
        (["Team"], datetime(2026, 10, 5), ValidationError),
    ],
)
def test_set_owners_rejects_blank_teams_and_naive_times(
    portfolio: PortfolioService, teams: list[str], at: datetime, error: type[Exception]
) -> None:
    repository = portfolio.register_repository(url("example-org/api"), public=True)
    assert repository.id is not None
    with pytest.raises(error):
        portfolio.set_owners(repository.id, [TeamName(t) for t in teams], at)


def test_set_owners_on_an_unknown_repository_is_not_found(portfolio: PortfolioService) -> None:
    with pytest.raises(NotFoundError):
        portfolio.set_owners(uuid4(), [TeamName("Team")], T0)


def test_a_failed_set_owners_rolls_back_every_row(
    portfolio: PortfolioService, engine: Engine
) -> None:
    repo = url("example-org/api")
    repository = portfolio.register_repository(repo, public=True)
    assert repository.id is not None
    portfolio.assign_owner(repository.id, "Current", T0)
    with pytest.raises(RepositoryError):
        portfolio.set_owners(repository.id, [TeamName("New")], T0 - timedelta(days=1))
    assert ownerships(engine, repo) == [("Current", T0, None)]
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.teams.find_by_name("New") is None
