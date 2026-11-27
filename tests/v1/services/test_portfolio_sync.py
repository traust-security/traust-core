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
from tests.v1.repositories.tables.conftest import T0, Seed, apart
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConflictError, NotFoundError, RepositoryError, ValidationError
from traust_core.v1.models.artifacts import RepoStateArtifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.inventory import (
    OrgName,
    OwnerAssignment,
    OwnershipSource,
    RefName,
    RepositoryFilter,
    SyncReport,
    TeamName,
)
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoPath
from traust_core.v1.models.vocabulary import LivenessStatus, RefKind
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.sources import OwnerHint, OwnerOrigin, RepoInfo, SourceError
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog
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
        described: RepoInfo | None = None,
        info_error: SourceError | ValidationError | None = None,
        head_error: SourceError | None = None,
    ) -> None:
        self.listing, self.visibility, self.heads, self.error = listing, visibility, heads, error
        self.described, self.info_error, self.head_error = described, info_error, head_error
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
        if self.info_error:
            raise self.info_error
        return self._result(self.described or RepoInfo(repo=repo, visibility=self.visibility))

    def head(self, repo: HttpsRepoUrl, branch: str) -> Result[GitSha]:
        if self.head_error:
            raise self.head_error
        assert self.heads is not None
        return self._result(GitSha.parse(self.heads[branch]))

    def owners(self, repo: HttpsRepoUrl) -> Result[list[OwnerHint]]:
        return self._result([OwnerHint(handle="approver-a", origin=OwnerOrigin.OWNERS_FILE)])

    def file(self, repo: HttpsRepoUrl, path: RepoPath, sha: GitSha) -> Result[str | None]:
        self.calls.append(f"file {repo} {path}@{sha}")
        return self._result("kind: ClusterServiceVersion\n" if str(path) == "csv.yaml" else None)


def listed(*paths: str, visibility: str = "public") -> list[RepoInfo]:
    return [RepoInfo(repo=url(p), visibility=visibility) for p in paths]


def describing(repo: str, parent: str | None, *, fork: bool = True) -> RepoInfo:
    return RepoInfo(repo=url(repo), visibility="public", fork=fork, parent=parent)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def portfolio(engine: Engine) -> PortfolioService:
    return PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy())


def repository_count(portfolio: PortfolioService) -> int:
    page = portfolio.list_repositories(RepositoryFilter(), PageRequest(limit=100))
    return len(page.items)


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
def test_import_repository_asks_the_forge_for_a_new_repository_and_an_unlinked_one(
    portfolio: PortfolioService, visibility: str | None, public: bool
) -> None:
    forge = Forge(visibility=visibility)
    repo = url("example-group/sub/api", "gitlab.com")
    added = sync(portfolio, forge).import_repository(repo)
    assert portfolio.get_repository(added.added[0]).public is public
    # a known repository without an upstream is asked once more: the forge may name its parent
    assert sync(portfolio, forge).import_repository(repo) == SyncReport(unchanged=added.added)
    assert forge.calls == [f"info {repo}", f"info {repo}"]


def test_import_repository_registers_a_fork_with_its_upstream(
    portfolio: PortfolioService,
) -> None:
    forge = Forge(described=describing("example-org/fork", "example-org/api"))
    report = sync(portfolio, forge).import_repository(url("example-org/fork"))
    fork = portfolio.get_repository(report.added[0])
    parent = portfolio.find_repository(url("example-org/api"))
    assert parent is not None and parent.id is not None
    assert fork.upstream_id == parent.id
    # the parent is brought in private, until its own import says otherwise
    assert parent.public is False


@pytest.mark.parametrize("fork", [False, None])
def test_import_repository_leaves_a_non_fork_without_an_upstream(
    portfolio: PortfolioService, fork: bool | None
) -> None:
    # fork=None is the forge not saying: no lineage is recorded either way
    forge = Forge(described=describing("example-org/plain", None, fork=fork))
    report = sync(portfolio, forge).import_repository(url("example-org/plain"))
    assert portfolio.get_repository(report.added[0]).upstream_id is None


def test_import_repository_backfills_a_known_forks_missing_upstream(
    portfolio: PortfolioService,
) -> None:
    registered = portfolio.register_repository(url("example-org/fork"), public=True)
    assert registered.id is not None
    forge = Forge(described=describing("example-org/fork", "example-org/api"))
    report = sync(portfolio, forge).import_repository(url("example-org/fork"))
    assert report == SyncReport(unchanged=(registered.id,))
    parent = portfolio.find_repository(url("example-org/api"))
    assert parent is not None and parent.id is not None
    assert portfolio.get_repository(registered.id).upstream_id == parent.id


def test_import_repository_leaves_a_linked_fork_unchanged(portfolio: PortfolioService) -> None:
    forge = Forge(described=describing("example-org/fork", "example-org/api"))
    first = sync(portfolio, forge).import_repository(url("example-org/fork"))
    linked = portfolio.get_repository(first.added[0])
    assert linked.id is not None and linked.upstream_id is not None
    again = sync(portfolio, forge).import_repository(url("example-org/fork"))
    assert again == SyncReport(unchanged=(linked.id,))
    assert portfolio.get_repository(linked.id).upstream_id == linked.upstream_id
    # the link settles the question: the forge is not asked again
    assert forge.calls == [f"info {url('example-org/fork')}"]


def test_import_repository_matches_the_forks_parent_by_normalized_url(
    portfolio: PortfolioService,
) -> None:
    parent = portfolio.register_repository(url("example-org/api"), public=True)
    assert parent.id is not None
    forge = Forge(described=describing("example-org/fork", "Example-Org/API"))
    report = sync(portfolio, forge).import_repository(url("example-org/fork"))
    assert portfolio.get_repository(report.added[0]).upstream_id == parent.id
    assert repository_count(portfolio) == 2  # the fork and its one parent row


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
    # the same row, its head confirmed again (the naming time is stamped anew)
    assert (again.id, again.sha) == (ref.id, ref.sha)
    assert again.default_named_at is not None and ref.default_named_at is not None
    assert again.default_named_at >= ref.default_named_at


def test_a_default_line_the_forge_couldnt_give_fails_the_import_and_a_retry_imports_it(
    portfolio: PortfolioService,
) -> None:
    """A forge that can't give the head raises before anything is written — no
    half-registered repository — so the next import asks again (Qodo 392: a linked fork
    was never asked for its default line)."""
    fork = url("example-org/fork")
    forge = Forge(
        described=RepoInfo(
            repo=fork,
            visibility="public",
            fork=True,
            parent="example-org/api",
            default_branch="main",
        ),
        heads={"main": "c" * 40},
        head_error=SourceError("forge down", ComparisonStatus.UNREACHABLE),
    )
    with pytest.raises(SourceError, match="forge down"):
        sync(portfolio, forge).import_repository(fork)
    assert portfolio.find_repository(fork) is None  # nothing was written
    forge.head_error = None
    report = sync(portfolio, forge).import_repository(fork)
    (repository_id,) = report.added
    line = portfolio.inventory.default_line(repository_id)
    assert line is not None and (line.name, line.sha) == ("main", "c" * 40)
    assert portfolio.get_repository(repository_id).upstream_id is not None
    assert sync(portfolio, forge).import_repository(fork) == SyncReport(unchanged=(repository_id,))
    assert forge.calls.count(f"info {fork}") == 2  # a linked fork with its line isn't asked


def test_an_empty_repository_imports_without_a_default_line(
    portfolio: PortfolioService,
) -> None:
    """The forge answered that the default branch names no commit (an empty repository):
    registered like any repository, just without a default line — the forge answered, so
    it is not an outage to fail on."""
    repo = url("example-org/empty")
    forge = Forge(
        described=RepoInfo(repo=repo, visibility="public", default_branch="main"),
        head_error=SourceError(
            f"{repo}: no commit on branch main",
            ComparisonStatus.ERROR,
            empty_repository=True,
        ),
    )
    (repository_id,) = sync(portfolio, forge).import_repository(repo).added
    assert portfolio.inventory.default_line(repository_id) is None
    assert portfolio.get_repository(repository_id).url == str(repo)


def test_import_branch_on_the_default_line_returns_its_latest_flagged_head(
    portfolio: PortfolioService,
) -> None:
    """The recorded default line names the branch, so no forge metadata call can fail it, and
    the ref returned is the flagged row (Qodo 392)."""
    api = url("example-org/api")
    forge = Forge(described=RepoInfo(repo=api, visibility="public", default_branch="main"))
    forge.heads = {"main": "c" * 40, "dev": "e" * 40}
    (repository_id,) = sync(portfolio, forge).import_repository(api).added
    apart()
    forge.heads["main"] = "d" * 40
    forge.info_error = SourceError("forge down", ComparisonStatus.UNREACHABLE)
    ref = sync(portfolio, forge).import_branch(repository_id, api, RefName("main"))
    assert (ref.sha, ref.is_default) == ("d" * 40, True)
    assert portfolio.inventory.default_line(repository_id) == ref
    other = sync(portfolio, forge).import_branch(repository_id, api, RefName("dev"))
    assert (other.sha, other.is_default) == ("e" * 40, False)
    assert portfolio.inventory.default_line(repository_id) == ref


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


def test_set_owners_stamps_cores_clock_on_both_ends(engine: Engine) -> None:
    repo = url("example-org/api")
    opened = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy(), clock=FixedClock(T0))
    repository = opened.register_repository(repo, public=True)
    assert repository.id is not None
    opened.set_owners(repository.id, [TeamName("Old")])
    later = T0 + timedelta(days=1)
    uow = SqlTraustUnitOfWork(engine)
    moved = PortfolioService(uow, PortfolioPolicy(), clock=FixedClock(later))
    moved.set_owners(repository.id, [TeamName("New")])
    with SqlTraustUnitOfWork(engine) as uow:
        before = {uow.teams.get(o.team_id).name for o in uow.ownerships.as_of(repository.id, T0)}
        after = {uow.teams.get(o.team_id).name for o in uow.ownerships.as_of(repository.id, later)}
    assert (before, after) == ({"Old"}, {"New"})


def test_set_owners_never_closes_ownership_at_or_before_it_opened(
    portfolio: PortfolioService, engine: Engine
) -> None:
    repo = url("example-org/api")
    repository = portfolio.register_repository(repo, public=True)
    assert repository.id is not None
    portfolio.set_owners(repository.id, [TeamName("Current")], T0)
    with pytest.raises(ConflictError):
        portfolio.set_owners(repository.id, [], T0)
    assert ownerships(engine, repo) == [("Current", T0, None)]


def test_a_parents_own_import_corrects_its_placeholder_visibility(
    portfolio: PortfolioService,
) -> None:
    fork_forge = Forge(described=describing("example-org/fork", "example-org/api"))
    sync(portfolio, fork_forge).import_repository(url("example-org/fork"))
    parent = portfolio.find_repository(url("example-org/api"))
    assert parent is not None and parent.id is not None and parent.public is False

    parent_forge = Forge(described=describing("example-org/api", None, fork=False))
    report = sync(portfolio, parent_forge).import_repository(url("example-org/api"))
    assert report == SyncReport(unchanged=(parent.id,))
    assert portfolio.get_repository(parent.id).public is True


def test_a_fork_links_a_parent_registered_in_another_case(portfolio: PortfolioService) -> None:
    parent = portfolio.register_repository(url("Example-Org/API"), public=True)
    assert parent.id is not None
    forge = Forge(described=describing("example-org/fork", "Example-Org/API"))
    report = sync(portfolio, forge).import_repository(url("example-org/fork"))
    assert portfolio.get_repository(report.added[0]).upstream_id == parent.id
    assert repository_count(portfolio) == 2  # the fork and its one parent row


def test_a_forge_outage_on_a_known_repository_raises_and_writes_nothing(
    portfolio: PortfolioService,
) -> None:
    known = portfolio.register_repository(url("example-org/api"), public=True)
    assert known.id is not None
    forge = Forge(info_error=SourceError("forge down", ComparisonStatus.UNREACHABLE))
    with pytest.raises(SourceError):
        sync(portfolio, forge).import_repository(url("example-org/api"))
    assert portfolio.get_repository(known.id) == known  # nothing changed without the forge


def test_a_parent_imported_in_another_case_is_the_forks_placeholder(
    portfolio: PortfolioService,
) -> None:
    fork_forge = Forge(described=describing("example-org/fork", "Example-Org/API"))
    fork_id = sync(portfolio, fork_forge).import_repository(url("example-org/fork")).added[0]
    placeholder_id = portfolio.get_repository(fork_id).upstream_id
    assert placeholder_id is not None

    parent_forge = Forge(described=describing("Example-Org/API", None, fork=False))
    report = sync(portfolio, parent_forge).import_repository(url("Example-Org/API"))
    assert report == SyncReport(unchanged=(placeholder_id,))  # no second row
    assert portfolio.get_repository(placeholder_id).public is True


def test_a_known_repository_the_forge_reports_gone_stays_unchanged(
    portfolio: PortfolioService,
) -> None:
    """The forge's positive no-such-repository is the disposition's evidence (Qodo #474),
    not a failed import; a repository that isn't known yet raises instead."""
    known = portfolio.register_repository(url("example-org/api"), public=True)
    assert known.id is not None
    gone = SourceError(
        "the forge reports no such repository",
        ComparisonStatus.ERROR,
        liveness_status=LivenessStatus.MISSING,
    )
    report = sync(portfolio, Forge(info_error=gone)).import_repository(url("example-org/api"))
    assert report == SyncReport(unchanged=(known.id,))
    with pytest.raises(SourceError):
        sync(portfolio, Forge(info_error=gone)).import_repository(url("example-org/other"))


def test_a_host_the_forge_cannot_ask_raises_and_writes_nothing(
    portfolio: PortfolioService,
) -> None:
    known = portfolio.register_repository(url("example-org/api"), public=True)
    assert known.id is not None
    forge = Forge(info_error=ValidationError("unsupported forge kind: example"))
    with pytest.raises(ValidationError, match="unsupported forge kind"):
        sync(portfolio, forge).import_repository(url("example-org/api"))
    assert portfolio.get_repository(known.id) == known


def test_every_lookup_and_registration_finds_a_github_repository_in_any_case(
    portfolio: PortfolioService,
) -> None:
    # GitHub's owner/repo is case-insensitive: planning, filtered reads and registration all
    # resolve the row a fork's lowercase placeholder (or anyone) registered
    first = portfolio.register_repository(url("example-org/api"), public=False)
    again = portfolio.register_repository(url("Example-Org/API"), public=True)
    assert again.id == first.id and repository_count(portfolio) == 1
    found = portfolio.find_repository(url("EXAMPLE-ORG/api"))
    assert found is not None and found.id == first.id
    listed = portfolio.list_repositories(
        RepositoryFilter(url=str(url("Example-Org/Api"))), PageRequest(limit=10)
    )
    assert [r.id for r in listed.items] == [first.id]
    # GitLab keeps exact matching
    lab = portfolio.register_repository(url("group/app", "gitlab.com"), public=False)
    assert portfolio.find_repository(url("Group/App", "gitlab.com")) is None
    assert lab.id is not None


def test_sync_resolves_a_custom_hosts_fork_with_the_portfolios_hosts(engine: Engine) -> None:
    hosts = {"github.com": "github", "github.example.com": "github"}
    portfolio = PortfolioService(SqlTraustUnitOfWork(engine), PortfolioPolicy(), hosts=hosts)
    fork_url = HttpsRepoUrl.parse("https://github.example.com/mirror-org/api", hosts)
    described = RepoInfo(repo=fork_url, visibility="private", fork=True, parent="example-org/api")
    # no hosts given: the sync resolves the parent with the portfolio's
    report = PortfolioSync(portfolio, Forge(described=described)).import_repository(fork_url)  # type: ignore[arg-type]
    fork_id = report.added[0]
    upstream_id = portfolio.get_repository(fork_id).upstream_id
    assert upstream_id is not None
    assert portfolio.get_repository(upstream_id).url == "https://github.example.com/example-org/api"


@pytest.mark.parametrize("visibility", ["public", "Public", "PUBLIC"])
def test_a_new_repository_is_registered_with_its_final_visibility(
    portfolio: PortfolioService, engine: Engine, visibility: str
) -> None:
    repo = url(f"example-org/api-{visibility}")
    report = sync(portfolio, Forge(visibility=visibility)).import_repository(repo)
    registered = portfolio.get_repository(report.added[0])
    assert registered.public is True
    assert registered.updated_at == registered.created_at  # written once, not flipped after


@pytest.mark.parametrize(("answer", "asked"), [(False, False), (True, True), (None, True)])
def test_a_known_non_fork_is_asked_again_only_without_the_forges_answer(
    tmp_path: Path, answer: bool | None, asked: bool
) -> None:
    context = Context(Config(home=tmp_path))
    portfolio = context.services().portfolio
    known = portfolio.register_repository(url("example-org/app"), public=True)
    said = {"observed_at": T0.isoformat(), "status": "ok"}
    if answer is not None:
        said["fork"] = answer  # type: ignore[assignment]
    published = portfolio._require_publisher().publish_ref(RepoStateArtifact.from_document(said))
    with SqlTraustUnitOfWork(context.database) as uow:
        ref = Seed(uow).repository_ref(Seed(uow).repository(), is_default=True)
        ref = uow.repository_refs.update(ref.model_copy(update={"repository_id": known.id}))
        observation = Seed(uow).assessment(ref, kind="repo_state")
        assert observation.id is not None
        AssessmentLog(uow).attach(observation.id, published.id, published.digest)
        uow.commit()
    assert portfolio.fork_answer(known.id) is answer  # type: ignore[arg-type]
    forge = Forge(described=RepoInfo(repo=url("example-org/app"), visibility="public"))
    report = sync(portfolio, forge).import_repository(url("example-org/app"))
    assert report.unchanged == (known.id,)
    assert (f"info {url('example-org/app')}" in forge.calls) is asked


def test_an_observation_without_a_fork_answer_never_stops_a_later_link(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path))
    portfolio = context.services().portfolio
    fork = portfolio.register_repository(url("example-org/fork"), public=False)
    silent = RepoStateArtifact.from_document({"observed_at": T0.isoformat(), "status": "ok"})
    published = portfolio._require_publisher().publish_ref(silent)
    with SqlTraustUnitOfWork(context.database) as uow:  # observed, the forge silent on forks
        ref = Seed(uow).repository_ref(Seed(uow).repository(), is_default=True)
        ref = uow.repository_refs.update(ref.model_copy(update={"repository_id": fork.id}))
        observation = Seed(uow).assessment(ref, kind="repo_state")
        assert observation.id is not None
        AssessmentLog(uow).attach(observation.id, published.id, published.digest)
        uow.commit()
    forge = Forge(described=describing("example-org/fork", "example-org/api"))
    sync(portfolio, forge).import_repository(url("example-org/fork"))
    assert forge.calls == [f"info {url('example-org/fork')}"]  # still asked
    assert portfolio.get_repository(fork.id).upstream_id is not None  # type: ignore[arg-type]
