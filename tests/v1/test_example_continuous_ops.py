import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.v1.example.continuous_ops import cli
from tests.v1.example.continuous_ops.materializer import RepoStateMaterializer
from tests.v1.example.continuous_ops.model import ObserveStatus
from tests.v1.example.continuous_ops.repository import (
    InMemoryRepoStateUnitOfWork,
    RepoStateUnitOfWork,
    SqlRepoStateUnitOfWork,
    metadata,
)
from tests.v1.example.continuous_ops.router import RepoRouter
from traust_core.v1.context import Config, Context
from traust_core.v1.domain import FixedClock, GitSha, HttpsRepoUrl, Outcome, ServiceError
from traust_core.v1.interfaces import AssetRequest, Provenance, Readiness, RepoInfo, Result
from traust_core.v1.repositories import create_database_engine

CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))
HOSTS = ["github.com"]
URL = "https://github.com/org/repo"
REPO = HttpsRepoUrl.parse(URL, HOSTS)
OLD, NEW = "a" * 40, "b" * 40


class FakeForge:
    name = "fake-forge"

    def __init__(self, heads: dict[str, str]) -> None:
        self._heads = heads

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]:
        if str(repo) not in self._heads:
            raise ServiceError(f"{repo}: unreachable")
        info = RepoInfo(repo=repo, head=GitSha(self._heads[str(repo)]))
        return Result(info, Provenance(provider=self.name, acquired_at=CLOCK.now()))

    def checkout(self, request: object) -> Result[object]:
        raise NotImplementedError

    def release(self, workspace: object) -> None:
        raise NotImplementedError


@pytest.fixture(params=["memory", "sqlite"])
def uow_factory(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[object]:
    if request.param == "memory":
        uow = InMemoryRepoStateUnitOfWork()
        yield lambda: uow
        return
    engine = create_database_engine(f"sqlite:///{tmp_path}/ops.db")
    metadata.create_all(engine)
    yield lambda: SqlRepoStateUnitOfWork(engine)


def engine_context(uow_factory: object, heads: dict[str, str]) -> Context:
    ctx = Context(Config(), clock=CLOCK)
    ctx.assets.register(
        "repo_state", lambda: RepoStateMaterializer(uow_factory, FakeForge(heads), ctx.clock, HOSTS)
    )
    return ctx


def stored(uow_factory: object) -> object:
    uow: RepoStateUnitOfWork = uow_factory()
    with uow:
        return uow.repo_state.get(REPO)


def test_engine_path_imports_and_calls_the_service(uow_factory: object) -> None:
    ctx = engine_context(uow_factory, {URL: NEW})
    result = ctx.assets.get("repo_state").materialize(
        AssetRequest(
            asset="repo_state", run_id="tick-1", partition=URL, params={"audited_head": OLD}
        )
    )
    assert result.outcome is Outcome.SUCCEEDED
    state = stored(uow_factory)
    assert (state.status, str(state.head)) == (ObserveStatus.OK, NEW)
    assert RepoRouter().route(state, [], []).lane == "diff-scan"


def test_llm_path_runs_the_cli_and_lands_on_the_same_service(
    uow_factory: object, capsys: pytest.CaptureFixture[str]
) -> None:
    materializer = engine_context(uow_factory, {URL: NEW}).assets.get("repo_state")
    code = cli.main(["--repo", URL, "--audited-head", OLD], materializer)
    assert code == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "succeeded"
    assert str(stored(uow_factory).head) == NEW


def test_unreachable_repo_is_degraded_not_failed(uow_factory: object) -> None:
    ctx = engine_context(uow_factory, {})
    result = ctx.assets.get("repo_state").materialize(
        AssetRequest(asset="repo_state", run_id="tick-1", partition=URL)
    )
    assert result.outcome is Outcome.DEGRADED and result.degraded == {"unreachable": 1}
    state = stored(uow_factory)
    assert state.status is ObserveStatus.UNREACHABLE
    assert RepoRouter().route(state, [], []).lane is None


def test_bad_partition_fails_without_touching_data(uow_factory: object) -> None:
    ctx = engine_context(uow_factory, {URL: NEW})
    result = ctx.assets.get("repo_state").materialize(
        AssetRequest(asset="repo_state", run_id="tick-1", partition="ssh://github.com/org/repo")
    )
    assert result.outcome is Outcome.FAILED
    assert stored(uow_factory) is None


def test_job_result_with_nothing_degraded_is_succeeded() -> None:
    from traust_core.v1.domain import JobResult

    assert JobResult.partly({}).outcome is Outcome.SUCCEEDED
