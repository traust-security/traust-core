"""LocalCheckout: a commit's tree straight off a repository on this machine — a worktree per
checkout, removed and pruned on release so the materialized repository re-runs clean, with no
mirror, no fetch and no cache behind it."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import commit_all, git
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.process import ProcessError, ProcessResult, ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace

AT = datetime(2026, 10, 30, tzinfo=UTC)
HEAD = GitSha.parse("a" * 40)
HTTPS = HttpsRepoUrl.parse("https://github.com/o/r", ("github.com",))


def materialized(tmp_path: Path, *contents: bytes) -> tuple[Path, GitSha]:
    """A repository a caller materialized on this machine, one commit per content blob."""
    repo = tmp_path / "canary"
    repo.mkdir()
    git(repo, "init", "-q")
    sha = GitSha.parse("0" * 40)
    for i, content in enumerate(contents):
        (repo / f"f{i}.txt").write_bytes(content)
        sha = GitSha.parse(commit_all(repo, f"c{i}"))
    return repo, sha


def provider() -> LocalCheckout:
    return LocalCheckout(ProcessRunner(("git",)), FixedClock(AT))


def request(repo: Path, ref: GitSha, **kwargs: Any) -> CheckoutRequest:
    return CheckoutRequest(repo=LocalRepoUrl.parse(str(repo)), ref=ref, **kwargs)


def registered(repo: Path) -> list[str]:
    return [
        line
        for line in git(repo, "worktree", "list", "--porcelain").splitlines()
        if line.startswith("worktree ")
    ]


@pytest.mark.parametrize("writable", [False, True], ids=["read-only", "writable"])
def test_a_local_checkout_at_a_pinned_sha_is_the_commits_worktree(
    tmp_path: Path, writable: bool
) -> None:
    repo, head = materialized(tmp_path, b"hello\n")
    result = provider().checkout(request(repo, head, writable=writable))
    workspace = result.data
    assert (workspace.path / "f0.txt").read_bytes() == b"hello\n"
    assert (workspace.provider, workspace.sha) == ("git-local", head)
    assert result.acquisition.source == f"file://{repo}"
    if writable:
        (workspace.path / "fix.txt").write_text("a fleet fix\n")
    provider().release(workspace)
    assert not workspace.path.exists()
    assert registered(repo) == [f"worktree {repo}"]


@pytest.mark.parametrize(
    "cited",
    [lambda repo: str(repo), lambda repo: f"file://{repo}"],
    ids=["plain-path", "file-url"],
)
def test_a_local_origin_is_cited_as_a_path_or_a_file_url(tmp_path: Path, cited: str) -> None:
    repo, head = materialized(tmp_path, b"hello\n")
    workspace = provider().checkout(CheckoutRequest(repo=cited(repo), ref=head)).data
    assert (workspace.path / "f0.txt").read_bytes() == b"hello\n"
    provider().release(workspace)


def test_the_materialized_repository_stays_clean_for_re_runs(tmp_path: Path) -> None:
    repo, head = materialized(tmp_path, b"hello\n")
    p = provider()
    for _ in range(2):
        workspace = p.checkout(request(repo, head)).data
        p.release(workspace)
    assert registered(repo) == [f"worktree {repo}"]


def test_release_prunes_a_registration_whose_worktree_directory_is_already_gone(
    tmp_path: Path,
) -> None:
    repo, head = materialized(tmp_path, b"hello\n")
    p = provider()
    workspace = p.checkout(request(repo, head)).data
    shutil.rmtree(workspace.path)  # a crash took the directory, the registration remains
    p.release(workspace)
    assert registered(repo) == [f"worktree {repo}"]


def test_a_bare_local_repository_checks_out_too(tmp_path: Path) -> None:
    work, head = materialized(tmp_path, b"hello\n")
    bare = tmp_path / "canary.git"
    git(work, "clone", "-q", "--bare", str(work), str(bare))
    p = provider()
    workspace = p.checkout(request(bare, head)).data
    assert (workspace.path / "f0.txt").read_bytes() == b"hello\n"
    p.release(workspace)
    assert registered(bare) == [f"worktree {bare}"]


@pytest.mark.parametrize(
    "make_unhealthy",
    [
        lambda tmp_path: tmp_path / "missing",
        lambda tmp_path: (tmp_path / "plain").mkdir() or tmp_path / "plain",
        lambda tmp_path: (
            shutil.rmtree(tmp_path / "canary" / ".git" / "refs") or tmp_path / "canary"
        ),
    ],
    ids=["missing", "not-a-repository", "half-deleted"],
)
def test_an_unhealthy_path_is_refused_without_creating_a_workspace(
    tmp_path: Path, make_unhealthy: Callable[[Path], Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, head = materialized(tmp_path, b"hello\n")
    monkeypatch.setattr(
        "traust_core.v1.providers.local.tempfile.mkdtemp",
        lambda *args, **kwargs: pytest.fail("a refused origin creates no workspace"),
    )
    with pytest.raises(NotFoundError, match="is not a healthy git repository"):
        provider().checkout(request(make_unhealthy(tmp_path), head))


def test_a_commit_the_local_repository_does_not_hold_raises_without_a_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _ = materialized(tmp_path, b"hello\n")
    monkeypatch.setattr(
        "traust_core.v1.providers.local.tempfile.mkdtemp",
        lambda *args, **kwargs: pytest.fail("a refused commit creates no workspace"),
    )
    with pytest.raises(NotFoundError, match="is not in"):
        provider().checkout(request(repo, GitSha.parse("e" * 40)))


def test_an_https_origin_is_not_a_local_origin(tmp_path: Path) -> None:
    _, head = materialized(tmp_path, b"hello\n")
    with pytest.raises(ValidationError, match="checks out a local repository"):
        provider().checkout(CheckoutRequest(repo=HTTPS, ref=head))


def test_releasing_a_workspace_from_another_origin_is_refused() -> None:
    workspace = Workspace(repo=HTTPS, sha=HEAD, path=Path("/nowhere"), provider="git-mirror")
    with pytest.raises(ValidationError, match="not a local origin"):
        provider().release(workspace)


def test_a_failed_worktree_add_leaves_no_workspace_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, head = materialized(tmp_path, b"hello\n")

    class WorktreeRefused:
        """The real runner, minus `worktree add`: git itself refused to add one."""

        def __init__(self) -> None:
            self._inner = ProcessRunner(("git",))

        def run(self, argv: list[str], **kwargs: Any) -> Any:
            if "worktree" in argv and "add" in argv:
                raise ProcessError(
                    ProcessResult(tuple(argv), 128, b"", b"fatal: cannot add worktree", 0.0)
                )
            return self._inner.run(argv, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    created: list[Path] = []
    real_mkdtemp = tempfile.mkdtemp
    monkeypatch.setattr(
        "traust_core.v1.providers.local.tempfile.mkdtemp",
        lambda *args, **kwargs: (
            created.append(Path(real_mkdtemp(*args, **kwargs))) or str(created[-1])
        ),
    )
    with pytest.raises(ProcessError, match="exited 128"):
        LocalCheckout(WorktreeRefused(), FixedClock(AT)).checkout(request(repo, head))
    assert created and not created[0].exists()


def test_check_names_git_when_the_runner_does_not_allow_it() -> None:
    readiness = LocalCheckout(ProcessRunner(("nothing",)), FixedClock(AT)).check()
    assert not readiness.ready
