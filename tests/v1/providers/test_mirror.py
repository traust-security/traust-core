"""MirrorCheckout: a commit's tree from a per-repository bare mirror — delta fetches on a moved
head, a worktree per order removed on release, and the forge token only in git's configuration
environment, never argv, a log line or a result."""

from __future__ import annotations

import logging
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import commit_all, git
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.checkout import GitCheckout, NumstatRow
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest

AT = datetime(2026, 10, 30, tzinfo=UTC)
REPO = "https://github.com/o/r"
URL = HttpsRepoUrl.parse(REPO, ("github.com",))


class Forge:
    """A local bare repository standing in for the forge at REPO, with a working clone."""

    def __init__(self, root: Path) -> None:
        self.bare = root / "forge" / "o" / "r.git"
        self.bare.mkdir(parents=True)
        git(self.bare, "init", "--bare", "-q")
        self.work = root / "work"
        self.work.mkdir()
        git(self.work, "init", "-q")

    def commit(self, name: str, content: bytes) -> GitSha:
        (self.work / name).write_bytes(content)
        sha = GitSha.parse(commit_all(self.work, name))
        git(self.work, "push", "-q", str(self.bare), "HEAD:refs/heads/main")
        return sha


class NoHttp:
    """ForgeApi's client is never used: the mirror only reads its token-header policy."""


class SpyRunner:
    """Records every argv and environment handed to the real runner."""

    def __init__(self, inner: ProcessRunner) -> None:
        self._inner = inner
        self.argv: list[tuple[str, ...]] = []
        self.envs: list[dict[str, str]] = []

    def run(self, argv: list[str], **kwargs: Any) -> Any:
        self.argv.append(tuple(argv))
        self.envs.append(dict(kwargs.get("env") or {}))
        return self._inner.run(argv, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def cache_for(tmp_path: Path, forge: Forge) -> Path:
    """The provider's cache root, its mirror pre-seeded so fetches reach the local forge: git's
    `url.insteadOf` rewrites the https URL (only a test configures it)."""
    cache = tmp_path / "cache"
    mirror(cache).mkdir(parents=True)
    git(mirror(cache), "init", "--bare", "-q")
    git(mirror(cache), "config", f"url.{forge.bare}.insteadOf", REPO)
    return cache


def mirror(cache: Path) -> Path:
    return cache / "github.com" / "o" / "r.git"


def provider(
    cache: Path,
    tokens: dict[str, str] | None = None,
    runner: ProcessRunner | SpyRunner | None = None,
) -> MirrorCheckout:
    return MirrorCheckout(
        runner or ProcessRunner(("git",)),
        FixedClock(AT),
        cache,
        ForgeApi(NoHttp(), {"github.com": "github"}, tokens or {}),
    )


def evictor(cache: Path) -> MirrorCheckout:
    return MirrorCheckout(ProcessRunner(("git",)), SystemClock(), cache, ForgeApi(NoHttp(), {}, {}))


def leftovers() -> set[str]:
    return {p.name for p in Path(tempfile.gettempdir()).glob("checkout-*")}


def object_bytes(path: Path) -> int:
    return sum(f.stat().st_size for f in (path / "objects").rglob("*") if f.is_file())


def test_a_whole_tree_checkout_is_the_commits_worktree_and_release_removes_it(
    tmp_path: Path,
) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    p = provider(cache_for(tmp_path, forge))
    result = p.checkout(CheckoutRequest(repo=REPO, ref=head))
    workspace = result.data
    assert (workspace.path / "a.txt").read_bytes() == b"hello\n"
    assert (workspace.provider, workspace.sha) == ("git-mirror", head)
    assert result.acquisition.source == REPO
    p.release(workspace)
    assert not workspace.path.exists()


def test_a_writable_workspace_can_be_dirtied_and_is_still_released(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    workspace = provider(cache).checkout(CheckoutRequest(repo=REPO, ref=head, writable=True)).data
    (workspace.path / "fix.txt").write_text("a fleet fix\n")
    provider(cache).release(workspace)
    assert not workspace.path.exists()
    assert "checkout-" not in git(mirror(cache), "worktree", "list", "--porcelain")


def test_the_workspace_is_released_when_the_consumer_fails(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=head)).data
    with pytest.raises(RuntimeError, match="the consumer failed"):
        try:
            raise RuntimeError("the consumer failed")
        finally:
            p.release(workspace)
    assert not workspace.path.exists()


def test_a_commit_the_forge_does_not_hold_raises_and_leaves_no_workspace(
    tmp_path: Path,
) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    before = leftovers()
    with pytest.raises(NotFoundError, match="is not in"):
        provider(cache).checkout(CheckoutRequest(repo=REPO, ref=GitSha.parse("e" * 40)))
    assert leftovers() == before


def test_history_since_an_anchor_is_reachable_from_the_workspace(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    anchor = forge.commit("a.txt", b"one\n")
    head = forge.commit("b.txt", b"two\n")
    cache = cache_for(tmp_path, forge)
    workspace = provider(cache).checkout(CheckoutRequest(repo=REPO, ref=head, history=anchor)).data
    reader = GitCheckout(ProcessRunner(("git",)))
    assert reader.numstat(workspace.path, str(anchor)) == [NumstatRow("b.txt", 1, 0)]
    provider(cache).release(workspace)


def test_a_second_checkout_of_a_moved_head_fetches_only_the_delta(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("big.bin", os.urandom(200_000))
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.checkout(CheckoutRequest(repo=REPO, ref=head))
    seeded = object_bytes(mirror(cache))
    moved = forge.commit("tiny.txt", b"a small change\n")
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=moved)).data
    assert (workspace.path / "tiny.txt").read_bytes() == b"a small change\n"
    assert (workspace.path / "big.bin").stat().st_size == 200_000
    assert seeded > 100_000
    assert object_bytes(mirror(cache)) - seeded < 8_000
    p.release(workspace)


def test_the_forge_token_rides_gits_config_environment_never_argv_logs_or_results(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    token = "not-a-real-token"
    spy = SpyRunner(ProcessRunner(("git",)))
    p = provider(cache, tokens={"github.com": token}, runner=spy)
    result = p.checkout(CheckoutRequest(repo=REPO, ref=head))
    p.release(result.data)
    assert all(token not in arg for argv in spy.argv for arg in argv)
    [fetch_env] = [env for env in spy.envs if "GIT_CONFIG_COUNT" in env]
    assert fetch_env["GIT_CONFIG_KEY_0"] == f"http.{REPO}.extraheader"
    assert token in fetch_env["GIT_CONFIG_VALUE_0"]
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.mirror"):
        provider(cache).checkout(CheckoutRequest(repo=REPO, ref=head))
    assert token not in caplog.text
    assert token not in result.acquisition.model_dump_json()


def test_an_idle_mirror_is_evicted(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    idle = time.time() - 40 * 86400
    os.utime(mirror(cache) / "traust-last-checkout", (idle, idle))
    assert [str(repo) for repo in evictor(cache).evict(30)] == [REPO]
    assert not mirror(cache).exists()


def test_a_mirror_checked_out_today_is_kept(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=head)).data
    p.release(workspace)
    assert evictor(cache).evict(30) == []
    assert mirror(cache).is_dir()


def test_a_mirror_never_checked_out_is_evicted_by_its_directory_age(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    cache = cache_for(tmp_path, forge)
    idle = time.time() - 40 * 86400
    os.utime(mirror(cache), (idle, idle))
    assert [str(repo) for repo in evictor(cache).evict(30)] == [REPO]
    assert not mirror(cache).exists()


def test_refresh_fetches_a_moved_head_without_a_worktree(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"one\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    moved = forge.commit("b.txt", b"two\n")
    p.refresh(URL, moved)
    assert "checkout-" not in git(mirror(cache), "worktree", "list", "--porcelain")
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=moved)).data
    assert (workspace.path / "b.txt").read_bytes() == b"two\n"
    p.release(workspace)


def test_refresh_of_a_head_the_forge_does_not_hold_raises(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"one\n")
    cache = cache_for(tmp_path, forge)
    with pytest.raises(NotFoundError, match="after refresh"):
        provider(cache).refresh(URL, GitSha.parse("e" * 40))


def test_check_names_git_when_the_runner_does_not_allow_it() -> None:
    readiness = MirrorCheckout(
        ProcessRunner(("nothing",)), FixedClock(AT), Path("/nowhere"), ForgeApi(NoHttp(), {}, {})
    ).check()
    assert not readiness.ready
