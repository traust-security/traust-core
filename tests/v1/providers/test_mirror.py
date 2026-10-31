"""MirrorCheckout: a commit's tree from a per-repository bare mirror — delta fetches on a moved
head, a worktree per order removed on release, and the forge token only in git's configuration
environment, never argv, a log line or a result."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from tests.v1.conftest import commit_all, git
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.checkout import GitCheckout, NumstatRow
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.process import ProcessError, ProcessResult, ProcessRunner
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

    def review_commit(self, ref: str) -> GitSha:
        git(self.work, "checkout", "--orphan", "review")
        git(self.work, "rm", "-rf", ".")
        (self.work / "review.txt").write_text("only on the review ref\n")
        sha = GitSha.parse(commit_all(self.work, "review"))
        git(self.work, "push", "-q", str(self.bare), f"HEAD:{ref}")
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


class LocalForge(ProcessRunner):
    """The real runner, minus GIT_ALLOW_PROTOCOL on the fetch: git's file transport carries the
    local forge that stands in for the https repository (only a test configures insteadOf)."""

    def run(self, argv: Sequence[str], **kwargs: Any) -> Any:
        env = kwargs.get("env")
        if ("fetch" in argv or "ls-remote" in argv) and env:
            kwargs["env"] = {k: v for k, v in env.items() if k != "GIT_ALLOW_PROTOCOL"}
        return super().run(argv, **kwargs)


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
        runner or LocalForge(("git",)),
        FixedClock(AT),
        cache,
        ForgeApi(NoHttp(), {"github.com": "github"}, tokens or {}),
    )


def evictor(cache: Path) -> MirrorCheckout:
    return MirrorCheckout(ProcessRunner(("git",)), SystemClock(), cache, ForgeApi(NoHttp(), {}, {}))


@pytest.fixture
def worktrees(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The mirror's worktrees under the test's own dir: a leftovers check must not see other
    workers' checkouts (several suites now check out through the mirror in parallel)."""
    root = tmp_path / "checkouts"
    root.mkdir()
    real = tempfile.mkdtemp
    monkeypatch.setattr(tempfile, "mkdtemp", lambda prefix="": real(prefix=prefix, dir=root))
    return root


def leftovers(root: Path) -> set[str]:
    return {p.name for p in root.glob("checkout-*")}


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
    tmp_path: Path, worktrees: Path
) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    before = leftovers(worktrees)
    with pytest.raises(NotFoundError, match="is not in"):
        provider(cache).checkout(CheckoutRequest(repo=REPO, ref=GitSha.parse("e" * 40)))
    assert leftovers(worktrees) == before


@pytest.mark.parametrize("ref", ["refs/pull/7/head", "refs/merge-requests/7/head"])
@pytest.mark.parametrize("operation", ["checkout", "refresh"])
def test_a_commit_retained_only_by_a_review_ref_is_acquired(
    tmp_path: Path, worktrees: Path, ref: str, operation: str
) -> None:
    forge = Forge(tmp_path)
    forge.commit("main.txt", b"main\n")
    head = forge.review_commit(ref)
    assert git(forge.bare, "for-each-ref", "--contains", str(head), "--format=%(refname)") == ref
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    if operation == "refresh":
        p.refresh(URL, head)
        assert leftovers(worktrees) == set()
        assert git(mirror(cache), "show", f"{head}:review.txt") == "only on the review ref"
    else:
        workspace = p.checkout(CheckoutRequest(repo=REPO, ref=head)).data
        try:
            assert (workspace.path / "review.txt").read_text() == "only on the review ref\n"
            assert not (workspace.path / "main.txt").exists()
        finally:
            p.release(workspace)
    assert git(mirror(cache), "for-each-ref", "--format=%(refname)") == "refs/heads/main"


def test_an_unadvertised_commit_is_not_accepted_from_a_direct_sha_fetch(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("main.txt", b"main\n")
    hidden = forge.review_commit("refs/fork-only/7/head")
    cache = cache_for(tmp_path, forge)
    with pytest.raises(NotFoundError, match="is not in"):
        provider(cache).checkout(CheckoutRequest(repo=REPO, ref=hidden))


def test_a_deleted_review_ref_cannot_reauthorize_its_cached_commit(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("main.txt", b"main\n")
    ref = "refs/pull/7/head"
    head = forge.review_commit(ref)
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    git(forge.work, "push", "-q", str(forge.bare), f":{ref}")
    with pytest.raises(NotFoundError, match="is not in"):
        p.checkout(CheckoutRequest(repo=REPO, ref=head))


@pytest.mark.parametrize("operation", ["checkout", "refresh"])
def test_a_transport_failure_fetching_a_review_commit_is_not_reported_as_missing(
    tmp_path: Path, worktrees: Path, operation: str
) -> None:
    forge = Forge(tmp_path)
    forge.commit("main.txt", b"main\n")
    head = forge.review_commit("refs/pull/7/head")
    cache = cache_for(tmp_path, forge)

    class VanishedForge(LocalForge):
        def run(self, argv: Sequence[str], **kwargs: Any) -> Any:
            if "fetch" in argv and argv[-1] == "refs/pull/7/head":
                shutil.rmtree(forge.bare)
            return super().run(argv, **kwargs)

    p = provider(cache, runner=VanishedForge(("git",)))
    with pytest.raises(ProcessError):
        if operation == "refresh":
            p.refresh(URL, head)
        else:
            p.checkout(CheckoutRequest(repo=REPO, ref=head))
    assert leftovers(worktrees) == set()


def test_a_failed_worktree_add_leaves_no_workspace_behind(tmp_path: Path, worktrees: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)

    class WorktreeRefused:
        """The real runner, minus `worktree add`: git itself refused to add one."""

        def __init__(self) -> None:
            self._inner = LocalForge(("git",))

        def run(self, argv: list[str], **kwargs: Any) -> Any:
            if "worktree" in argv and "add" in argv:
                raise ProcessError(
                    ProcessResult(tuple(argv), 128, b"", b"fatal: cannot add worktree", 0.0)
                )
            return self._inner.run(argv, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    before = leftovers(worktrees)
    with pytest.raises(ProcessError, match="exited 128"):
        provider(cache, runner=WorktreeRefused()).checkout(CheckoutRequest(repo=REPO, ref=head))
    assert leftovers(worktrees) == before


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


def test_a_negative_idle_window_is_refused_not_a_full_clear(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    with pytest.raises(ValidationError, match=r"non-negative"):
        evictor(cache).evict(-1)
    assert mirror(cache).is_dir()


def test_a_failed_touch_strands_no_worktree(
    tmp_path: Path, worktrees: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    before = leftovers(worktrees)

    def exploding(self: MirrorCheckout, path: Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(MirrorCheckout, "_touch", exploding)
    with pytest.raises(OSError, match="disk full"):
        provider(cache).checkout(CheckoutRequest(repo=REPO, ref=head))
    assert leftovers(worktrees) == before


def test_the_forge_token_rides_gits_config_environment_never_argv_logs_or_results(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    token = "not-a-real-token"
    spy = SpyRunner(LocalForge(("git",)))
    p = provider(cache, tokens={"github.com": token}, runner=spy)
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.mirror"):
        result = p.checkout(CheckoutRequest(repo=REPO, ref=head))
        p.release(result.data)
    [fetch_env] = [env for env in spy.envs if "GIT_CONFIG_COUNT" in env]
    assert fetch_env["GIT_CONFIG_KEY_0"] == f"http.{REPO}.extraheader"
    assert fetch_env["GIT_ALLOW_PROTOCOL"] == "https"
    credential = fetch_env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: ")
    for secret in (token, credential):
        assert all(secret not in arg for argv in spy.argv for arg in argv)
        assert secret not in caplog.text
        assert secret not in result.acquisition.model_dump_json()


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


def test_a_mirror_under_a_live_checkout_survives_evict_until_released(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=head)).data
    idle = time.time() - 40 * 86400
    os.utime(mirror(cache) / "traust-last-checkout", (idle, idle))
    assert evictor(cache).evict(30) == []
    assert mirror(cache).is_dir()
    p.release(workspace)
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


def test_refresh_fetches_a_moved_head_without_a_worktree(tmp_path: Path, worktrees: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"one\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    moved = forge.commit("b.txt", b"two\n")
    p.refresh(URL, moved)
    assert list(worktrees.iterdir()) == []
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=moved)).data
    assert (workspace.path / "b.txt").read_bytes() == b"two\n"
    p.release(workspace)


@pytest.mark.parametrize(
    ("operation", "stage"),
    [("checkout", "fetch"), ("checkout", "worktree"), ("refresh", "fetch")],
)
def test_eviction_cannot_remove_a_mirror_during_acquisition(
    tmp_path: Path, worktrees: Path, operation: str, stage: str
) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    last_use = mirror(cache) / "traust-last-checkout"
    last_use.touch()
    idle = time.time() - 40 * 86400
    os.utime(last_use, (idle, idle))
    entered, resume = Event(), Event()

    class PausedForge(LocalForge):
        def run(self, argv: Sequence[str], **kwargs: Any) -> Any:
            if stage in argv and (stage == "fetch" or "add" in argv):
                entered.set()
                if not resume.wait(timeout=10):
                    raise TimeoutError("the acquisition was not resumed")
            return super().run(argv, **kwargs)

    p = provider(cache, runner=PausedForge(("git",)))
    with ThreadPoolExecutor(max_workers=1) as pool:
        acquisition = (
            pool.submit(p.refresh, URL, head)
            if operation == "refresh"
            else pool.submit(p.checkout, CheckoutRequest(repo=REPO, ref=head))
        )
        try:
            assert entered.wait(timeout=10)
            assert evictor(cache).evict(0) == []
            assert mirror(cache).is_dir()
        finally:
            resume.set()
        result = acquisition.result(timeout=10)

    if operation == "checkout":
        assert result is not None
        workspace = result.data
        try:
            assert (workspace.path / "a.txt").read_bytes() == b"hello\n"
            assert evictor(cache).evict(0) == []
        finally:
            p.release(workspace)
    else:
        assert git(mirror(cache), "show", f"{head}:a.txt") == "hello"
        assert last_use.stat().st_mtime == idle
        assert leftovers(worktrees) == set()
    assert [str(repo) for repo in evictor(cache).evict(0)] == [REPO]
    assert not mirror(cache).exists()


def test_a_mirror_evicted_after_another_eviction_scans_is_ignored(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    idle = time.time() - 40 * 86400
    os.utime(mirror(cache), (idle, idle))
    scanned, resume = Event(), Event()

    class PausedEvictor(MirrorCheckout):
        @contextmanager
        def _locked(self, path: Path, *, blocking: bool = True) -> Iterator[bool]:
            scanned.set()
            if not resume.wait(timeout=10):
                raise TimeoutError("the eviction was not resumed")
            with super()._locked(path, blocking=blocking) as acquired:
                yield acquired

    p = PausedEvictor(ProcessRunner(("git",)), SystemClock(), cache, ForgeApi(NoHttp(), {}, {}))
    with ThreadPoolExecutor(max_workers=1) as pool:
        eviction = pool.submit(p.evict, 30)
        try:
            assert scanned.wait(timeout=10)
            assert [str(repo) for repo in evictor(cache).evict(30)] == [REPO]
        finally:
            resume.set()
        assert eviction.result(timeout=10) == []
    assert not mirror(cache).exists()


def test_a_half_deleted_mirror_is_reinitialized_and_fetches_again(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"hello\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    shutil.rmtree(mirror(cache) / "refs")
    shutil.rmtree(mirror(cache) / "objects")
    workspace = p.checkout(CheckoutRequest(repo=REPO, ref=head)).data
    assert (workspace.path / "a.txt").read_bytes() == b"hello\n"
    p.release(workspace)


def test_refresh_of_a_head_the_forge_does_not_hold_raises(tmp_path: Path, worktrees: Path) -> None:
    forge = Forge(tmp_path)
    forge.commit("a.txt", b"one\n")
    cache = cache_for(tmp_path, forge)
    with pytest.raises(NotFoundError, match="after refresh"):
        provider(cache).refresh(URL, GitSha.parse("e" * 40))
    assert leftovers(worktrees) == set()


def test_refresh_does_not_extend_the_idle_clock(tmp_path: Path) -> None:
    forge = Forge(tmp_path)
    head = forge.commit("a.txt", b"one\n")
    cache = cache_for(tmp_path, forge)
    p = provider(cache)
    p.release(p.checkout(CheckoutRequest(repo=REPO, ref=head)).data)
    last_use = mirror(cache) / "traust-last-checkout"
    idle = time.time() - 40 * 86400
    os.utime(last_use, (idle, idle))
    moved = forge.commit("b.txt", b"two\n")
    p.refresh(URL, moved)
    assert last_use.stat().st_mtime == idle


def test_check_names_git_when_the_runner_does_not_allow_it() -> None:
    readiness = MirrorCheckout(
        ProcessRunner(("nothing",)), FixedClock(AT), Path("/nowhere"), ForgeApi(NoHttp(), {}, {})
    ).check()
    assert not readiness.ready
