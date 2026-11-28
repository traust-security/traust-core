"""Tests for shared (repo, commit) read-only checkouts and refcounting."""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.v1.conftest import commit_all, git
from tests.v1.providers.test_mirror import Forge, LocalForge, NoHttp, SpyRunner
from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, LocalRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.local import LocalCheckout
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest

AT = datetime(2026, 11, 22, tzinfo=UTC)
URL = HttpsRepoUrl.parse("https://github.com/o/r", ("github.com",))


def test_mirror_shared_checkout_reuses_worktree_and_refcounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache { public void get() {} }\n")
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))

    first = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    adds_after_first = sum(1 for a in spy.argv if "worktree" in a and "add" in a)
    second = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    adds_after_second = sum(1 for a in spy.argv if "worktree" in a and "add" in a)

    assert first.path == second.path
    assert first.shared and second.shared
    assert adds_after_first == 1
    assert adds_after_second == 1  # zero extra git worktree add

    # Releasing one holder keeps the shared worktree alive and blocks eviction.
    mirror.release(first)
    assert second.path.is_dir()
    old_ts = (AT - timedelta(days=2)).timestamp()
    last_use = tmp_path / "mirrors" / "github.com" / "o" / "r.git" / "traust-last-checkout"
    os.utime(last_use, (old_ts, old_ts))
    assert mirror.evict(1) == []

    # Releasing the last holder removes the shared worktree and unblocks eviction.
    mirror.release(second)
    assert not second.path.exists()
    assert mirror.evict(1) == [URL]


def test_shared_checkout_refuses_writable(tmp_path: Path) -> None:
    mirror = MirrorCheckout(
        ProcessRunner(allowed=("git",)),
        FixedClock(AT),
        tmp_path / "mirrors",
        ForgeApi(NoHttp(), {}),  # type: ignore[arg-type]
    )
    with pytest.raises(ValidationError, match="read-only"):
        mirror.checkout(
            CheckoutRequest(repo=URL, ref=GitSha.parse("a" * 40), shared=True, writable=True)
        )


def test_local_shared_checkout_reuses_worktree_and_refcounts(tmp_path: Path) -> None:
    repo = tmp_path / "monorepo-fixture"
    repo.mkdir()
    git(repo, "init", "-q")
    ts_file = repo / "packages" / "cache-lib" / "src" / "cache.ts"
    ts_file.parent.mkdir(parents=True)
    ts_file.write_text(
        "export class ItemCache {}\nexport function lookupById(id: string) { return id; }\n",
        encoding="utf-8",
    )
    sha = GitSha.parse(commit_all(repo, "add ts cache"))
    local_url = LocalRepoUrl.parse(repo.as_uri())

    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT))
    ws1 = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    ws2 = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    assert ws1.path == ws2.path

    local.release(ws1)
    assert ws2.path.is_dir()
    local.release(ws2)
    assert not ws2.path.exists()


def test_mirror_shared_checkout_refreshes_tags_pushed_after_initial_mirror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache {}\n")
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))

    first = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    assert git(first.path, "tag", "--points-at", str(sha)) == ""

    # Push a new release tag to the remote after the mirror already holds `sha`.
    git(forge.bare, "update-ref", "refs/tags/v7.1.0", str(sha))

    second = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    assert second.path == first.path
    assert "v7.1.0" in git(second.path, "tag", "--points-at", str(sha)).splitlines()

    mirror.release(first)
    mirror.release(second)


def test_local_shared_checkout_is_thread_safe_across_concurrent_acquire_and_release(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "concurrent-monorepo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "README.md").write_text("concurrent\n", encoding="utf-8")
    sha = GitSha.parse(commit_all(repo, "init"))
    local_url = LocalRepoUrl.parse(repo.as_uri())
    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT))
    errors: list[Exception] = []

    def worker() -> None:
        try:
            for _ in range(5):
                ws = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
                assert ws.path.is_dir()
                assert (ws.path / "README.md").is_file()
                local.release(ws)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_mirror_release_refuses_unowned_directory_and_preserves_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers.sources import Workspace

    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache {}\n")
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))
    real_ws = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data

    unrelated = tmp_path / "important-user-dir"
    unrelated.mkdir()
    sentinel = unrelated / "keep.txt"
    sentinel.write_text("do not delete\n", encoding="utf-8")

    for shared in (True, False):
        forged = Workspace(repo=URL, sha=sha, path=unrelated, provider=mirror.name, shared=shared)
        with pytest.raises(ValidationError, match="refusing to remove"):
            mirror.release(forged)
        assert unrelated.is_dir()
        assert sentinel.read_text(encoding="utf-8") == "do not delete\n"

    # Real shared worktree still releases cleanly afterward.
    assert real_ws.path.is_dir()
    mirror.release(real_ws)
    assert not real_ws.path.exists()


def test_shared_release_without_shared_flag_preserves_other_holder_on_mirror_and_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.providers.sources import Workspace

    # 1. MirrorCheckout: two holders; releasing first with shared=False decrements refcount
    #    rather than deleting the live shared worktree out from under holder 2.
    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache {}\n")
    other_sha = GitSha.parse("b" * 40)
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))
    h1 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    h2 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    assert h1.path == h2.path

    # Mismatched SHA targeting a managed shared worktree is refused without deletion.
    with pytest.raises(ValidationError, match="refusing to remove"):
        mirror.release(
            Workspace(repo=URL, sha=other_sha, path=h1.path, provider=mirror.name, shared=False)
        )
    assert h2.path.is_dir()

    # Omitting shared=True still follows the ref-counted shared release path.
    mirror.release(Workspace(repo=URL, sha=sha, path=h1.path, provider=mirror.name, shared=False))
    assert h2.path.is_dir()
    mirror.release(h2)
    assert not h2.path.exists()

    # 2. LocalCheckout: same two-holder protection when shared=False is passed.
    repo = tmp_path / "local-two-holders"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "README.md").write_text("shared\n", encoding="utf-8")
    local_sha = GitSha.parse(commit_all(repo, "init"))
    local_url = LocalRepoUrl.parse(repo.as_uri())
    shared_dir = tmp_path / "local-shared"
    local_a = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), shared_dir)
    local_b = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), shared_dir)
    lh1 = local_a.checkout(CheckoutRequest(repo=local_url, ref=local_sha, shared=True)).data
    lh2 = local_b.checkout(CheckoutRequest(repo=local_url, ref=local_sha, shared=True)).data
    assert lh1.path == lh2.path

    # Cross-instance mismatched SHA targeting a managed shared worktree is refused.
    local_c = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), shared_dir)
    with pytest.raises(ValidationError, match="refusing to remove"):
        local_c.release(
            Workspace(
                repo=local_url, sha=other_sha, path=lh1.path, provider=local_c.name, shared=False
            )
        )
    assert lh2.path.is_dir()

    # Cross-instance release with shared=False still decrements the on-disk refcount.
    local_c.release(
        Workspace(repo=local_url, sha=local_sha, path=lh1.path, provider=local_c.name, shared=False)
    )
    assert lh2.path.is_dir()
    # Final release from another fresh instance removes the shared worktree.
    LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), shared_dir).release(lh2)
    assert not lh2.path.exists()

    # Cross-config-home protection: a second LocalCheckout with a different shared_dir cannot
    # remove a live shared worktree (even with shared=False), because git worktree lock metadata
    # classifies it independently of caller config.
    other_shared_dir = tmp_path / "other-config-home-shared"
    owner = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), shared_dir)
    foreign = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), other_shared_dir)
    ws_owned = owner.checkout(CheckoutRequest(repo=local_url, ref=local_sha, shared=True)).data
    for shared_flag in (False, True):
        with pytest.raises(ValidationError, match="refusing to remove"):
            foreign.release(
                Workspace(
                    repo=local_url,
                    sha=local_sha,
                    path=ws_owned.path,
                    provider=foreign.name,
                    shared=shared_flag,
                )
            )
        assert ws_owned.path.is_dir()
    owner.release(ws_owned)
    assert not ws_owned.path.exists()


def test_mirror_shared_checkout_throttles_tag_refresh_within_ttl_and_refreshes_after_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    (forge.work / "spring-beans").mkdir(parents=True, exist_ok=True)
    sha = forge.commit("spring-beans/Cache.java", b"public class Cache {}\n")
    git(forge.bare, "update-ref", "refs/tags/v7.1.0", str(sha))
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    clock = FixedClock(AT)
    spy = SpyRunner(LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL")))
    mirror = MirrorCheckout(spy, clock, tmp_path / "mirrors", ForgeApi(NoHttp(), {}))

    ws1 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    fetches_after_1 = sum(1 for a in spy.argv if "fetch" in a)

    # Consecutive sibling checkouts within the 60s TTL skip redundant remote tag fetches.
    clock._at = AT + timedelta(seconds=10)
    ws2 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    ws3 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    fetches_within_ttl = sum(1 for a in spy.argv if "fetch" in a)
    assert fetches_within_ttl == fetches_after_1

    # Explicit refresh_tags=True bypasses the TTL immediately to pick up a newly pushed tag.
    git(forge.bare, "update-ref", "refs/tags/v7.1.1", str(sha))
    ws_forced = mirror.checkout(
        CheckoutRequest(repo=URL, ref=sha, shared=True, refresh_tags=True)
    ).data
    fetches_after_forced = sum(1 for a in spy.argv if "fetch" in a)
    assert fetches_after_forced == fetches_within_ttl + 1
    assert "v7.1.1" in git(ws_forced.path, "tag", "--points-at", str(sha)).splitlines()

    # Once the TTL expires, new remote tags are also fetched automatically.
    git(forge.bare, "update-ref", "refs/tags/v7.1.2", str(sha))
    clock._at = AT + timedelta(seconds=75)
    ws4 = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    fetches_after_ttl = sum(1 for a in spy.argv if "fetch" in a)
    assert fetches_after_ttl == fetches_after_forced + 1
    assert "v7.1.2" in git(ws4.path, "tag", "--points-at", str(sha)).splitlines()

    for ws in (ws1, ws2, ws3, ws_forced, ws4):
        mirror.release(ws)


def test_mirror_checkout_handles_sha256_remote_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_core.v1.errors import NotFoundError
    from traust_core.v1.models.component_target import ComponentTargetRequest
    from traust_core.v1.models.values import GitSha
    from traust_core.v1.providers.checkout import GitCheckout
    from traust_core.v1.services.component_target import ComponentTargetResolver

    forge = Forge(tmp_path, object_format="sha256")
    sha = forge.commit("setup.cfg", b"[metadata]\nname = sha256-pkg\nversion = 2.0.0\n")
    assert len(str(sha)) == 64
    git(forge.bare, "update-ref", "refs/tags/v2.0.0", str(sha))
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))

    runner = LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL"))
    mirror = MirrorCheckout(runner, FixedClock(AT), tmp_path / "mirrors", ForgeApi(NoHttp(), {}))

    # Shared and non-shared remote checkouts both work against a SHA-256 remote.
    ws_shared = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    ws_solo = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=False)).data
    try:
        assert (ws_shared.path / "setup.cfg").is_file()
        assert (ws_solo.path / "setup.cfg").is_file()
        resolver = ComponentTargetResolver(GitCheckout(runner))
        resolved = resolver.resolve(
            ComponentTargetRequest(
                purl="pkg:pypi/sha256-pkg@2.0.0",
                repository=str(URL),
                commit=str(sha),
                module_path=".",
            ),
            ws_shared.path,
        )
        assert resolved.commit == str(sha)
        assert resolved.module_path == "."

        # Requesting a 40-hex SHA against the SHA-256 mirror fails cleanly with NotFoundError.
        with pytest.raises(NotFoundError):
            mirror.checkout(CheckoutRequest(repo=URL, ref=GitSha.parse("a" * 40), shared=False))
    finally:
        mirror.release(ws_shared)
        mirror.release(ws_solo)
    assert not ws_shared.path.exists()
    assert not ws_solo.path.exists()


class _MovingClock:
    """A clock a test advances: the tag-refresh TTL needs time to pass."""

    def __init__(self, at: datetime) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at


def _mirror_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forge: Forge, clock: object = None
) -> MirrorCheckout:
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{forge.bare}"]\n\tinsteadOf = {URL}\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    runner = LocalForge(allowed=("git",), keep_env=("PATH", "HOME", "GIT_CONFIG_GLOBAL"))
    return MirrorCheckout(
        runner,
        clock or FixedClock(AT),  # type: ignore[arg-type]
        tmp_path / "mirrors",
        ForgeApi(NoHttp(), {}),  # type: ignore[arg-type]
    )


def test_eviction_never_walks_into_a_live_shared_worktree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An audited repository may carry a bare-repo fixture: it is source, never a mirror.
    forge = Forge(tmp_path)
    (forge.work / "tests" / "data" / "x.git").mkdir(parents=True)
    (forge.work / "tests" / "data" / "x.git" / "objects").mkdir()
    (forge.work / "tests" / "data" / "x.git" / "objects" / ".keep").write_text("")
    sha = forge.commit("tests/data/x.git/HEAD", b"ref: refs/heads/main\n")
    mirror = _mirror_for(tmp_path, monkeypatch, forge)
    held = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    fixture = held.path / "tests" / "data" / "x.git"
    old = (AT - timedelta(days=40)).timestamp()
    os.utime(fixture, (old, old))
    assert mirror.evict(0) == []
    assert (fixture / "HEAD").is_file()
    assert not (fixture.parent / "x.git.lock").exists()
    mirror.release(held)


def test_a_torn_holder_count_keeps_the_shared_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    sha = forge.commit("a.txt", b"a\n")
    mirror = _mirror_for(tmp_path, monkeypatch, forge)
    first = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    second = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    [refs] = (tmp_path / "mirrors").rglob(f"{sha}.refs")
    refs.write_text("", encoding="utf-8")  # a write interrupted mid-way
    mirror.release(first)
    assert second.path.is_dir()  # another holder may still be reading it


def test_a_torn_holder_count_keeps_the_local_shared_tree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "a.txt").write_text("a\n")
    sha = GitSha.parse(commit_all(repo, "a"))
    local_url = LocalRepoUrl.parse(repo.as_uri())
    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), tmp_path / "shared")
    first = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    second = local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True)).data
    [refs] = (tmp_path / "shared").rglob(f"{sha}.refs")
    refs.write_text("", encoding="utf-8")
    local.release(first)
    assert second.path.is_dir()


def test_a_shared_tree_whose_first_count_fails_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = Forge(tmp_path)
    sha = forge.commit("a.txt", b"a\n")
    mirror = _mirror_for(tmp_path, monkeypatch, forge)
    blocked = tmp_path / "mirrors" / "github.com" / "o" / "r.shared" / f"{sha}.refs"
    blocked.mkdir(parents=True)  # the count can't be written
    with pytest.raises(OSError):
        mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True))
    assert not (blocked.parent / str(sha)).exists()
    listed = git(tmp_path / "mirrors" / "github.com" / "o" / "r.git", "worktree", "list")
    assert len(listed.splitlines()) == 1  # only the bare mirror: no orphan blocks eviction


def test_a_local_shared_tree_whose_first_count_fails_is_removed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "a.txt").write_text("a\n")
    sha = GitSha.parse(commit_all(repo, "a"))
    local_url = LocalRepoUrl.parse(repo.as_uri())
    local = LocalCheckout(ProcessRunner(allowed=("git",)), FixedClock(AT), tmp_path / "shared")
    worktree, refs = local._shared_paths(repo, str(sha))
    refs.mkdir(parents=True)
    with pytest.raises(OSError):
        local.checkout(CheckoutRequest(repo=local_url, ref=sha, shared=True))
    assert not worktree.exists()
    assert len(git(repo, "worktree", "list").splitlines()) == 1


def test_stale_tags_fail_the_checkout_closed_and_the_next_one_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # tags are mutable release evidence: past their TTL, cached ones are not current, so an
    # unreachable forge is a typed transient failure, never a silent stale success
    forge = Forge(tmp_path)
    sha = forge.commit("a.txt", b"a\n")
    clock = _MovingClock(AT)
    mirror = _mirror_for(tmp_path, monkeypatch, forge, clock)
    first = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    gone = forge.bare.with_name("gone.git")
    forge.bare.rename(gone)  # the forge is down
    clock.at = AT + timedelta(minutes=5)  # past the tag-refresh TTL
    with pytest.raises(ServiceError, match="release tags") as failed:
        mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True))
    assert failed.value.operation == "mirror.refresh_tags"
    gone.rename(forge.bare)  # back: the failure stamped nothing, so this one refreshes
    git(forge.bare, "update-ref", "refs/tags/v2", str(sha))
    second = mirror.checkout(CheckoutRequest(repo=URL, ref=sha, shared=True)).data
    assert "v2" in git(second.path, "tag", "--points-at", str(sha)).splitlines()
    mirror.release(first)
    mirror.release(second)
