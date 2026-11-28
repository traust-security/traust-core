"""A commit's tree from a per-repository bare git mirror: only head moves cross the wire after
the first fetch; the host's forge token rides git's configuration environment, never argv."""

from __future__ import annotations

import fcntl
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from pydantic import TypeAdapter

from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers import shared_tree
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.checkout import HARDENED, GitCheckout
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.process import ProcessError, ProcessRunner
from traust_core.v1.providers.sources import CheckoutProviderName, CheckoutRequest, Workspace

log = logging.getLogger(__name__)

FETCH_TIMEOUT_SECONDS = 600.0
# https only: an insteadOf rewrite can never hand the fetch an ext:: transport helper.
_FETCH_ENV = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
_LAST_USE = "traust-last-checkout"
TAG_REFRESH_TTL_SECONDS = 60.0
_TAGS_REFRESHED = "traust-tags-refreshed"
_REPO_URL = TypeAdapter(HttpsRepoUrl)
# shared worktrees sit beside their mirror (`<repo>.shared/`) and LocalCheckout's under
# `_local-shared/`: checked-out source, never mirrors, so eviction never walks into them
_SHARED_SUFFIX = ".shared"
LOCAL_SHARED_DIR = "_local-shared"


class MirrorCheckout:
    """`RepoCheckoutService`'s mirror seam: whole trees, any history, writable on request."""

    name = CheckoutProviderName.MIRROR

    def __init__(self, runner: ProcessRunner, clock: Clock, root: Path, api: ForgeApi) -> None:
        self._runner, self._clock, self._root, self._api = runner, clock, root, api
        self._reader = GitCheckout(runner)

    def check(self) -> Readiness:
        return Readiness(ready=self._runner.allows("git"), detail="git is not allowed here")

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        if request.shared and request.writable:
            raise ValidationError("a shared checkout must be read-only")
        sha = str(request.ref)
        mirror = self._mirror(request.repo)
        with self._locked(mirror):
            if request.shared:
                worktree = self._acquire_shared(
                    mirror, request.repo, sha, refresh_tags=request.refresh_tags
                )
            else:
                if not self._fetch(mirror, request.repo, sha):
                    raise NotFoundError(f"commit {sha} is not in {request.repo}")
                self._touch(mirror)
                # Resolve macOS's symlinked temp dir before consumers relativize paths against it.
                worktree = Path(tempfile.mkdtemp(prefix="checkout-")).resolve()
                try:
                    self._git(mirror, "worktree", "add", "--quiet", "--detach", str(worktree), sha)
                except BaseException:
                    shutil.rmtree(worktree, ignore_errors=True)
                    raise
        return Result(
            Workspace(
                repo=request.repo,
                sha=request.ref,
                path=worktree,
                provider=self.name,
                shared=request.shared,
            ),
            Acquisition(
                provider=self.name, acquired_at=self._clock.now(), source=str(request.repo)
            ),
        )

    def _shared_paths(self, mirror: Path, sha: str) -> tuple[Path, Path]:
        base = mirror.parent / f"{mirror.stem}{_SHARED_SUFFIX}"
        return (base / sha).resolve(), base / f"{sha}.refs"

    def _acquire_shared(
        self, mirror: Path, repo: HttpsRepoUrl, sha: str, *, refresh_tags: bool = False
    ) -> Path:
        worktree, refs_file = self._shared_paths(mirror, sha)
        if (
            worktree.is_dir()
            and self._reader.is_checkout(worktree)
            and self._reader.head(worktree) == sha
        ):
            self._maybe_fetch_tags(mirror, repo, force=refresh_tags)
            self._touch(mirror)
            shared_tree.acquire(refs_file)
            return worktree
        if _healthy(mirror) and self._reachable(mirror, sha):
            self._maybe_fetch_tags(mirror, repo, force=refresh_tags)
        elif not self._fetch(mirror, repo, sha):
            raise NotFoundError(f"commit {sha} is not in {repo}")
        self._touch(mirror)
        worktree.parent.mkdir(parents=True, exist_ok=True)
        if worktree.exists():
            self._git(mirror, "worktree", "remove", "--force", str(worktree), check=False)
            shutil.rmtree(worktree, ignore_errors=True)
        try:
            self._git(mirror, "worktree", "add", "--quiet", "--detach", str(worktree), sha)
            # inside the cleanup: a tree whose first count never landed has no holder to
            # release it, and a registered worktree blocks the mirror's eviction
            shared_tree.write_holders(refs_file, 1)
        except BaseException:
            self._git(mirror, "worktree", "remove", "--force", str(worktree), check=False)
            shutil.rmtree(worktree, ignore_errors=True)
            refs_file.unlink(missing_ok=True)
            self._git(mirror, "worktree", "prune", check=False)
            raise
        return worktree

    def release(self, workspace: Workspace) -> None:
        mirror = self._mirror(workspace.repo)
        with self._locked(mirror):
            if not _healthy(mirror):
                raise ValidationError(
                    f"workspace {workspace.path} is not a worktree of {workspace.repo}; "
                    "refusing to remove"
                )
            target = workspace.path.resolve()
            owned = self._worktrees(mirror)
            worktree, refs_file = self._shared_paths(mirror, str(workspace.sha))
            shared_root = worktree.parent
            is_managed_shared = target == worktree or target.is_relative_to(shared_root)
            if workspace.shared or is_managed_shared:
                if target != worktree or target not in owned:
                    raise ValidationError(
                        f"workspace {workspace.path} is not the shared worktree for "
                        f"{workspace.repo}@{workspace.sha}; refusing to remove"
                    )
                if not shared_tree.release(refs_file):
                    return
            elif target not in owned:
                raise ValidationError(
                    f"workspace {workspace.path} is not a worktree of {workspace.repo}; "
                    "refusing to remove"
                )
            self._git(
                mirror,
                "worktree",
                "remove",
                "--force",
                str(target),
                check=False,
            )
            shutil.rmtree(target, ignore_errors=True)
            self._git(mirror, "worktree", "prune", check=False)

    def _worktrees(self, mirror: Path) -> set[Path]:
        """Registered worktrees owned by `mirror` (excluding the bare mirror itself)."""
        listed = self._runner.run(
            ["git", "-C", str(mirror), *HARDENED, "worktree", "list", "--porcelain"],
            check=False,
        ).stdout.decode(errors="replace")
        worktrees = [
            line.removeprefix("worktree ")
            for line in listed.splitlines()
            if line.startswith("worktree ")
        ]
        mirror_resolved = mirror.resolve()
        return {Path(w).resolve() for w in worktrees if Path(w).resolve() != mirror_resolved}

    def refresh(self, repo: HttpsRepoUrl, head: GitSha) -> None:
        """Fetch the repo's mirror so it holds `head` (seeding it when absent); a commit the
        forge no longer serves raises."""
        mirror = self._mirror(repo)
        with self._locked(mirror):
            if not self._fetch(mirror, repo, str(head)):
                raise NotFoundError(f"commit {head} is not in {repo} after refresh")

    def evict(self, idle_days: int) -> list[HttpsRepoUrl]:
        """Drop every mirror with no checkout in `idle_days` days; the repos dropped."""
        if idle_days < 0:
            raise ValidationError(f"idle_days must be non-negative: {idle_days}")
        cutoff = self._clock.now().timestamp() - timedelta(days=idle_days).total_seconds()
        dropped = []
        mirrors = []
        for top, dirs, files in os.walk(self._root, followlinks=False):
            path = Path(top)
            # checked-out source (a shared tree) can hold its own `x.git/HEAD` fixtures
            dirs[:] = [
                d
                for d in dirs
                if not d.endswith(_SHARED_SUFFIX)
                and not (path == self._root and d == LOCAL_SHARED_DIR)
            ]
            if path.name.endswith(".git") and ("HEAD" in files or _LAST_USE in files):
                # Loose refs can end in .git; never descend into a mirror's contents.
                dirs.clear()
                mirrors.append(path)
        for mirror in sorted(mirrors):
            with self._locked(mirror, blocking=False) as acquired:
                if not acquired or not mirror.is_dir():
                    continue
                last_use = mirror / _LAST_USE
                touched = (last_use if last_use.exists() else mirror).stat().st_mtime
                if touched >= cutoff:
                    continue
                # Registered worktrees remain live after the acquisition lock is released.
                worktrees = mirror / "worktrees"
                if worktrees.is_dir() and any(worktrees.iterdir()):
                    continue
                shutil.rmtree(mirror, ignore_errors=True)
                dropped.append(_REPO_URL.validate_python(self._repo_url(mirror)))
                log.info("evicted the mirror of %s", dropped[-1])
        return dropped

    @contextmanager
    def _locked(self, mirror: Path, *, blocking: bool = True) -> Iterator[bool]:
        mirror.parent.mkdir(parents=True, exist_ok=True)
        with mirror.with_name(f"{mirror.name}.lock").open("a") as held:
            try:
                fcntl.flock(held, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                yield False
                return
            yield True

    def _object_format(self, mirror: Path) -> str | None:
        res = self._runner.run(
            ["git", "-C", str(mirror), *HARDENED, "rev-parse", "--show-object-format"],
            check=False,
        )
        return res.stdout.decode().strip() if res.returncode == 0 else None

    def _fetch(self, mirror: Path, repo: HttpsRepoUrl, sha: str) -> bool:
        expected_format = "sha256" if len(sha) == 64 else "sha1"
        created = False
        if not _healthy(mirror):
            self._runner.run(
                [
                    "git",
                    "init",
                    "--bare",
                    "--quiet",
                    f"--object-format={expected_format}",
                    str(mirror),
                ]
            )
            self._touch(mirror)
            created = True
        elif self._object_format(mirror) != expected_format:
            return False
        self._git(mirror, "config", "remote.origin.url", str(repo))
        started = time.monotonic()
        env = self._fetch_env(repo)
        fetch = ["git", "-C", str(mirror), *HARDENED, "fetch", "--quiet"]
        fetch_res = self._runner.run(
            [
                *fetch,
                "--prune",
                str(repo),
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
            env=env,
            check=False,
        )
        if fetch_res.returncode:
            if b"mismatched algorithms" in fetch_res.stderr:
                if created:
                    shutil.rmtree(mirror, ignore_errors=True)
                return False
            raise ProcessError(fetch_res)
        if self._reachable(mirror, sha):
            if self._reader.tags_at(mirror, sha):
                self._mark_tags_refreshed(mirror)
            log.info("mirror fetch %s in %.1fs", repo, time.monotonic() - started)
            return True
        advertised = self._runner.run(
            [
                "git",
                "-C",
                str(mirror),
                *HARDENED,
                "ls-remote",
                "--refs",
                str(repo),
                "refs/pull/*/head",
                "refs/merge-requests/*/head",
            ],
            env=env,
        )
        refs = {
            ref: tip
            for line in advertised.stdout.decode().splitlines()
            for tip, ref in [line.split("\t", 1)]
        }
        matching = tuple(ref for ref, tip in refs.items() if tip == sha)
        candidates = matching or self._api.review_refs(repo, sha)
        for ref in candidates:
            if ref not in refs:
                continue
            result = self._runner.run([*fetch, "--no-tags", str(repo), ref], env=env, check=False)
            if result.returncode:
                if b"not our ref" in result.stderr or b"couldn't find remote ref" in result.stderr:
                    continue
                raise ProcessError(result)
            if (
                self._reader.reachable(mirror, sha)
                and not self._runner.run(
                    [
                        "git",
                        "-C",
                        str(mirror),
                        *HARDENED,
                        "merge-base",
                        "--is-ancestor",
                        sha,
                        "FETCH_HEAD",
                    ],
                    check=False,
                ).returncode
            ):
                log.info("mirror fetch %s in %.1fs", repo, time.monotonic() - started)
                return True
        return False

    def _maybe_fetch_tags(self, mirror: Path, repo: HttpsRepoUrl, *, force: bool = False) -> None:
        """Refresh tags past their TTL. Tags are mutable release evidence: cached tags past
        their TTL are not current, so an unreachable forge fails the checkout closed, as a
        typed transient error (the commit being local proves nothing about its tags), and
        stamps nothing, so the next checkout retries."""
        if not force and self._tags_fresh(mirror):
            return
        try:
            self._fetch_tags(mirror, repo)
        except ProcessError as e:
            log.warning("tag refresh for %s failed", repo, exc_info=True)
            raise ServiceError(
                f"cannot refresh the release tags of {repo}: the forge is unreachable and "
                "cached tags are not current release evidence",
                operation="mirror.refresh_tags",
            ) from e

    def _tags_fresh(self, mirror: Path) -> bool:
        marker = mirror / _TAGS_REFRESHED
        try:
            refreshed_at = float(marker.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return False
        elapsed = self._clock.now().timestamp() - refreshed_at
        return 0.0 <= elapsed < TAG_REFRESH_TTL_SECONDS

    def _mark_tags_refreshed(self, mirror: Path) -> None:
        (mirror / _TAGS_REFRESHED).write_text(
            f"{self._clock.now().timestamp()}\n", encoding="utf-8"
        )

    def _fetch_tags(self, mirror: Path, repo: HttpsRepoUrl) -> None:
        """Refresh remote tags into an existing mirror without recreating worktrees."""
        env = self._fetch_env(repo)
        self._runner.run(
            [
                "git",
                "-C",
                str(mirror),
                *HARDENED,
                "fetch",
                "--quiet",
                "--prune",
                str(repo),
                "+refs/tags/*:refs/tags/*",
            ],
            env=env,
        )
        self._mark_tags_refreshed(mirror)

    def _reachable(self, mirror: Path, sha: str) -> bool:
        return self._reader.reachable(mirror, sha) and bool(
            self._runner.run(
                [
                    "git",
                    "-C",
                    str(mirror),
                    *HARDENED,
                    "for-each-ref",
                    "--contains",
                    sha,
                    "--format=%(refname)",
                    "refs/heads",
                    "refs/tags",
                ],
            ).stdout.strip()
        )

    def _fetch_env(self, repo: HttpsRepoUrl) -> dict[str, str]:
        headers = self._api.git_headers(repo.host)
        if not headers:
            return dict(_FETCH_ENV)
        return {
            **_FETCH_ENV,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{repo!s}.extraheader",
            "GIT_CONFIG_VALUE_0": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        }

    def _git(self, mirror: Path, *args: str, check: bool = True) -> None:
        self._runner.run(["git", "-C", str(mirror), *HARDENED, *args], check=check)

    def _mirror(self, repo: HttpsRepoUrl) -> Path:
        return self._root / repo.host / f"{repo.path}.git"

    def _touch(self, mirror: Path) -> None:
        (mirror / _LAST_USE).touch()

    def _repo_url(self, mirror: Path) -> str:
        rel = mirror.relative_to(self._root).as_posix().removesuffix(".git")
        host, _, path = rel.partition("/")
        return f"https://{host}/{path}"


def _healthy(mirror: Path) -> bool:
    # git init finished writing it; a crash mid-rmtree leaves HEAD without refs/ or objects/.
    return (
        (mirror / "HEAD").is_file() and (mirror / "refs").is_dir() and (mirror / "objects").is_dir()
    )
