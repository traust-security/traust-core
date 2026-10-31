"""A commit's tree from a per-repository bare git mirror: only head moves cross the wire after
the first fetch; the host's forge token rides git's configuration environment, never argv."""

from __future__ import annotations

import fcntl
import logging
import shutil
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from pydantic import TypeAdapter

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
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
_REPO_URL = TypeAdapter(HttpsRepoUrl)


class MirrorCheckout:
    """`RepoCheckoutService`'s mirror seam: whole trees, any history, writable on request."""

    name = CheckoutProviderName.MIRROR

    def __init__(self, runner: ProcessRunner, clock: Clock, root: Path, api: ForgeApi) -> None:
        self._runner, self._clock, self._root, self._api = runner, clock, root, api
        self._reader = GitCheckout(runner)

    def check(self) -> Readiness:
        return Readiness(ready=self._runner.allows("git"), detail="git is not allowed here")

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        sha = str(request.ref)
        mirror = self._mirror(request.repo)
        with self._locked(mirror):
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
            Workspace(repo=request.repo, sha=request.ref, path=worktree, provider=self.name),
            Acquisition(
                provider=self.name, acquired_at=self._clock.now(), source=str(request.repo)
            ),
        )

    def release(self, workspace: Workspace) -> None:
        mirror = self._mirror(workspace.repo)
        with self._locked(mirror):
            self._git(
                mirror,
                "worktree",
                "remove",
                "--force",
                str(workspace.path),
                check=False,
            )
            shutil.rmtree(workspace.path, ignore_errors=True)

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
        for mirror in sorted(self._root.rglob("*.git")):
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

    def _fetch(self, mirror: Path, repo: HttpsRepoUrl, sha: str) -> bool:
        if not _healthy(mirror):
            self._runner.run(["git", "init", "--bare", "--quiet", str(mirror)])
            self._touch(mirror)
        started = time.monotonic()
        env = self._fetch_env(repo)
        fetch = ["git", "-C", str(mirror), *HARDENED, "fetch", "--quiet"]
        self._runner.run(
            [
                *fetch,
                "--prune",
                str(repo),
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
            env=env,
        )
        reachable = self._reader.reachable(mirror, sha)
        if not reachable:
            result = self._runner.run([*fetch, "--no-tags", str(repo), sha], env=env, check=False)
            if result.returncode:
                if any(
                    message in result.stderr
                    for message in (
                        f"not our ref {sha}".encode(),
                        f"couldn't find remote ref {sha}".encode(),
                    )
                ):
                    return False
                raise ProcessError(result)
            reachable = self._reader.reachable(mirror, sha)
        log.info("mirror fetch %s in %.1fs", repo, time.monotonic() - started)
        return reachable

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
