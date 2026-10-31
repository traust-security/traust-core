"""A commit's tree straight off a repository on this machine: a worktree per checkout, no
mirror, no fetch, no cache — the local twin of the mirror for repositories a caller
materialized at a deterministic sha."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.values import LocalRepoUrl
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.checkout import HARDENED, GitCheckout
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace


class LocalCheckout:
    """`RepoCheckoutService`'s local seam: whole trees, any history, writable on request, from
    a repository the caller materialized on this machine."""

    name = "git-local"

    def __init__(self, runner: ProcessRunner, clock: Clock) -> None:
        self._runner, self._clock = runner, clock
        self._reader = GitCheckout(runner)

    def check(self) -> Readiness:
        return Readiness(ready=self._runner.allows("git"), detail="git is not allowed here")

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        repo = request.repo
        if not isinstance(repo, LocalRepoUrl):
            raise ValidationError(f"{self.name} checks out a local repository, not {repo!s}")
        if not _healthy(repo.path):
            raise NotFoundError(f"{repo.path} is not a healthy git repository")
        sha = str(request.ref)
        if not self._reader.reachable(repo.path, sha):
            raise NotFoundError(f"commit {sha} is not in {repo}")
        worktree = Path(tempfile.mkdtemp(prefix="checkout-"))
        try:
            self._git(repo.path, "worktree", "add", "--quiet", "--detach", str(worktree), sha)
        except BaseException:
            shutil.rmtree(worktree, ignore_errors=True)
            raise
        return Result(
            Workspace(repo=repo, sha=request.ref, path=worktree, provider=self.name),
            Acquisition(provider=self.name, acquired_at=self._clock.now(), source=str(repo)),
        )

    def release(self, workspace: Workspace) -> None:
        repo = workspace.repo
        if not isinstance(repo, LocalRepoUrl):
            raise ValidationError(f"workspace {workspace.path} is not a local origin: {repo!s}")
        if workspace.path.resolve() not in self._worktrees(repo.path):
            raise ValidationError(
                f"workspace {workspace.path} is not a worktree of {repo.path}; refusing to remove"
            )
        self._git(repo.path, "worktree", "remove", "--force", str(workspace.path), check=False)
        shutil.rmtree(workspace.path, ignore_errors=True)
        # the worktree registered in the source repository's own worktrees/ dir; prune so a
        # materialized repository re-runs clean even when the directory is already gone
        self._git(repo.path, "worktree", "prune", check=False)

    def _worktrees(self, repo: Path) -> set[Path]:
        """The worktrees git registered under `repo`, never its own main one: the only paths
        release removes, so a forged or foreign path is refused, never deleted."""
        listed = self._runner.run(
            ["git", "-C", str(repo), *HARDENED, "worktree", "list", "--porcelain"], check=False
        ).stdout.decode(errors="replace")
        worktrees = [
            line.removeprefix("worktree ")
            for line in listed.splitlines()
            if line.startswith("worktree ")
        ]
        return {Path(worktree).resolve() for worktree in worktrees[1:]}

    def _git(self, repo: Path, *args: str, check: bool = True) -> None:
        self._runner.run(["git", "-C", str(repo), *HARDENED, *args], check=check)


def _healthy(repo: Path) -> bool:
    # mirror.py's _healthy, plus the .git/ dir of a materialized clone (a bare repository
    # keeps HEAD, refs/ and objects/ at its own root)
    return any(
        (root / "HEAD").is_file() and (root / "refs").is_dir() and (root / "objects").is_dir()
        for root in (repo, repo / ".git")
    )
