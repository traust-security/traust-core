"""A commit's tree straight off a repository on this machine: a worktree per checkout, no
mirror, no fetch, no cache — the local twin of the mirror for repositories a caller
materialized at a deterministic sha."""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.values import LocalRepoUrl
from traust_core.v1.providers import shared_tree
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.checkout import HARDENED, GitCheckout
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.sources import CheckoutRequest, Workspace


class LocalCheckout:
    """`RepoCheckoutService`'s local seam: whole trees, any history, writable on request, from
    a repository the caller materialized on this machine."""

    name = "git-local"

    def __init__(self, runner: ProcessRunner, clock: Clock, shared_dir: Path | None = None) -> None:
        self._runner, self._clock = runner, clock
        self._reader = GitCheckout(runner)
        self._shared_dir = shared_dir
        self._lock = threading.Lock()

    def check(self) -> Readiness:
        return Readiness(ready=self._runner.allows("git"), detail="git is not allowed here")

    def _shared_root(self) -> Path:
        if self._shared_dir is not None:
            return self._shared_dir
        return Path(tempfile.gettempdir()) / f"traust-local-shared-{os.getuid()}"

    def _shared_base(self, repo_path: Path) -> Path:
        digest = hashlib.sha256(str(repo_path.resolve()).encode("utf-8")).hexdigest()[:16]
        return (self._shared_root() / digest).resolve()

    def _shared_paths(self, repo_path: Path, sha: str) -> tuple[Path, Path]:
        base = self._shared_base(repo_path)
        return (base / sha).resolve(), base / f"{sha}.refs"

    @contextmanager
    def _locked(self, repo_path: Path) -> Iterator[None]:
        base = self._shared_base(repo_path)
        base.mkdir(parents=True, exist_ok=True)
        with self._lock, (base / "shared.lock").open("a") as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(held.fileno(), fcntl.LOCK_UN)

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]:
        if request.shared and request.writable:
            raise ValidationError("a shared checkout must be read-only")
        repo = request.repo
        if not isinstance(repo, LocalRepoUrl):
            raise ValidationError(f"{self.name} checks out a local repository, not {repo!s}")
        if not _healthy(repo.path):
            raise NotFoundError(f"{repo.path} is not a healthy git repository")
        sha = str(request.ref)
        if not self._reader.reachable(repo.path, sha):
            raise NotFoundError(f"commit {sha} is not in {repo}")
        if request.shared:
            with self._locked(repo.path):
                worktree, refs_file = self._shared_paths(repo.path, sha)
                if (
                    worktree.is_dir()
                    and self._reader.is_checkout(worktree)
                    and self._reader.head(worktree) == sha
                ):
                    shared_tree.acquire(refs_file)
                    return Result(
                        Workspace(
                            repo=repo,
                            sha=request.ref,
                            path=worktree,
                            provider=self.name,
                            shared=True,
                        ),
                        Acquisition(
                            provider=self.name,
                            acquired_at=self._clock.now(),
                            source=str(repo),
                        ),
                    )
                if worktree.exists():
                    self._git(repo.path, "worktree", "unlock", str(worktree), check=False)
                    self._git(
                        repo.path, "worktree", "remove", "--force", str(worktree), check=False
                    )
                    shutil.rmtree(worktree, ignore_errors=True)
                    self._git(repo.path, "worktree", "prune", check=False)
                try:
                    self._git(
                        repo.path, "worktree", "add", "--quiet", "--detach", str(worktree), sha
                    )
                    self._git(
                        repo.path, "worktree", "lock", "--reason", "traust-shared", str(worktree)
                    )
                    # inside the cleanup: a tree whose first count never landed has no holder
                    shared_tree.write_holders(refs_file, 1)
                except BaseException:
                    self._git(repo.path, "worktree", "unlock", str(worktree), check=False)
                    self._git(
                        repo.path, "worktree", "remove", "--force", str(worktree), check=False
                    )
                    shutil.rmtree(worktree, ignore_errors=True)
                    refs_file.unlink(missing_ok=True)
                    self._git(repo.path, "worktree", "prune", check=False)
                    raise
                return Result(
                    Workspace(
                        repo=repo,
                        sha=request.ref,
                        path=worktree,
                        provider=self.name,
                        shared=True,
                    ),
                    Acquisition(
                        provider=self.name, acquired_at=self._clock.now(), source=str(repo)
                    ),
                )
        worktree = Path(tempfile.mkdtemp(prefix="checkout-")).resolve()
        try:
            self._git(repo.path, "worktree", "add", "--quiet", "--detach", str(worktree), sha)
        except BaseException:
            shutil.rmtree(worktree, ignore_errors=True)
            raise
        return Result(
            Workspace(repo=repo, sha=request.ref, path=worktree, provider=self.name, shared=False),
            Acquisition(provider=self.name, acquired_at=self._clock.now(), source=str(repo)),
        )

    def release(self, workspace: Workspace) -> None:
        repo = workspace.repo
        if not isinstance(repo, LocalRepoUrl):
            raise ValidationError(f"workspace {workspace.path} is not a local origin: {repo!s}")
        target = workspace.path.resolve()
        with self._locked(repo.path):
            owned, locked = self._worktree_state(repo.path)
            worktree, refs_file = self._shared_paths(repo.path, str(workspace.sha))
            shared_root = worktree.parent
            is_managed_shared = target == worktree or target.is_relative_to(shared_root)
            if workspace.shared or is_managed_shared:
                if target != worktree or target not in owned:
                    raise ValidationError(
                        f"workspace {workspace.path} is not the shared worktree for "
                        f"{repo}@{workspace.sha}; refusing to remove"
                    )
                if not shared_tree.release(refs_file):
                    return
                self._git(repo.path, "worktree", "unlock", str(target), check=False)
            elif target not in owned:
                raise ValidationError(
                    f"workspace {workspace.path} is not a worktree of {repo.path}; "
                    "refusing to remove"
                )
            elif target in locked:
                raise ValidationError(
                    f"workspace {workspace.path} is a locked shared worktree managed by another "
                    "cache; refusing to remove"
                )
            self._git(repo.path, "worktree", "remove", "--force", str(target), check=False)
            shutil.rmtree(target, ignore_errors=True)
            # the worktree registered in the source repository's own worktrees/ dir; prune so a
            # materialized repository re-runs clean even when the directory is already gone
            self._git(repo.path, "worktree", "prune", check=False)

    def _worktree_state(self, repo: Path) -> tuple[set[Path], set[Path]]:
        """(owned, locked) secondary worktrees git registered under `repo`, never its main one."""
        listed = self._runner.run(
            ["git", "-C", str(repo), *HARDENED, "worktree", "list", "--porcelain"], check=False
        ).stdout.decode(errors="replace")
        entries: list[tuple[Path, bool]] = []
        current: Path | None = None
        is_locked = False
        for line in listed.splitlines():
            if line.startswith("worktree "):
                if current is not None:
                    entries.append((current, is_locked))
                current = Path(line.removeprefix("worktree ")).resolve()
                is_locked = False
            elif line == "locked" or line.startswith("locked "):
                is_locked = True
        if current is not None:
            entries.append((current, is_locked))
        secondary = entries[1:]
        return (
            {path for path, _ in secondary},
            {path for path, flag in secondary if flag},
        )

    def _git(self, repo: Path, *args: str, check: bool = True) -> None:
        self._runner.run(["git", "-C", str(repo), *HARDENED, *args], check=check)


def _healthy(repo: Path) -> bool:
    # mirror.py's _healthy, plus the .git/ dir of a materialized clone (a bare repository
    # keeps HEAD, refs/ and objects/ at its own root)
    return any(
        (root / "HEAD").is_file() and (root / "refs").is_dir() and (root / "objects").is_dir()
        for root in (repo, repo / ".git")
    )
