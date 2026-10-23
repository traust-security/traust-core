from __future__ import annotations

from functools import cached_property
from pathlib import Path
from typing import Protocol

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import LanguageStats
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.base import Readiness, Result


class CheckoutRequest(Dto):
    repo: HttpsRepoUrl
    ref: GitSha | None = None
    depth: int | None = 1


class Workspace(Dto):
    repo: HttpsRepoUrl
    sha: GitSha
    path: Path


class RepoInfo(Dto):
    repo: HttpsRepoUrl
    default_branch: str | None = None
    head: GitSha | None = None
    archived: bool | None = None
    pushed_at: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None


class OwnerHint(Dto): ...


class ChangedFile(Dto):
    filename: str
    changes: int


class Comparison(Dto):
    ahead_by: int
    files: tuple[ChangedFile, ...]
    truncated: bool
    patch: str | None = None


class Quota(Dto):
    remaining: int | None


class SourceError(ServiceError):
    def __init__(self, message: str, observation_status: ComparisonStatus) -> None:
        super().__init__(message)
        self.observation_status = observation_status


class SourceProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]: ...

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]: ...

    def release(self, workspace: Workspace) -> None: ...

    def owners(self, repo: HttpsRepoUrl) -> Result[list[OwnerHint]]: ...

    def list_org(self, org: OrgName) -> Result[list[HttpsRepoUrl]]: ...

    def languages(self, repo: HttpsRepoUrl) -> Result[LanguageStats]: ...

    def compare(self, repo: HttpsRepoUrl, baseline: str, branch: str) -> Result[Comparison]: ...

    def quota(self, repo: HttpsRepoUrl) -> Result[Quota]: ...


class WorkspaceFiles:
    """Read-only view of a checkout for citation checks: lenient path resolution and line counts.

    Lenient because verifiers cite paths relative to a component or package root, or abbreviate
    hyphenated basenames; a false "not found" costs a re-vote, so only no match at all is a miss.
    """

    STRIP_PREFIXES = ("./", "src/", "app/")
    SKIP_DIRS = frozenset(
        {".git", "vendor", "node_modules", "dist", "build", "__pycache__", ".venv", "venv", ".tox"}
    )

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def resolve(self, cited: str) -> Path | None:
        """The file a cited path names under the root, allowing prefix skew; never outside it."""
        if not cited or cited == ".":
            return None
        options = [cited, *(cited[len(p) :] for p in self.STRIP_PREFIXES if cited.startswith(p))]
        if cited.startswith(self.root.name + "/"):
            options.append(cited[len(self.root.name) + 1 :])
        for option in options:
            path = (self.root / option).resolve()
            if path.is_file() and path.is_relative_to(self.root):
                return path
        return None

    def matches(self, cited: str) -> list[Path]:
        """`resolve`, else every file whose trailing path components (or basename tail) match."""
        if exact := self.resolve(cited):
            return [exact]
        parts, name = Path(cited).parts, Path(cited).name
        if same := self._by_name.get(name):
            return [p for p in same if p.relative_to(self.root).parts[-len(parts) :] == parts]
        dirs = parts[:-1]
        return [
            p
            for basename, paths in self._by_name.items()
            if basename.endswith("-" + name)
            for p in paths
            if not dirs or p.relative_to(self.root).parts[:-1][-len(dirs) :] == dirs
        ]

    def line_count(self, path: Path) -> int | None:
        try:
            return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return None

    @cached_property
    def _by_name(self) -> dict[str, list[Path]]:
        index: dict[str, list[Path]] = {}
        for p in self.root.rglob("*"):
            if p.is_file() and not self.SKIP_DIRS.intersection(p.relative_to(self.root).parts):
                index.setdefault(p.name, []).append(p)
        return index
