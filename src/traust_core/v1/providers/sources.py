from __future__ import annotations

from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Protocol

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.models.code_facts import LanguageStats
from traust_core.v1.models.inventory import OrgName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, RepoOrigin, RepoPath
from traust_core.v1.providers.base import Readiness, Result


class CheckoutRequest(Dto):
    repo: RepoOrigin
    # An order always names its commit.
    ref: GitSha
    # The minimum history the order needs: None (just the files), a depth, or an anchor sha the
    # history must reach. The mirror serves every shape; the archive serves none.
    history: int | GitSha | None = None
    writable: bool = False
    # Glob patterns of the files to keep (a basename, or a path when it holds "/"); None keeps all.
    keep: tuple[str, ...] | None = None


class CheckoutProviderName(StrEnum):
    """The closed set of providers a Workspace can come from."""

    MIRROR = "git-mirror"
    ARCHIVE = "forge-archive"
    LOCAL = "git-local"


class Workspace(Dto):
    repo: RepoOrigin
    sha: GitSha
    path: Path
    # The checkout provider that made it, so release reaches the right one.
    provider: CheckoutProviderName


class Checkouts(Protocol):
    """The one door for a commit's files as a tool provider consumes it; `RepoCheckoutService`
    satisfies it."""

    def checkout(self, request: CheckoutRequest) -> Result[Workspace]: ...

    def release(self, workspace: Workspace) -> None: ...


def workspace_file(workspace: Workspace, path: str, *, max_bytes: int | None = None) -> str | None:
    """A kept file's text in the workspace; None when the commit doesn't hold it."""
    file = workspace.path / RepoPath.parse(path).value
    if max_bytes is not None and max_bytes < 0:
        raise ValidationError(f"max_bytes must be non-negative, got {max_bytes}")
    try:
        if not file.resolve().is_relative_to(workspace.path.resolve()):
            raise ValidationError(f"workspace file {path!r} leaves the checkout")
    except (OSError, RuntimeError) as e:
        raise ValidationError(f"workspace file {path!r} cannot be resolved") from e
    if not file.is_file():
        return None
    with file.open("rb") as source:
        content = source.read(max_bytes + 1) if max_bytes is not None else source.read()
    if max_bytes is not None and len(content) > max_bytes:
        raise ValidationError(f"workspace file {path!r} exceeds {max_bytes} bytes")
    return content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


class RepoInfo(Dto):
    repo: HttpsRepoUrl
    default_branch: str | None = None
    head: GitSha | None = None
    archived: bool | None = None
    pushed_at: str | None = None
    visibility: str | None = None
    fork: bool | None = None
    parent: str | None = None


class OwnerOrigin(StrEnum):
    OWNERS_FILE = "owners-file"
    CONTRIBUTOR = "contributor"


class OwnerHint(Dto):
    """A forge handle that may own a repository: untrusted content, recorded, never followed."""

    handle: str
    origin: OwnerOrigin
    file: str | None = None


class ChangedFile(Dto):
    filename: str
    changes: int


class Comparison(Dto):
    ahead_by: int
    files: tuple[ChangedFile, ...]
    truncated: bool
    patch: str | None = None


class RepoTree(Dto):
    """The file paths of a commit's tree; `truncated` when the forge capped the listing."""

    paths: tuple[str, ...]
    truncated: bool


class CommitFile(Dto):
    filename: str
    patch: str = ""


class Commit(Dto):
    sha: str
    files: tuple[CommitFile, ...]


class Quota(Dto):
    remaining: int | None


class SourceError(ServiceError):
    def __init__(self, message: str, observation_status: ComparisonStatus) -> None:
        super().__init__(message)
        self.observation_status = observation_status


class SourceProvider(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def info(self, repo: HttpsRepoUrl) -> Result[RepoInfo]: ...

    def owners(self, repo: HttpsRepoUrl) -> Result[list[OwnerHint]]: ...

    def list_org(self, org: OrgName, host: str) -> Result[list[RepoInfo]]: ...

    def languages(self, repo: HttpsRepoUrl) -> Result[LanguageStats]: ...

    def head(self, repo: HttpsRepoUrl, branch: str) -> Result[GitSha]: ...

    def compare(self, repo: HttpsRepoUrl, baseline: str, branch: str) -> Result[Comparison]: ...

    def compare_patch(self, repo: HttpsRepoUrl, baseline: str) -> Result[str]: ...

    def tree(self, repo: HttpsRepoUrl, ref: str) -> Result[RepoTree]: ...

    def quota(self, repo: HttpsRepoUrl) -> Result[Quota]: ...

    def commit(self, repo: HttpsRepoUrl, sha: str) -> Result[Commit]: ...

    def file(self, repo: HttpsRepoUrl, path: RepoPath, sha: GitSha) -> Result[str | None]: ...


def _path_options(cited: str, root_name: str, prefixes: tuple[str, ...]) -> list[str]:
    options = [cited, *(cited[len(p) :] for p in prefixes if cited.startswith(p))]
    if cited.startswith(root_name + "/"):
        options.append(cited[len(root_name) + 1 :])
    return options


def _suffix_matches(cited: str, by_name: dict[str, list[Path]], root: Path) -> list[Path]:
    parts, name = Path(cited).parts, Path(cited).name
    if same := by_name.get(name):
        return [p for p in same if p.relative_to(root).parts[-len(parts) :] == parts]
    dirs = parts[:-1]
    return [
        p
        for basename, paths in by_name.items()
        if basename.endswith("-" + name)
        for p in paths
        if not dirs or p.relative_to(root).parts[:-1][-len(dirs) :] == dirs
    ]


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
        for option in _path_options(cited, self.root.name, self.STRIP_PREFIXES):
            path = (self.root / option).resolve()
            if path.is_file() and path.is_relative_to(self.root):
                return path
        return None

    def matches(self, cited: str) -> list[Path]:
        """`resolve`, else every file whose trailing path components (or basename tail) match."""
        if exact := self.resolve(cited):
            return [exact]
        return _suffix_matches(cited, self._by_name, self.root)

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


class ForgeFiles:
    """Pinned forge files for citation checks; paths name repo files, never local files."""

    def __init__(self, source: SourceProvider, repo: HttpsRepoUrl, sha: GitSha) -> None:
        if not isinstance(repo, HttpsRepoUrl) or not isinstance(sha, GitSha):
            raise ValidationError("forge citation files need an HttpsRepoUrl and a full GitSha")
        HttpsRepoUrl.parse(str(repo), (repo.host,))
        GitSha.parse(sha.value)
        self._source, self._repo, self._sha = source, repo, sha
        self._line_counts: dict[Path, int | None] = {}

    def resolve(self, cited: str) -> Path | None:
        if not self._valid_citation(cited):
            return None
        for option in _path_options(
            cited, self._repo.path.rsplit("/", 1)[-1], WorkspaceFiles.STRIP_PREFIXES
        ):
            path = Path(option)
            if path in self._paths:
                return path
        return None

    def matches(self, cited: str) -> list[Path]:
        if not self._valid_citation(cited):
            return []
        if exact := self.resolve(cited):
            return [exact]
        return _suffix_matches(cited, self._by_name, Path())

    def line_count(self, path: Path) -> int | None:
        if not isinstance(path, Path) or not self._valid_citation(path.as_posix()):
            raise ValidationError("forge citation line counts need a relative repository file path")
        if path not in self._paths:
            return None
        if path not in self._line_counts:
            text = self._source.file(self._repo, RepoPath.parse(path.as_posix()), self._sha).data
            self._line_counts[path] = None if text is None else len(text.splitlines())
        return self._line_counts[path]

    @staticmethod
    def _valid_citation(cited: str) -> bool:
        try:
            RepoPath.parse(cited.removeprefix("./"))
        except ValidationError:
            return False
        return True

    @cached_property
    def _paths(self) -> frozenset[Path]:
        tree = self._source.tree(self._repo, str(self._sha)).data
        if tree.truncated:
            raise SourceError(
                f"citation tree for {self._repo} at {self._sha} is truncated",
                ComparisonStatus.ERROR,
            )
        paths = frozenset(Path(path) for path in tree.paths)
        if any(
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or any(char in path.as_posix() for char in ("\\", ":", "\x00"))
            for path in paths
        ):
            raise SourceError(
                f"citation tree for {self._repo} at {self._sha} contains an unsafe file path",
                ComparisonStatus.ERROR,
            )
        return paths

    @cached_property
    def _by_name(self) -> dict[str, list[Path]]:
        index: dict[str, list[Path]] = {}
        for path in sorted(self._paths):
            if not WorkspaceFiles.SKIP_DIRS.intersection(path.parts):
                index.setdefault(path.name, []).append(path)
        return index
