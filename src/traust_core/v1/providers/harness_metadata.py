from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.harness_metadata import HarnessMetadata
from traust_core.v1.models.values import require_aware_datetime
from traust_core.v1.providers.checkout import HARDENED
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner

_EXCLUDED = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        "__pycache__",
        "__pypackages__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        "deps",
        "node_modules",
        "site-packages",
        "vendor",
        "vendored",
        "third_party",
        "generated",
        "build",
        "dist",
        "htmlcov",
    }
)
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _is_test(path: Path) -> bool:
    return (
        bool({"test", "tests"}.intersection(path.parts[:-1]))
        or path.name == "conftest.py"
        or path.name.startswith("test_")
        or path.name.endswith("_test.py")
    )


class HarnessMetadataProvider:
    def __init__(self, root: Path, process: ProcessRunner, clock: Clock) -> None:
        self._root = root
        self._process = process
        self._clock = clock

    def measure(self) -> HarnessMetadata:
        """Measure current first-party Python physical lines and syntactic test definitions."""
        if not self._root.is_dir():
            raise ValidationError(f"harness root is not a directory: {self._root}")
        measured_at = self._clock.now()
        require_aware_datetime(measured_at, "harness measured_at")
        limitations: list[str] = []
        version_path = self._root / "VERSION"
        version = None
        if version_path.exists():
            try:
                version = self._read(version_path).decode("utf-8").strip() or None
            except UnicodeError as e:
                raise ValidationError(f"invalid harness VERSION at {version_path}: {e}") from e
            if version is None:
                limitations.append("VERSION is empty; harness version is unavailable")
        else:
            limitations.append("VERSION is missing; harness version is unavailable")

        revision = None
        commits = None
        releases = None
        git_path = self._root / ".git"
        has_git = git_path.exists() or git_path.is_symlink()
        git_permitted = self._process.allows("git")
        if has_git and git_permitted:
            revision = self._git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
            if not _REVISION.fullmatch(revision):
                raise ValidationError(f"invalid harness Git HEAD at {self._root}: {revision!r}")
            raw_count = self._git("rev-list", "--count", revision, "--").strip()
            if not raw_count.isdigit():
                raise ValidationError(f"invalid harness Git commit count at {self._root}")
            if self._git("rev-parse", "--is-shallow-repository").strip() == b"true":
                limitations.append("Git history is shallow; total commit count is unavailable")
            else:
                commits = int(raw_count)
            releases = len(self._git("tag", "--list").splitlines())
            files = (
                Path(os.fsdecode(name))
                for name in set(self._git("ls-files", "--cached", "-z", "--").split(b"\0"))
                if name
            )
        else:
            if not has_git:
                limitations.append(
                    "Git metadata is missing; revision, commits and releases unavailable"
                )
            if not git_permitted:
                limitations.append("Git not permitted; revision, commits and releases unavailable")
            limitations.append(
                "Source and test counts use shipped files, not a Git tracked-file list"
            )
            files = self._shipped_files(self._root)

        source_available = (self._root / "src").is_dir()
        tests_available = any((self._root / name).is_dir() for name in ("test", "tests"))
        source_lines = 0
        test_count = 0
        for relative in files:
            if relative.suffix != ".py" or _EXCLUDED.intersection(relative.parts[:-1]):
                continue
            path = self._root / relative
            data = self._read(path)
            if _is_test(relative):
                tests_available = True
                try:
                    tree = ast.parse(data, filename=str(path))
                except (SyntaxError, ValueError) as e:
                    raise ValidationError(f"invalid harness Python test at {path}: {e}") from e
                test_count += sum(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test_")
                    for node in ast.walk(tree)
                )
            else:
                source_available = True
                source_lines += len(data.splitlines())
        if not source_available:
            limitations.append("Python source tree is missing; source line count is unavailable")
        if not tests_available:
            limitations.append("Test tree is missing; test count is unavailable")
        return HarnessMetadata(
            measured_at=measured_at,
            version=version,
            revision=revision,
            commits=commits,
            releases=releases,
            source_lines=source_lines if source_available else None,
            test_count=test_count if tests_available else None,
            limitations=tuple(limitations),
        )

    def _git(self, *args: str) -> bytes:
        return self._process.run(["git", "-C", str(self._root), *HARDENED, *args]).stdout

    def _read(self, path: Path) -> bytes:
        try:
            if not path.resolve().is_relative_to(self._root.resolve()):
                raise ValidationError(f"harness file escapes root {self._root}: {path}")
            return path.read_bytes()
        except OSError as e:
            raise ValidationError(f"cannot read harness metadata at {path}: {e}") from e

    def _shipped_files(self, directory: Path) -> Iterator[Path]:
        try:
            for path in directory.iterdir():
                if path.name in _EXCLUDED:
                    continue
                if path.is_dir() and not path.is_symlink():
                    yield from self._shipped_files(path)
                elif path.suffix == ".py":
                    yield path.relative_to(self._root)
        except OSError as e:
            raise ValidationError(f"cannot read shipped harness files at {directory}: {e}") from e
