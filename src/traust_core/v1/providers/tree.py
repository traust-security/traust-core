"""The regular files of an untrusted checkout, read as text; never follows a symlink out."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError

SKIP_DIRS = frozenset(
    {".git", "vendor", "node_modules", "third_party", "testdata", ".tox", "__pycache__", "dist",
     "build", ".venv", "venv"}
)  # fmt: skip
MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class TreeFile:
    rel: str
    path: Path

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def parts(self) -> tuple[str, ...]:
        return tuple(self.rel.split("/"))

    @cached_property
    def text(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise ServiceError(f"cannot read {self.rel}: {e}") from e


def tree_files(root: Path, skip: frozenset[str] = SKIP_DIRS) -> list[TreeFile]:
    """Files up to 2 MB with no path part in `skip`, in path order."""
    if not root.is_dir():
        raise ValidationError(f"workspace is not a directory: {root}")
    found = []
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in names:
            path = Path(top) / name
            if name in skip or path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size <= MAX_FILE_BYTES:
                found.append(TreeFile(path.relative_to(root).as_posix(), path))
    return sorted(found, key=lambda f: f.parts)
