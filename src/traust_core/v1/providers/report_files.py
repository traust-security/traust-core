"""Report files on disk that a caller names: directory sweeps, text reads, sibling lookups."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path, PurePath

# The disposition-aware cumulative supersedes its raw report when both exist.
SARIF_SUFFIXES = (
    "-findings-current.json",
    "-security-audit.json",
    "-container-audit.json",
    "-cloud-config-audit.json",
)


class ReportFiles:
    def collect(self, path: Path) -> list[Path]:
        """The .json files under a directory, or the one file named; none when the path is
        missing. Refuted registers (worklists) and hidden skill-state directories are skipped."""
        if path.is_dir():
            return sorted(
                p
                for p in path.rglob("*.json")
                if not p.name.endswith("-refuted-register.json")
                and not any(part.startswith(".") for part in p.relative_to(path).parts[:-1])
            )
        if path.is_file():
            return [path]
        return []

    def threat_models(self, paths: Sequence[Path]) -> list[Path]:
        """THREAT_MODEL.md and *-threat-model.md under each directory (skipping pipeline scratch
        under any `artifacts/`), and each file named; never a symlink."""
        files: list[Path] = []
        for p in paths:
            if p.is_dir():
                found = sorted({*p.rglob("THREAT_MODEL.md"), *p.rglob("*-threat-model.md")})
                files.extend(f for f in found if "artifacts" not in f.relative_to(p).parts)
            else:
                files.append(p)
        return [f for f in files if not f.is_symlink()]

    def sarif_reports(self, root: Path) -> list[Path]:
        """The reports under `root` to export as SARIF, one per baseline; symlinks and hidden
        directories are skipped."""
        selected: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            top = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not (d.startswith(".") or (top / d).is_symlink())]
            names = set(filenames)
            for fn in sorted(filenames):
                path = top / fn
                if path.is_symlink() or not fn.endswith(SARIF_SUFFIXES):
                    continue
                if not fn.endswith("-findings-current.json") and _superseded(fn, names):
                    continue
                selected.append(path)
        return selected

    def read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def exists(self, path: PurePath) -> bool:
        return Path(path).exists()

    def is_file(self, path: PurePath) -> bool:
        return Path(path).is_file()


def _superseded(name: str, siblings: set[str]) -> bool:
    stem = name[: -len(".json")]
    if f"{stem}-findings-current.json" in siblings:
        return True
    return any(
        stem.endswith(suffix) and f"{stem[: -len(suffix)]}-findings-current.json" in siblings
        for suffix in ("-security-audit", "-cloud-config-audit")
    )
