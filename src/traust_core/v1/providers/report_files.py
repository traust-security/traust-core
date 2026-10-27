"""Report files on disk that a caller names: directory sweeps, text reads, sibling lookups."""

from __future__ import annotations

from pathlib import Path, PurePath


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

    def read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def exists(self, path: PurePath) -> bool:
        return Path(path).exists()

    def is_file(self, path: PurePath) -> bool:
        return Path(path).is_file()
