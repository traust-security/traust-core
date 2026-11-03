from __future__ import annotations

import csv
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.input_segments import (
    InputInventoryRelation,
    InputSegment,
    InputSegmentInventory,
)
from traust_core.v1.models.values import HttpsRepoUrl

_REPO_URL = TypeAdapter(HttpsRepoUrl)
_KINDS = ("groups", "release-payload", "catalog", "services")
_URL_COLUMNS = ("GitHub URL", "URL")


@dataclass(frozen=True)
class _Segment:
    name: str
    kind: str = "groups"
    label: str | None = None


class InputSegments:
    """Read declared inventory segments and their source hierarchy without storing graph rows."""

    def __init__(self, root: Path, load: Callable[[str], list[object]]) -> None:
        self._root = root
        self._load = load

    def read(self) -> InputSegmentInventory:
        if not self._root.is_dir():
            raise ConfigError(f"reading input segments: {self._root} is not a directory")
        declared = self._declarations()
        try:
            present = {
                path.name: path
                for path in self._root.iterdir()
                if path.is_dir() and not path.name.startswith(".")
            }
        except OSError as e:
            raise ConfigError(f"listing input segments in {self._root}: {e}") from e
        names = [name for name in declared if name in present]
        names.extend(sorted(present.keys() - set(declared)))
        segments: list[InputSegment] = []
        hierarchy: list[InputInventoryRelation] = []
        for name in names:
            rows = self._relations(present[name], declared.get(name, _Segment(name)))
            segments.append(
                InputSegment(
                    name=name, repository_urls=tuple(sorted({r.repository_url for r in rows}))
                )
            )
            hierarchy.extend(rows)
        return InputSegmentInventory(segments=tuple(segments), hierarchy=tuple(hierarchy))

    def _declarations(self) -> dict[str, _Segment]:
        path = self._root / "inventory.yaml"
        try:
            documents = self._load(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeError, ValidationError) as e:
            raise ConfigError(f"reading input segment descriptor {path}: {e}") from e
        if len(documents) > 1:
            raise ConfigError(f"{path}: expected one inventory document")
        document = documents[0] if documents else None
        if document is None:
            return {}
        if not isinstance(document, dict):
            raise ConfigError(f"{path}: top level must be a mapping")
        segments = document.get("segments")
        if segments is None:
            return {}
        if not isinstance(segments, dict):
            raise ConfigError(f"{path}: segments must be a mapping")
        declared: dict[str, _Segment] = {}
        for name, spec in segments.items():
            if not isinstance(name, str) or not name.strip():
                raise ConfigError(f"{path}: segment names must be nonblank text")
            if spec is None:
                spec = {}
            if not isinstance(spec, (str, dict)):
                raise ConfigError(f"{path}: segments.{name} must be a mapping or kind string")
            kind = spec if isinstance(spec, str) else spec.get("kind", "groups")
            if kind not in _KINDS:
                raise ConfigError(f"{path}: segments.{name}.kind={kind!r}; expected {_KINDS}")
            label = spec.get("label") if isinstance(spec, dict) else None
            if label is not None and (not isinstance(label, str) or not label.strip()):
                raise ConfigError(f"{path}: segments.{name}.label must be nonblank text")
            declared[name] = _Segment(name, kind, label)
        return declared

    def _relations(self, directory: Path, segment: _Segment) -> tuple[InputInventoryRelation, ...]:
        found: list[InputInventoryRelation] = []
        try:
            paths = sorted(directory.rglob("*-repos.csv"))
        except OSError as e:
            raise ConfigError(f"listing repository inventories in {directory}: {e}") from e
        for path in paths:
            if path.name.startswith("owners"):
                continue
            try:
                with path.open(encoding="utf-8-sig", newline="") as stream:
                    rows = csv.reader(stream, strict=True)
                    header = next((row for row in rows if row), ())
                    if not header:
                        continue
                    columns = [header.index(column) for column in _URL_COLUMNS if column in header]
                    if not columns:
                        raise ConfigError(f"{path}: expected a GitHub URL or URL column")
                    for row in rows:
                        if len(row) > len(header):
                            raise ConfigError(f"{path}:{rows.line_num}: too many CSV fields")
                        raw = next(
                            (row[i].strip() for i in columns if i < len(row) and row[i].strip()),
                            "",
                        )
                        if not raw:
                            continue
                        try:
                            url = str(_REPO_URL.validate_python(raw))
                        except PydanticValidationError as e:
                            raise ConfigError(
                                f"{path}:{rows.line_num}: invalid repository URL: {e}"
                            ) from e
                        values = dict(zip(header, row, strict=False))
                        found.append(self._relation(directory, path, segment, url, values))
            except (OSError, UnicodeError, csv.Error) as e:
                raise ConfigError(f"reading repository inventory {path}: {e}") from e
        return tuple(dict.fromkeys(found))

    def _relation(
        self, directory: Path, path: Path, segment: _Segment, url: str, row: dict[str, str]
    ) -> InputInventoryRelation:
        parts = path.relative_to(directory).parts
        stem = path.name.removesuffix("-repos.csv").removesuffix("-payload")
        product = parts[0] if len(parts) > 1 else stem
        version = release = None
        if segment.kind == "catalog":
            version = parts[1] if len(parts) > 2 else None
        elif segment.kind == "release-payload" and len(parts) == 1:
            release = stem.removeprefix(f"{segment.name}-")
            product = None
        category = (row.get("Category") or "").strip() or None
        return InputInventoryRelation(
            segment=segment.name,
            segment_label=segment.label or segment.name.title(),
            repository_url=url,
            source=str(path.relative_to(self._root)),
            product=product,
            version=version,
            release=release,
            category=category,
            branch=(row.get("Source Branch") or row.get("Branch") or "").strip() or None,
            sub_service=(row.get("App/Sub-Service") or "").strip() or None,
            resource_type=(row.get("Resource Type") or "").strip() or None,
        )
