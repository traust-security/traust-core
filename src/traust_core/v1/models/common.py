from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Generic, NewType, TypeVar
from uuid import UUID

from pydantic import Field, JsonValue, SerializerFunctionWrapHandler, model_serializer

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.vocabulary import SourceType

T = TypeVar("T")

Sha256 = NewType("Sha256", str)
ArtifactName = NewType("ArtifactName", str)
RepoPath = NewType("RepoPath", str)
Cursor = NewType("Cursor", str)


class TimeBucket(StrEnum):
    DAY = "day"
    WEEK = "week"
    MONTH = "month"

    def window_of(self, at: datetime) -> TimeWindow:
        """The UTC day, ISO week (from Monday) or calendar month containing `at`, end exclusive."""
        if self is TimeBucket.MONTH:
            return TimeWindow.month_of(at)
        day = at.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        if self is TimeBucket.DAY:
            return TimeWindow(start=day, end=day + timedelta(days=1))
        start = day - timedelta(days=day.weekday())
        return TimeWindow(start=start, end=start + timedelta(weeks=1))


class TimeWindow(Model):
    start: datetime
    end: datetime

    @classmethod
    def month_of(cls, at: datetime) -> TimeWindow:
        """The UTC calendar month containing `at`, end exclusive."""
        start = at.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = (
            start.replace(year=start.year + 1, month=1)
            if start.month == 12
            else start.replace(month=start.month + 1)
        )
        return cls(start=start, end=end)


class ArtifactRef(Model):
    id: UUID
    name: ArtifactName
    digest: Sha256


class Provenance(Model):
    run_id: UUID
    artifact: ArtifactRef | None = None
    source: SourceType
    occurred_at: datetime


MAX_PATH_LEN = 200
_REPO_ROOT = frozenset({".", "/", "./", "/.", "/./"})
_LINES = re.compile(r"(\d+)(?:-\d+)?")


FILE_BYTES_SHA256 = "file-bytes-sha256/v1"


class CodeHash(Model):
    algorithm: str = Field(min_length=1)
    digest: str = Field(min_length=1)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.algorithm == FILE_BYTES_SHA256 and not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise ValidationError(f"{self.algorithm}: expected a lowercase SHA-256 digest")


class CodeSpan(Model):
    path: RepoPath
    line: int | None = None
    symbol: str | None = Field(default=None, min_length=1)
    hashes: tuple[CodeHash, ...] = ()

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)
        if not self.hashes:
            data.pop("hashes", None)
        return data

    @classmethod
    def parse(cls, raw: str) -> CodeSpan:
        """`path`, `path:line` or `path:start-end` (the first line kept). A path must name an
        artifact: a repo-root marker collapses finding identity to (repo, '', cwe)."""
        path, sep, lines = raw.strip().rpartition(":")
        found = _LINES.fullmatch(lines) if sep else None
        if found is None:
            path = raw.strip()
        if path in _REPO_ROOT or not path.removeprefix("./"):
            raise ValidationError(
                f"location {raw!r} is the repo root: name the artifact (an absent SECURITY.md "
                "is still 'SECURITY.md') or use a contracts repo-scope pseudo-path"
            )
        if "\n" in path or len(path) > MAX_PATH_LEN:
            raise ValidationError(f"location path is not a path (newline or over {MAX_PATH_LEN})")
        return cls(
            path=RepoPath(path.removeprefix("./")), line=int(found.group(1)) if found else None
        )


class ToolTarget(StrEnum):
    CHECKOUT = "checkout"
    SBOM = "sbom"
    IMAGE = "image"
    SYMBOLS = "symbols"


class SymbolQuery(Dto):
    """The vulnerable symbols a reachability tool looks for, and the checkout it looks in."""

    workspace: Path
    names: tuple[str, ...] = Field(min_length=1)


class ToolRequest(Dto):
    """What one deterministic tool runs over: exactly one target, plus the tool's own params."""

    workspace: Path | None = None
    sbom: Path | None = None
    image: str | None = Field(default=None, min_length=1)
    symbols: SymbolQuery | None = None
    params: dict[str, JsonValue] = Field(default_factory=dict)

    # In __init__, not a validator: pydantic would wrap the typed error in its own.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        named = [t for t in ToolTarget if getattr(self, _TARGET_FIELD[t]) is not None]
        if len(named) != 1:
            raise ValidationError(
                f"a tool request names exactly one target of {[t.value for t in ToolTarget]}, "
                f"got {[t.value for t in named]}"
            )

    @property
    def target(self) -> ToolTarget:
        return next(t for t in ToolTarget if getattr(self, _TARGET_FIELD[t]) is not None)

    def checkout(self) -> Path:
        """The checkout to run over; ValidationError when the request names another target."""
        if self.workspace is None:
            raise ValidationError(f"this tool runs over a checkout, not a {self.target.value}")
        return self.workspace


_TARGET_FIELD = {
    ToolTarget.CHECKOUT: "workspace",
    ToolTarget.SBOM: "sbom",
    ToolTarget.IMAGE: "image",
    ToolTarget.SYMBOLS: "symbols",
}


class PageRequest(Dto):
    limit: int = 100
    cursor: Cursor | None = None

    def position(self) -> tuple[datetime, UUID] | None:
        """Where the page resumes; rejects a non-positive limit."""
        if self.limit <= 0:
            raise ValidationError("page limit must be positive")
        return decode_cursor(self.cursor)


class Page(Dto, Generic[T]):
    items: tuple[T, ...]
    next: Cursor | None = None

    @classmethod
    def of(
        cls, rows: Sequence[T], limit: int, key: Callable[[T], tuple[datetime, UUID]]
    ) -> Page[T]:
        """A page from `limit + 1` keyset rows: the extra row only signals a next page."""
        items = tuple(rows[:limit])
        return cls(items=items, next=encode_cursor(*key(items[-1])) if len(rows) > limit else None)


def every_item(fetch: Callable[[PageRequest], Page[T]], limit: int = 1000) -> Iterator[T]:
    """Every item of a paged read, following its cursor page by page."""
    page = PageRequest(limit=limit)
    while True:
        found = fetch(page)
        yield from found.items
        if found.next is None:
            return
        page = PageRequest(limit=limit, cursor=found.next)


def encode_cursor(occurred_at: datetime, record_id: UUID) -> Cursor:
    """Keyset pagination position: a timestamp, tie-broken by id."""
    return Cursor(f"{occurred_at.isoformat()}|{record_id}")


def decode_cursor(cursor: Cursor | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    raw_at, sep, raw_id = cursor.partition("|")
    try:
        if not sep:
            raise ValueError("missing separator")
        return datetime.fromisoformat(raw_at), UUID(raw_id)
    except ValueError as e:
        raise ValidationError(f"malformed cursor: {cursor!r}") from e
