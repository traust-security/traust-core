from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, NewType, TypeVar
from uuid import UUID

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


class CodeSpan(Model):
    path: RepoPath
    line: int | None = None

    @classmethod
    def parse(cls, raw: str) -> CodeSpan:
        raise NotImplementedError("stub: replaces check_location_paths.py")


class PageRequest(Dto):
    limit: int = 100
    cursor: Cursor | None = None


class Page(Dto, Generic[T]):
    items: tuple[T, ...]
    next: Cursor | None = None
