from __future__ import annotations

from datetime import date

from pydantic import AwareDatetime, Field

from traust_core.v1.models.base import Dto, Model


class ReachabilityWatch(Dto):
    id: str = Field(min_length=1)
    question: str = Field(min_length=1)
    why_it_matters: str | None = None
    checked: date | None = None
    last_answer: str | None = None
    on_fire: str | None = None


class ReachabilityReview(Dto):
    reviewed: AwareDatetime | date | None
    review_cadence_days: int = Field(default=92, gt=0, strict=True)
    reviewer: str | None = Field(default=None, min_length=1)
    watch: tuple[ReachabilityWatch, ...] = ()


class LanguageCoverageRow(Model):
    language: str
    dominant: int
    present: int
    dependency_ecosystem: str | None
    reachability_engines: tuple[str, ...]
    no_dependencies_reason: str | None


class LanguageCoverage(Model):
    repositories: int
    measured: int
    unmeasured: int
    unknown: int
    unavailable: int
    languages: tuple[LanguageCoverageRow, ...]
