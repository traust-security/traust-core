"""The dashboard query and results: the metrics-query shapes. The vocabulary
(subjects, dimensions, measures) is defined here — the single source — and
flows to the SDK through the OpenAPI document generated from these models."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class Subject(StrEnum):
    """What a query counts; each subject carries its own dimensions and measures."""

    FINDINGS = "findings"
    REVIEW_ITEMS = "review_items"
    WORK_ITEMS = "work_items"
    REPOSITORIES = "repositories"


class Dimension(StrEnum):
    """The axes a query breaks its answer down by; the catalog serves a subset."""

    REPOSITORY = "repository"
    PRODUCT = "product"
    TEAM = "team"
    STATE = "state"
    SEVERITY = "severity"
    CATEGORY = "category"
    DECIDED = "decided"
    SLA_STATUS = "sla_status"
    AGE_BUCKET = "age_bucket"
    FIRST_SEEN_WEEK = "first_seen_week"
    CHANGED_WEEK = "changed_week"
    REASON = "reason"
    STATUS = "status"
    STRATEGY = "strategy"


class Measure(StrEnum):
    """What a query counts or sums; the catalog serves a subset."""

    FINDINGS = "findings"
    REPOSITORIES = "repositories"
    CVSS_SUM = "cvss_sum"
    OLDEST_OPEN_AGE = "oldest_open_age"
    REVIEW_ITEMS = "review_items"
    WORK_ITEMS = "work_items"
    MEDIAN_OPEN_DAYS = "median_open_days"


class DashboardOrder(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by: Measure | Dimension
    desc: bool = False


class DashboardQuery(BaseModel):
    """One metrics query: a subject, the repository filter that trims the answer
    to a caller's access, and an allow-listed combination of measures and
    dimensions. Empty ids with no other filter is the whole estate."""

    model_config = ConfigDict(extra="forbid")

    subject: Subject
    repository_ids: tuple[UUID, ...] = ()
    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
    measures: tuple[Measure, ...] = Field(min_length=1)
    group_by: tuple[Dimension, ...] = Field(default=(), max_length=3)
    where: dict[Dimension, tuple[str, ...]] = Field(default={}, max_length=8)
    order: tuple[DashboardOrder, ...] = Field(default=(), max_length=3)
    limit: int = Field(default=50, ge=1, le=1000)


class DashboardRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: dict[Dimension, str | None]
    measures: dict[Measure, float | None]


class DashboardResults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: Subject
    rows: tuple[DashboardRow, ...] = Field(max_length=1000)


class DashboardPreset(BaseModel):
    """A named, code-defined query a card references by id. The query's
    repository filter stays empty — the caller's grant fills it at run time."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    description: str
    query: DashboardQuery


class DashboardPresetQuery(BaseModel):
    """The access trim for running a preset: the caller's repositories,
    expanded through products and teams exactly like an ad-hoc query."""

    model_config = ConfigDict(extra="forbid")

    repository_ids: tuple[UUID, ...] = ()
    product_ids: tuple[UUID, ...] = ()
    team_ids: tuple[UUID, ...] = ()
