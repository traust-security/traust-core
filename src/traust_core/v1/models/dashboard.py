"""The dashboard query and results: the metrics-query shapes. The vocabulary
(subjects, dimensions, measures) is defined here — the single source — and
flows to the SDK through the OpenAPI document generated from these models."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Subject(StrEnum):
    """What a query counts; each subject carries its own dimensions and measures."""

    FINDINGS = "findings"
    REVIEW_ITEMS = "review_items"
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


class Measure(StrEnum):
    """What a query counts or sums; the catalog serves a subset."""

    FINDINGS = "findings"
    REPOSITORIES = "repositories"
    OLDEST_OPEN_AGE = "oldest_open_age"
    REVIEW_ITEMS = "review_items"
    MEDIAN_OPEN_DAYS = "median_open_days"


class DashboardOrder(BaseModel):
    model_config = ConfigDict(extra="forbid")

    by: Measure | Dimension
    desc: bool = False


# The request's list bounds: a whole-estate grant (366 repositories) clears the id cap.
_ID_CAP = 1000
_WhereValues = Annotated[tuple[str, ...], Field(max_length=100)]


class DashboardQuery(BaseModel):
    """One metrics query: a subject, the repository filter that trims the answer
    to a caller's access, and an allow-listed combination of measures and
    dimensions. Empty ids with no other filter is the whole estate."""

    model_config = ConfigDict(extra="forbid")

    subject: Subject
    repository_ids: tuple[UUID, ...] = Field(default=(), max_length=_ID_CAP)
    product_ids: tuple[UUID, ...] = Field(default=(), max_length=_ID_CAP)
    team_ids: tuple[UUID, ...] = Field(default=(), max_length=_ID_CAP)
    measures: tuple[Measure, ...] = Field(min_length=1)
    group_by: tuple[Dimension, ...] = Field(default=(), max_length=3)
    where: dict[Dimension, _WhereValues] = Field(default={}, max_length=8)
    order: tuple[DashboardOrder, ...] = Field(default=(), max_length=3)
    limit: int = Field(default=50, ge=1, le=1000)

    @field_validator("where")
    @classmethod
    def _no_nul_in_values(
        cls, where: dict[Dimension, tuple[str, ...]]
    ) -> dict[Dimension, tuple[str, ...]]:
        """Postgres text cannot carry NUL: refuse it here, not as a driver error."""
        for dimension, values in where.items():
            if any("\x00" in value for value in values):
                raise ValueError(f"a where value for {dimension.value} contains a NUL byte")
        return where


class DashboardRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: dict[Dimension, str | None]
    measures: dict[Measure, float | None]


class DashboardResults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: Subject
    rows: tuple[DashboardRow, ...] = Field(max_length=1000)
