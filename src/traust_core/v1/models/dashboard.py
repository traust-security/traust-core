"""The dashboard query and results: the metrics-query shapes, typed from the
contracts schema (nothing hand-copied — the vocabulary is the schema's)."""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from traust_core.v1 import contracts


def _vocabulary(key: str) -> dict[str, str]:
    """The query schema's inline enum as enum members: value -> value."""
    schema = contracts.view_schema("dashboard-query")
    node = schema["properties"][key]
    values = node["enum"] if "enum" in node else node["items"]["enum"]
    return {str(value).upper().replace("-", "_"): str(value) for value in values}


Subject = StrEnum("Subject", _vocabulary("subject"))
Dimension = StrEnum("Dimension", _vocabulary("group_by"))
Measure = StrEnum("Measure", _vocabulary("measures"))


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
