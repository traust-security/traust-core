"""Reports: one insight view built in one format over one scope, run as an order by the
reports role and published as a file in object storage. The order is the build (`order_id`);
the file is the artifact it produced (`artifact_id`). The last ready build of the same request
answers it again, so object storage serves as the cache; `refresh` builds anew."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.insight import ReportFormat, ViewFilter, ViewName


class ReportStatus(StrEnum):
    QUEUED = "queued"
    BUILDING = "building"
    READY = "ready"
    FAILED = "failed"


class ReportRequest(Model):
    """Which report, in which format, over which scope; `refresh` builds anew even when a
    ready build of the same request exists (a build already in flight is shared)."""

    report: ViewName
    format: ReportFormat = ReportFormat.MARKDOWN
    scope: ViewFilter = Field(default_factory=ViewFilter)
    refresh: bool = False


class ReportInput(Model):
    """The build's input document: the request without `refresh`, scope lists sorted, so
    identical requests are one content-addressed artifact."""

    report: ViewName
    format: ReportFormat
    scope: ViewFilter


class Report(Model):
    """One build of a report: the order that runs it and, once ready, the file it produced."""

    order_id: UUID
    report: ViewName
    format: ReportFormat
    scope: ViewFilter
    status: ReportStatus
    requested_at: datetime
    built_at: datetime | None = None
    artifact_id: UUID | None = None  # the built file, once ready
    reason: str | None = None  # why a build failed
