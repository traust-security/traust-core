from __future__ import annotations

from pydantic import AwareDatetime, Field

from traust_core.v1.models.base import Model


class HarnessMetadata(Model):
    """Current checkout measurements, independent of an audit's historical as_of."""

    measured_at: AwareDatetime
    version: str | None = None
    revision: str | None = None
    commits: int | None = Field(default=None, ge=0)
    releases: int | None = Field(default=None, ge=0)
    source_lines: int | None = Field(default=None, ge=0)
    test_count: int | None = Field(default=None, ge=0)
    limitations: tuple[str, ...] = ()
