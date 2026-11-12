from __future__ import annotations

from typing import Self
from uuid import UUID

from pydantic import Field, model_validator

from traust_core.v1.models.base import Model


class ClaimLocation(Model):
    path: str = Field(min_length=1)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    symbol: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("a claim location ends before it starts")
        return self


class FindingClaim(Model):
    title: str = Field(min_length=1)
    description: str
    fingerprint_algo: str
    fingerprint: str
    cwes: tuple[str, ...]
    category: str | None
    locations: tuple[ClaimLocation, ...]


class ClaimBase(Model):
    fingerprint_algo: str
    fingerprint: str
    title: str
    claim_decision_id: UUID | None
    occurrence_ids: tuple[UUID, ...]
