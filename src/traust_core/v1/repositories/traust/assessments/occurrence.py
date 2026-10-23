from __future__ import annotations

from collections.abc import Collection
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.findings import Occurrence
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

OCCURRENCE = TableSpec(
    TRAUST,
    "occurrence",
    lambda: (
        uuid_column("finding_id"),
        uuid_column("assessment_id"),
        text_column("severity"),
        text_column("cvss_vector", nullable=True),
        sa.Column("cvss_score", sa.Numeric, nullable=True),
        text_column("rule", nullable=True),
    ),
    append_only=True,
)


class OccurrenceRepository(RecordRepository[Occurrence], Protocol):
    def find(self, finding_id: UUID, assessment_id: UUID) -> Occurrence | None: ...
    def list_for_assessment(self, assessment_id: UUID) -> list[Occurrence]: ...
    def list_for_finding(self, finding_id: UUID) -> list[Occurrence]: ...
    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[Occurrence]: ...
    def list_by_ids(self, occurrence_ids: Collection[UUID]) -> list[Occurrence]: ...


class SqlOccurrenceRepository(SqlAppendOnlyRepository[Occurrence]):
    spec = OCCURRENCE
    record = Occurrence

    def find(self, finding_id: UUID, assessment_id: UUID) -> Occurrence | None:
        c = self.table.c
        return self._one(
            f"find {finding_id}/{assessment_id}",
            c.finding_id == finding_id,
            c.assessment_id == assessment_id,
        )

    def list_for_assessment(self, assessment_id: UUID) -> list[Occurrence]:
        return self._many(f"list for {assessment_id}", self.table.c.assessment_id == assessment_id)

    def list_for_finding(self, finding_id: UUID) -> list[Occurrence]:
        return self._many(f"list for finding {finding_id}", self.table.c.finding_id == finding_id)

    def list_for_findings(self, finding_ids: Collection[UUID]) -> list[Occurrence]:
        return self._many(
            f"list for {len(finding_ids)} findings", self.table.c.finding_id.in_(finding_ids)
        )

    def list_by_ids(self, occurrence_ids: Collection[UUID]) -> list[Occurrence]:
        return self._many(
            f"list {len(occurrence_ids)} by id", self.table.c.id.in_(list(occurrence_ids))
        )
