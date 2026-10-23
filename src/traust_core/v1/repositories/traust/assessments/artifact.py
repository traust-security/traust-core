from __future__ import annotations

from typing import Protocol
from uuid import UUID

from traust_core.v1.models.assessment import Artifact
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    uuid_column,
)

ARTIFACT = TableSpec(
    TRAUST,
    "artifact",
    lambda: (
        uuid_column("assessment_id", nullable=True),
        text_column("digest"),
        text_column("kind"),
        text_column("uri"),
    ),
    append_only=True,
)


class ArtifactRepository(RecordRepository[Artifact], Protocol):
    def get_or_add(self, record: Artifact) -> Artifact: ...

    def find(self, assessment_id: UUID | None, digest: str) -> Artifact | None:
        """By (assessment, digest); assessment None = an imported artifact."""
        ...

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]: ...


class SqlArtifactRepository(SqlAppendOnlyRepository[Artifact]):
    spec = ARTIFACT
    record = Artifact

    def get_or_add(self, record: Artifact) -> Artifact:
        imported = record.assessment_id is None
        return self._get_or_add(
            record,
            ["digest"] if imported else ["assessment_id", "digest"],
            lambda: self.find(record.assessment_id, record.digest),
            index_where=self.table.c.assessment_id.is_(None) if imported else None,
        )

    def find(self, assessment_id: UUID | None, digest: str) -> Artifact | None:
        c = self.table.c
        produced = (
            c.assessment_id.is_(None)
            if assessment_id is None
            else (c.assessment_id == assessment_id)
        )
        return self._one(f"find {digest}", produced, c.digest == digest)

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]:
        conditions = [self.table.c.assessment_id == assessment_id]
        if kind is not None:
            conditions.append(self.table.c.kind == kind)
        return self._many(f"list for {assessment_id}", *conditions)
