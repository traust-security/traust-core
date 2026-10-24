from __future__ import annotations

from collections.abc import Collection
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
    def list_by_ids(self, artifact_ids: Collection[UUID]) -> list[Artifact]: ...

    def find(self, assessment_id: UUID | None, digest: str) -> Artifact | None:
        """By (assessment, digest); assessment None = an imported artifact."""
        ...

    def latest_imported(self, kind: str) -> Artifact | None: ...
    def list_imported(self, kind: str, *, limit: int) -> list[Artifact]:
        """Imported documents of a kind, newest first."""
        ...

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]: ...
    def list_for_assessments(
        self, assessment_ids: Collection[UUID], kinds: Collection[str] | None
    ) -> list[Artifact]: ...


class SqlArtifactRepository(SqlAppendOnlyRepository[Artifact]):
    spec = ARTIFACT
    record = Artifact

    def list_by_ids(self, artifact_ids: Collection[UUID]) -> list[Artifact]:
        return self._many(f"list {len(artifact_ids)} artifacts", self.table.c.id.in_(artifact_ids))

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

    def latest_imported(self, kind: str) -> Artifact | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.assessment_id.is_(None), c.kind == kind)
            .order_by(c.created_at.desc(), c.id.desc())
            .limit(1)
        )
        row = self._execute(f"latest imported {kind}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_imported(self, kind: str, *, limit: int) -> list[Artifact]:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.assessment_id.is_(None), c.kind == kind)
            .order_by(c.created_at.desc(), c.id.desc())
            .limit(limit)
        )
        rows = self._execute(f"list imported {kind}", stmt).mappings()
        return [self._to_record(r) for r in rows]

    def list_for_assessment(
        self, assessment_id: UUID, *, kind: str | None = None
    ) -> list[Artifact]:
        conditions = [self.table.c.assessment_id == assessment_id]
        if kind is not None:
            conditions.append(self.table.c.kind == kind)
        return self._many(f"list for {assessment_id}", *conditions)

    def list_for_assessments(
        self, assessment_ids: Collection[UUID], kinds: Collection[str] | None
    ) -> list[Artifact]:
        c = self.table.c
        conditions = [c.assessment_id.in_(assessment_ids)]
        if kinds is not None:
            conditions.append(c.kind.in_(kinds))
        return self._many(
            f"list {sorted(kinds) if kinds is not None else 'all kinds'} "
            f"for {len(assessment_ids)} assessments",
            *conditions,
        )
