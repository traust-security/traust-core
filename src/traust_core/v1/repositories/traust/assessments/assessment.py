from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.assessment import Assessment
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

ASSESSMENT = TableSpec(
    TRAUST,
    "assessment",
    lambda: (
        uuid_column("repository_ref_id"),
        uuid_column("image_id", nullable=True),
        uuid_column("baseline_assessment_id", nullable=True),
        uuid_column("run_order_id", nullable=True),
        text_column("kind"),
        text_column("status"),
        text_column("assessor"),
        text_column("assessor_version"),
        timestamp_column("occurred_at"),
    ),
    append_only=True,
)


class AssessmentRepository(RecordRepository[Assessment], Protocol):
    def latest(
        self, repository_ref_id: UUID, kind: str, status: str | None = None
    ) -> Assessment | None: ...
    def latest_for_refs(
        self, repository_ref_ids: Collection[UUID], kind: str, status: str
    ) -> Assessment | None: ...
    def list_for_ref(self, repository_ref_id: UUID) -> list[Assessment]: ...
    def list_for_refs(
        self, repository_ref_ids: Collection[UUID], kind: str | None = None
    ) -> list[Assessment]: ...
    def list_for_run_order(self, run_order_id: UUID) -> list[Assessment]: ...
    def list_by_ids(self, assessment_ids: Collection[UUID]) -> list[Assessment]: ...
    def search(
        self,
        *,
        repository_ref_id: UUID | None = None,
        kind: str | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[Assessment]: ...


class SqlAssessmentRepository(SqlAppendOnlyRepository[Assessment]):
    spec = ASSESSMENT
    record = Assessment

    def latest(
        self, repository_ref_id: UUID, kind: str, status: str | None = None
    ) -> Assessment | None:
        c = self.table.c
        conditions = [c.repository_ref_id == repository_ref_id, c.kind == kind]
        if status is not None:
            conditions.append(c.status == status)
        stmt = (
            self._select()
            .where(*conditions)
            .order_by(c.occurred_at.desc(), c.created_at.desc(), c.id.desc())
            .limit(1)
        )
        row = self._execute(f"latest {kind} for {repository_ref_id}", stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def latest_for_refs(
        self, repository_ref_ids: Collection[UUID], kind: str, status: str
    ) -> Assessment | None:
        if not repository_ref_ids:
            return None
        c = self.table.c
        stmt = (
            self._select()
            .where(
                c.repository_ref_id.in_(list(repository_ref_ids)),
                c.kind == kind,
                c.status == status,
            )
            .order_by(c.occurred_at.desc(), c.created_at.desc(), c.id.desc())
            .limit(1)
        )
        op = f"latest {kind} of {len(repository_ref_ids)} refs"
        row = self._execute(op, stmt).mappings().first()
        return None if row is None else self._to_record(row)

    def list_for_ref(self, repository_ref_id: UUID) -> list[Assessment]:
        c = self.table.c
        return self._many(
            f"list for {repository_ref_id}",
            c.repository_ref_id == repository_ref_id,
            order_by=(c.occurred_at,),
        )

    def list_for_run_order(self, run_order_id: UUID) -> list[Assessment]:
        return self._many(
            f"list for order {run_order_id}", self.table.c.run_order_id == run_order_id
        )

    def list_by_ids(self, assessment_ids: Collection[UUID]) -> list[Assessment]:
        if not assessment_ids:
            return []
        c = self.table.c
        return self._many(f"{len(assessment_ids)} by id", c.id.in_(list(assessment_ids)))

    def search(
        self,
        *,
        repository_ref_id: UUID | None = None,
        kind: str | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int,
        after: tuple[datetime, UUID] | None = None,
    ) -> list[Assessment]:
        """Newest first by occurred_at; `since` inclusive, `until` exclusive."""
        c = self.table.c
        conditions = []
        if since is not None:
            conditions.append(c.occurred_at >= since)
        if until is not None:
            conditions.append(c.occurred_at < until)
        if repository_ref_id is not None:
            conditions.append(c.repository_ref_id == repository_ref_id)
        if kind is not None:
            conditions.append(c.kind == kind)
        if status is not None:
            conditions.append(c.status == status)
        return self._page("search", *conditions, limit=limit, after=after, at="occurred_at")

    def list_for_refs(
        self, repository_ref_ids: Collection[UUID], kind: str | None = None
    ) -> list[Assessment]:
        c = self.table.c
        where = [c.repository_ref_id.in_(repository_ref_ids)]
        if kind is not None:
            where.append(c.kind == kind)
        return self._many(
            f"list {kind or 'all'} for {len(repository_ref_ids)} refs",
            *where,
            order_by=(c.occurred_at,),
        )
