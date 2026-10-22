from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from traust_core.v1.errors import RepositoryError
from traust_core.v1.models.findings import Decision
from traust_core.v1.repositories.tables import (
    TRAUST,
    RecordRepository,
    SqlAppendOnlyRepository,
    TableSpec,
    text_column,
    timestamp_column,
    uuid_column,
)

DECISION = TableSpec(
    TRAUST,
    "decision",
    lambda: (
        uuid_column("finding_id"),
        uuid_column("assessment_id", nullable=True),
        uuid_column("fixed_repository_ref_id", nullable=True),
        uuid_column("repository_ref_id", nullable=True),
        uuid_column("restates_id", nullable=True),
        uuid_column("artifact_id", nullable=True),
        text_column("statement_key"),
        text_column("validity", nullable=True),
        text_column("resolution", nullable=True),
        text_column("evidence_grade", nullable=True),
        text_column("reason", nullable=True),
        text_column("severity", nullable=True),
        text_column("source_channel", nullable=True),
        text_column("actor", nullable=True),
        text_column("rationale", nullable=True),
        text_column("ticket", nullable=True),
        sa.Column("auto_accept_tier", sa.Boolean, nullable=False),
        timestamp_column("occurred_at"),
    ),
    append_only=True,
)


class DecisionRepository(RecordRepository[Decision], Protocol):
    def add_statement(self, decision: Decision) -> Decision: ...

    def find_by_statement(self, finding_id: UUID, statement_key: str) -> Decision | None:
        """The idempotency key: a retried or re-spelled statement is the same decision."""
        ...

    def list_for_finding(self, finding_id: UUID) -> list[Decision]: ...
    def list_since(self, since: datetime, limit: int) -> list[Decision]: ...


class SqlDecisionRepository(SqlAppendOnlyRepository[Decision]):
    spec = DECISION
    record = Decision

    def add_statement(self, decision: Decision) -> Decision:
        decision = self._to_record(decision)
        insert = postgres_insert if self._connection.dialect.name == "postgresql" else sqlite_insert
        stmt = (
            insert(self.table)
            .values(**self._values(decision))
            .on_conflict_do_nothing(
                index_elements=[self.table.c.finding_id, self.table.c.statement_key]
            )
            .returning(*self.table.c)
        )
        row = self._execute("add statement", stmt).mappings().one_or_none()
        if row is not None:
            return self._to_record(row)
        existing = self.find_by_statement(decision.finding_id, decision.statement_key)
        if existing is None:
            raise RepositoryError("decision statement conflicted without a visible original row")
        return existing

    def find_by_statement(self, finding_id: UUID, statement_key: str) -> Decision | None:
        c = self.table.c
        return self._one(
            f"find {statement_key}", c.finding_id == finding_id, c.statement_key == statement_key
        )

    def list_for_finding(self, finding_id: UUID) -> list[Decision]:
        c = self.table.c
        return self._many(
            f"list for {finding_id}", c.finding_id == finding_id, order_by=(c.occurred_at,)
        )

    def list_since(self, since: datetime, limit: int) -> list[Decision]:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.occurred_at > since)
            .order_by(c.occurred_at, c.created_at)
            .limit(limit)
        )
        return [self._to_record(r) for r in self._execute(f"since {since}", stmt).mappings()]
