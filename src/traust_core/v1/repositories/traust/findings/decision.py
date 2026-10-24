from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import sqlalchemy as sa
from pydantic import TypeAdapter
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from traust_core.v1.errors import RepositoryError
from traust_core.v1.models.findings import Decision
from traust_core.v1.models.vocabulary import Severity, Validity
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

_WRITE_SEVERITY = TypeAdapter(Severity | None)


class DecisionRepository(RecordRepository[Decision], Protocol):
    def add_statement(self, decision: Decision) -> Decision: ...

    def find_by_statement(self, finding_id: UUID, statement_key: str) -> Decision | None:
        """The idempotency key: a retried or re-spelled statement is the same decision."""
        ...

    def list_for_finding(self, finding_id: UUID) -> list[Decision]: ...
    def list_for_findings(
        self, finding_ids: Collection[UUID], until: datetime | None = None
    ) -> list[Decision]:
        """Decisions on these findings, those made after `until` left out."""
        ...

    def list_since(self, since: datetime, limit: int) -> list[Decision]: ...
    def list_finding_ids_with_validity(self, validity: Validity) -> list[UUID]:
        """Findings any decision ever judged `validity`: the candidates for that folded answer."""
        ...


class SqlDecisionRepository(SqlAppendOnlyRepository[Decision]):
    spec = DECISION
    record = Decision

    def _values(self, record: Decision) -> dict[str, Any]:
        severity = _WRITE_SEVERITY.validate_python(record.severity)
        values = super()._values(record)
        values["severity"] = severity
        return values

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

    def list_for_findings(
        self, finding_ids: Collection[UUID], until: datetime | None = None
    ) -> list[Decision]:
        c = self.table.c
        where = [c.finding_id.in_(finding_ids)]
        if until is not None:
            where.append(c.occurred_at <= until)
        return self._many(
            f"list for {len(finding_ids)} findings", *where, order_by=(c.occurred_at,)
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

    def list_finding_ids_with_validity(self, validity: Validity) -> list[UUID]:
        c = self.table.c
        stmt = sa.select(c.finding_id).where(c.validity == str(validity)).distinct()
        return list(self._execute(f"findings judged {validity}", stmt).scalars())
