from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

import sqlalchemy as sa

from traust_core.v1.models.artifacts import Verdict
from traust_core.v1.models.findings import TriageVerdict
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import STORAGE_SCHEMA, SqlRepository, SqlUnitOfWork
from traust_core.v1.repositories.storage import (
    EvidenceRepository,
    InMemoryEvidenceRepository,
    SqlEvidenceRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork


class TriageVerdictRepository(Protocol):
    def add_all(self, verdicts: Sequence[TriageVerdict]) -> None: ...
    def for_binding(self, binding_id: str) -> list[TriageVerdict]: ...
    def for_source_finding(self, source_finding_id: str) -> list[TriageVerdict]: ...
    def true_positives(self, binding_id: str) -> list[TriageVerdict]: ...


class TriageUnitOfWork(UnitOfWork, Protocol):
    evidence: EvidenceRepository
    triage_verdicts: TriageVerdictRepository


triage_verdict = sa.Table(
    "triage_verdict",
    sa.MetaData(schema=STORAGE_SCHEMA),
    sa.Column("binding_id", sa.Text, primary_key=True),
    sa.Column("artifact_digest", sa.Text, nullable=False),
    sa.Column("finding_id", sa.Text, primary_key=True),
    sa.Column("source_finding_id", sa.Text),
    sa.Column("triage_completed", sa.Text, nullable=False),
    sa.Column("verdict", sa.Text, nullable=False),
    sa.Column("severity", sa.Text),
    sa.Column("vote_breakdown", sa.JSON(none_as_null=True)),
    sa.Column("rationale", sa.Text),
)


class SqlTriageVerdictRepository(SqlRepository):
    def add_all(self, verdicts: Sequence[TriageVerdict]) -> None:
        if verdicts:
            rows = [v.model_dump() for v in verdicts]
            self._execute(f"add {len(rows)} verdicts", sa.insert(triage_verdict), rows)

    def _select(self, operation: str, *where: sa.ColumnElement[bool]) -> list[TriageVerdict]:
        stmt = sa.select(triage_verdict).where(*where).order_by(triage_verdict.c.finding_id)
        return [_to_verdict(r) for r in self._execute(operation, stmt).mappings()]

    def for_binding(self, binding_id: str) -> list[TriageVerdict]:
        return self._select(f"for binding {binding_id}", triage_verdict.c.binding_id == binding_id)

    def for_source_finding(self, source_finding_id: str) -> list[TriageVerdict]:
        return self._select(
            f"for source finding {source_finding_id}",
            triage_verdict.c.source_finding_id == source_finding_id,
        )

    def true_positives(self, binding_id: str) -> list[TriageVerdict]:
        return self._select(
            f"true positives in {binding_id}",
            triage_verdict.c.binding_id == binding_id,
            triage_verdict.c.verdict == Verdict.TRUE_POSITIVE,
        )


def _to_verdict(row: Any) -> TriageVerdict:
    return TriageVerdict.model_validate(dict(row))


class SqlTriageUnitOfWork(SqlUnitOfWork):
    evidence: SqlEvidenceRepository
    triage_verdicts: SqlTriageVerdictRepository

    def _open_repositories(self) -> None:
        self.evidence = SqlEvidenceRepository(self.connection)
        self.triage_verdicts = SqlTriageVerdictRepository(self.connection)


class InMemoryTriageVerdictRepository:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], TriageVerdict] = {}

    def add_all(self, verdicts: Sequence[TriageVerdict]) -> None:
        for v in verdicts:
            self._rows[(v.binding_id, v.finding_id)] = v

    def _select(self, keep: Any) -> list[TriageVerdict]:
        return sorted((v for v in self._rows.values() if keep(v)), key=lambda v: v.finding_id)

    def for_binding(self, binding_id: str) -> list[TriageVerdict]:
        return self._select(lambda v: v.binding_id == binding_id)

    def for_source_finding(self, source_finding_id: str) -> list[TriageVerdict]:
        return self._select(lambda v: v.source_finding_id == source_finding_id)

    def true_positives(self, binding_id: str) -> list[TriageVerdict]:
        return self._select(
            lambda v: v.binding_id == binding_id and v.verdict == Verdict.TRUE_POSITIVE
        )


class InMemoryTriageUnitOfWork(InMemoryUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.evidence = InMemoryEvidenceRepository()
        self.triage_verdicts = InMemoryTriageVerdictRepository()
