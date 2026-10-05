from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

import sqlalchemy as sa

from traust_core.v1.domain.clock import Clock
from traust_core.v1.domain.model import Model
from traust_core.v1.domain.storage import BindingContext
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import STORAGE_SCHEMA, SqlRepository, SqlUnitOfWork
from traust_core.v1.repositories.storage import (
    EvidenceRepository,
    InMemoryEvidenceRepository,
    SqlEvidenceRepository,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork
from traust_core.v1.security.artifacts import TriageArtifact, Verdict
from traust_core.v1.services.storage import RecordResult, bind_artifact


class TriageVerdict(Model):
    binding_id: str
    artifact_digest: str
    finding_id: str
    source_finding_id: str | None = None
    triage_completed: str
    verdict: str
    severity: str | None = None
    vote_breakdown: Mapping[str, int] | None = None
    rationale: str | None = None


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


def verdicts_from(triage: TriageArtifact, binding_id: str, digest: str) -> list[TriageVerdict]:
    return [
        TriageVerdict(
            binding_id=binding_id,
            artifact_digest=digest,
            finding_id=f.id,
            source_finding_id=f.orig_id,
            triage_completed=triage.triage_completed,
            verdict=f.verdict,
            severity=f.severity,
            vote_breakdown=_votes(f.vote_breakdown),
            rationale=f.rationale,
        )
        for f in triage.findings
    ]


def _votes(view: Any) -> dict[str, int] | None:
    if view is None:
        return None
    return {
        k: getattr(view, k)
        for k in ("true_positive", "hardening", "false_positive", "cannot_verify")
    }


def record_triage(
    uow: TriageUnitOfWork,
    triage: TriageArtifact,
    clock: Clock,
    context: BindingContext,
    references: Sequence[str] = (),
) -> RecordResult:
    with uow:
        result = bind_artifact(uow, triage.schema, triage.payload, clock, context, references)
        if not result.already_bound:
            uow.triage_verdicts.add_all(verdicts_from(triage, result.binding_id, result.digest))
        uow.commit()
    return result
