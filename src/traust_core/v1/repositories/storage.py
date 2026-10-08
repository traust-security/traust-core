from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from traust_core.v1.models.storage import ArtifactBinding, BindingContext, Evidence
from traust_core.v1.repositories.memory import InMemoryUnitOfWork
from traust_core.v1.repositories.sql import (
    STORAGE_SCHEMA,
    SqlRepository,
    SqlUnitOfWork,
    UtcTimestamp,
)
from traust_core.v1.repositories.unit_of_work import UnitOfWork

metadata = sa.MetaData(schema=STORAGE_SCHEMA)

artifact_evidence = sa.Table(
    "artifact_evidence",
    metadata,
    sa.Column("digest", sa.Text, primary_key=True),
    sa.Column("byte_size", sa.BigInteger, nullable=False),
    sa.Column("first_ingested_at", UtcTimestamp, nullable=False),
)

artifact_binding = sa.Table(
    "artifact_binding",
    metadata,
    sa.Column("binding_id", sa.Text, primary_key=True),
    sa.Column("artifact_digest", sa.Text, nullable=False),
    sa.Column("artifact_name", sa.Text, nullable=False),
    sa.Column("artifact_role", sa.Text),
    sa.Column("scope_id", sa.Text, nullable=False),
    sa.Column("subject_id", sa.Text),
    sa.Column("run_id", sa.Text),
    sa.Column("layer_id", sa.Text),
    sa.Column("supersedes_binding_id", sa.Text),
    sa.Column("bound_at", UtcTimestamp, nullable=False),
)

artifact_location = sa.Table(
    "artifact_location",
    metadata,
    sa.Column("binding_id", sa.Text, primary_key=True),
    sa.Column("reference", sa.Text, primary_key=True),
    sa.Column("registered_at", UtcTimestamp, nullable=False),
)


class EvidenceRepository(Protocol):
    def find_binding(self, binding_id: str) -> ArtifactBinding | None: ...
    def add(self, evidence: Evidence, binding: ArtifactBinding) -> None: ...
    def add_locations(self, binding_id: str, references: Sequence[str], at: datetime) -> None: ...


class StorageUnitOfWork(UnitOfWork, Protocol):
    evidence: EvidenceRepository


class SqlEvidenceRepository(SqlRepository):
    def _insert_ignore(self, table: sa.Table, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        insert = (
            postgresql.insert if self._connection.dialect.name == "postgresql" else sqlite.insert
        )
        self._execute(f"add {table.name}", insert(table).values(rows).on_conflict_do_nothing())

    def find_binding(self, binding_id: str) -> ArtifactBinding | None:
        stmt = (
            sa.select(artifact_binding, artifact_evidence.c.byte_size)
            .join(
                artifact_evidence, artifact_evidence.c.digest == artifact_binding.c.artifact_digest
            )
            .where(artifact_binding.c.binding_id == binding_id)
        )
        row = self._execute(f"get binding {binding_id}", stmt).mappings().first()
        if row is None:
            return None
        refs = self._execute(
            f"get locations {binding_id}",
            sa.select(artifact_location.c.reference)
            .where(artifact_location.c.binding_id == binding_id)
            .order_by(artifact_location.c.registered_at, artifact_location.c.reference),
        ).scalars()
        return _to_binding(row, tuple(refs))

    def add(self, evidence: Evidence, binding: ArtifactBinding) -> None:
        self._insert_ignore(artifact_evidence, [evidence.model_dump()])
        ctx = binding.context
        self._execute(
            f"add binding {binding.binding_id}",
            sa.insert(artifact_binding).values(
                binding_id=binding.binding_id,
                artifact_digest=binding.artifact_digest,
                artifact_name=binding.artifact_name,
                artifact_role=ctx.role,
                scope_id=ctx.scope_id,
                subject_id=ctx.subject_id,
                run_id=ctx.run_id,
                layer_id=ctx.layer_id,
                supersedes_binding_id=ctx.supersedes_binding_id,
                bound_at=binding.bound_at,
            ),
        )

    def add_locations(self, binding_id: str, references: Sequence[str], at: datetime) -> None:
        self._insert_ignore(
            artifact_location,
            [{"binding_id": binding_id, "reference": r, "registered_at": at} for r in references],
        )


def _to_binding(row: Any, references: tuple[str, ...]) -> ArtifactBinding:
    return ArtifactBinding(
        binding_id=row["binding_id"],
        artifact_digest=row["artifact_digest"],
        artifact_name=row["artifact_name"],
        context=BindingContext(
            scope_id=row["scope_id"],
            subject_id=row["subject_id"],
            run_id=row["run_id"],
            layer_id=row["layer_id"],
            role=row["artifact_role"],
            supersedes_binding_id=row["supersedes_binding_id"],
        ),
        bound_at=row["bound_at"],
        references=references,
        byte_size=row["byte_size"],
    )


class SqlStorageUnitOfWork(SqlUnitOfWork):
    evidence: SqlEvidenceRepository

    def _open_repositories(self) -> None:
        self.evidence = SqlEvidenceRepository(self.connection)


class InMemoryEvidenceRepository:
    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._bindings: dict[str, ArtifactBinding] = {}
        self._locations: dict[str, dict[str, datetime]] = {}

    def find_binding(self, binding_id: str) -> ArtifactBinding | None:
        binding = self._bindings.get(binding_id)
        if binding is None:
            return None
        locations = self._locations.get(binding_id, {})
        refs = tuple(r for r, _ in sorted(locations.items(), key=lambda kv: (kv[1], kv[0])))
        size = self._evidence[binding.artifact_digest].byte_size
        return binding.model_copy(update={"references": refs, "byte_size": size})

    def add(self, evidence: Evidence, binding: ArtifactBinding) -> None:
        self._evidence.setdefault(evidence.digest, evidence)
        self._bindings[binding.binding_id] = binding

    def add_locations(self, binding_id: str, references: Sequence[str], at: datetime) -> None:
        for ref in references:
            self._locations.setdefault(binding_id, {}).setdefault(ref, at)


class InMemoryStorageUnitOfWork(InMemoryUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.evidence = InMemoryEvidenceRepository()
