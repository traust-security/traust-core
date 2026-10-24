from __future__ import annotations

from typing import Protocol
from uuid import UUID

import sqlalchemy as sa

from traust_core.v1.models.ledger import Layer
from traust_core.v1.repositories.tables import (
    TRAUST_LEDGER,
    MutableRecordRepository,
    SqlMutableRepository,
    TableSpec,
    text_column,
    uuid_column,
)

LAYERS = TableSpec(
    TRAUST_LEDGER,
    "layers",
    lambda: (
        uuid_column("repository_id"),
        text_column("line", nullable=True),
        text_column("merkle_root", nullable=True),
        sa.Column("merkle_epoch", sa.Integer, nullable=True),
        sa.Column("merkle_size", sa.Integer, nullable=True),
        text_column("merkle_root_signature", nullable=True),
        text_column("merkle_signing_method"),
        sa.Column("merkle_signature_format", sa.Integer, nullable=True),
        text_column("merkle_frontier", nullable=True),
    ),
)


class LayerRepository(MutableRecordRepository[Layer], Protocol):
    def list_for_repository(self, repository_id: UUID) -> list[Layer]: ...

    def list_after(self, layer_id: UUID | None, limit: int) -> list[Layer]:
        """Layers in id order after ``layer_id``: a walk of every layer on the primary key."""
        ...

    def find_for_update(self, repository_id: UUID) -> Layer | None:
        """The repository layer (line null), row-locked until the transaction ends."""
        ...


class SqlLayerRepository(SqlMutableRepository[Layer]):
    spec = LAYERS
    record = Layer

    def list_for_repository(self, repository_id: UUID) -> list[Layer]:
        return self._many(f"list for {repository_id}", self.table.c.repository_id == repository_id)

    def list_after(self, layer_id: UUID | None, limit: int) -> list[Layer]:
        c = self.table.c
        stmt = self._select().order_by(c.id).limit(limit)
        if layer_id is not None:
            stmt = stmt.where(c.id > layer_id)
        return [self._to_record(r) for r in self._execute("list after", stmt).mappings()]

    def find_for_update(self, repository_id: UUID) -> Layer | None:
        c = self.table.c
        stmt = (
            self._select()
            .where(c.repository_id == repository_id, c.line.is_(None))
            .with_for_update()
        )
        row = self._execute(f"lock layer for {repository_id}", stmt).mappings().one_or_none()
        return None if row is None else self._to_record(row)
