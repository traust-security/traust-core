"""Contract tables, built per dialect.

The contracts DDL places the three namespaces differently per database:
Postgres schemas (`traust_ops.run_order`), SQLite table prefixes in one file
(`ops_run_order`) because FKs do not work across ATTACHed files. A TableSpec
declares a table once; the TableFactory for a dialect builds it with the
right schema and name. Repositories ask the factory for their table, so one
repository class serves both databases.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache
from typing import Any, ClassVar, Generic, Protocol, TypeVar
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from traust_core.v1.errors import NotFoundError, RepositoryError
from traust_core.v1.models.base import AppendOnly, Entity, Model
from traust_core.v1.repositories.sql import (
    Dialect,
    RecordUuid,
    SqlRepository,
    SqlUnitOfWork,
    UtcTimestamp,
    append_only_columns,
    record_columns,
)


@dataclass(frozen=True, slots=True)
class Namespace:
    schema: str
    sqlite_prefix: str = ""

    def locate(self, name: str, dialect: Dialect) -> tuple[str | None, str]:
        if dialect is Dialect.POSTGRES:
            return self.schema, name
        return None, f"{self.sqlite_prefix}{name}"


TRAUST = Namespace("traust")
TRAUST_OPS = Namespace("traust_ops", "ops_")
TRAUST_LEDGER = Namespace("traust_ledger", "ledger_")


@dataclass(frozen=True, slots=True, eq=False)
class TableSpec:
    """One contract table: domain columns only; base columns follow append_only."""

    namespace: Namespace
    name: str
    columns: Callable[[], Sequence[sa.Column[Any]]] = field(repr=False)
    append_only: bool = False

    def build(self, metadata: sa.MetaData, dialect: Dialect) -> sa.Table:
        schema, name = self.namespace.locate(self.name, dialect)
        base = append_only_columns() if self.append_only else record_columns()
        return sa.Table(name, metadata, *base, *self.columns(), schema=schema)


class TableFactory:
    """Every contract table for one dialect, built once on one MetaData."""

    def __init__(self, dialect: Dialect) -> None:
        self.dialect = dialect
        self.metadata = sa.MetaData()
        self._tables: dict[int, sa.Table] = {}

    @classmethod
    @cache
    def for_dialect(cls, dialect: Dialect) -> TableFactory:
        return cls(dialect)

    @classmethod
    def for_bind(cls, bind: Connection | sa.Engine) -> TableFactory:
        return cls.for_dialect(Dialect.of(bind))

    def table(self, spec: TableSpec) -> sa.Table:
        if (table := self._tables.get(id(spec))) is None:
            table = self._tables[id(spec)] = spec.build(self.metadata, self.dialect)
        return table


def uuid_column(name: str, *, nullable: bool = False) -> sa.Column[UUID]:
    return sa.Column(name, RecordUuid, nullable=nullable)


def text_column(name: str, *, nullable: bool = False) -> sa.Column[str]:
    return sa.Column(name, sa.Text, nullable=nullable)


def timestamp_column(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, UtcTimestamp, nullable=nullable)


A = TypeVar("A", bound=AppendOnly)
E = TypeVar("E", bound=Entity)
R = TypeVar("R", bound=Model)

_BASE = frozenset({"id", "created_at", "updated_at"})
# Rows per multi-row statement: well under SQLite's bound-parameter limit.
_BATCH = 500


class RecordRepository(Protocol[R]):
    def add(self, record: R) -> R: ...
    def get(self, record_id: UUID) -> R: ...


class MutableRecordRepository(RecordRepository[E], Protocol[E]):
    def update(self, record: E) -> E: ...


class SqlTableRepository(SqlRepository, Generic[R]):
    """Validated add / get for one contract table; subclasses set spec and record."""

    spec: ClassVar[TableSpec]
    record: ClassVar[type[Any]]

    def __init__(self, connection: Connection, tables: TableFactory | None = None) -> None:
        super().__init__(connection)
        self.table = (tables or TableFactory.for_bind(connection)).table(self.spec)

    def add(self, record: R) -> R:
        record = self._to_record(record)
        saved = self._insert_record(f"add {self.spec.name}", self.table, self._values(record))
        return record.model_copy(update=saved)

    def _insert(self) -> Callable[[sa.Table], Any]:
        return postgresql.insert if self._connection.dialect.name == "postgresql" else sqlite.insert

    def _add_missing(self, operation: str, records: Sequence[R], keys: Sequence[str]) -> None:
        """Insert the records whose natural key isn't stored yet, in bounded batches."""
        for start in range(0, len(records), _BATCH):
            batch = [self._values(r) for r in records[start : start + _BATCH]]
            stmt = (
                self._insert()(self.table)
                .values(batch)
                .on_conflict_do_nothing(index_elements=list(keys))
            )
            self._execute(operation, stmt)

    def _get_or_add(
        self,
        record: R,
        keys: Sequence[str],
        find: Callable[[], R | None],
        *,
        index_where: sa.ColumnElement[bool] | None = None,
    ) -> R:
        return self._get_or_add_with_status(record, keys, find, index_where=index_where)[0]

    def _get_or_add_with_status(
        self,
        record: R,
        keys: Sequence[str],
        find: Callable[[], R | None],
        *,
        index_where: sa.ColumnElement[bool] | None = None,
    ) -> tuple[R, bool]:
        stmt = (
            self._insert()(self.table)
            .values(self._values(record))
            .on_conflict_do_nothing(index_elements=list(keys), index_where=index_where)
            .returning(*self.table.c)
        )
        row = self._execute(f"get or add {self.spec.name}", stmt).mappings().first()
        if row is not None:
            return self._to_record(row), True
        # A separate statement sees the competing insert after it commits on Postgres.
        existing = find()
        if existing is None:
            raise RepositoryError(f"{self.spec.name}: conflicting row disappeared")
        return existing, False

    def get(self, record_id: UUID) -> R:
        found = self._one(f"get {record_id}", self.table.c.id == record_id)
        if found is None:
            raise NotFoundError(f"{self.spec.name} {record_id}")
        return found

    def _values(self, record: R) -> dict[str, Any]:
        return record.model_dump(exclude=_BASE & set(type(record).model_fields))

    def _to_record(self, row: Mapping[str, Any] | R) -> R:
        return self.record.model_validate(dict(row))  # type: ignore[no-any-return]

    def _select(self) -> sa.Select[Any]:
        return sa.select(self.table)

    def _one(self, operation: str, *where: sa.ColumnElement[bool]) -> R | None:
        row = self._execute(operation, self._select().where(*where)).mappings().one_or_none()
        return None if row is None else self._to_record(row)

    def _many_in(
        self, operation: str, column: sa.ColumnElement[Any], values: Collection[Any]
    ) -> list[R]:
        """Rows whose `column` is one of `values`, read in bounded batches."""
        items = list(values)
        return [
            row
            for start in range(0, len(items), _BATCH)
            for row in self._many(operation, column.in_(items[start : start + _BATCH]))
        ]

    def _many(
        self,
        operation: str,
        *where: sa.ColumnElement[bool],
        order_by: Sequence[sa.ColumnElement[Any]] = (),
    ) -> list[R]:
        stmt = (
            self._select()
            .where(*where)
            .order_by(*order_by, self.table.c.created_at, self.table.c.id)
        )
        return [self._to_record(r) for r in self._execute(operation, stmt).mappings()]

    def _page(
        self,
        operation: str,
        *where: sa.ColumnElement[bool],
        limit: int,
        after: tuple[datetime, UUID] | None,
        at: str = "created_at",
        oldest_first: bool = False,
    ) -> list[R]:
        """Keyset page by `at`, newest first (oldest first for a feed), resuming after
        `(at, id)`."""
        c = self.table.c
        key = sa.tuple_(c[at], c.id)
        if after is not None:
            # A row comparison lets the index seek to the cursor instead of filtering old pages.
            where = (*where, key > after if oldest_first else key < after)
        order = (c[at], c.id) if oldest_first else (c[at].desc(), c.id.desc())
        stmt = self._select().where(*where).order_by(*order).limit(limit)
        return [self._to_record(r) for r in self._execute(operation, stmt).mappings()]


class SqlAppendOnlyRepository(SqlTableRepository[A]):
    """Append-only table: add and read; the contracts trigger rejects mutation."""


class SqlMutableRepository(SqlTableRepository[E]):
    def update(self, record: E) -> E:
        record = self._to_record(record)
        if record.id is None:
            raise NotFoundError(f"{self.spec.name}: update needs a saved record")
        saved = self._update_record(
            f"update {record.id}", self.table, record.id, self._values(record)
        )
        return record.model_copy(update=saved)


class SqlTablesUnitOfWork(SqlUnitOfWork):
    """A unit of work whose repositories share the engine dialect's TableFactory."""

    def __init__(self, engine: sa.Engine) -> None:
        super().__init__(engine)
        self.tables = TableFactory.for_bind(engine)
