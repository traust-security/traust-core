from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import copy_context
from datetime import UTC, datetime
from enum import StrEnum
from types import TracebackType
from typing import Any, Self
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.engine import Connection, CursorResult, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.compiler import compiles

from traust_core.v1.errors import ConflictError, NotFoundError, RepositoryError

_WRITE_INTENT = "traust_write_intent"


class Dialect(StrEnum):
    """The two databases the contracts DDL ships for; names match its directories."""

    SQLITE = "sqlite"
    POSTGRES = "postgres"

    @classmethod
    def of(cls, bind: Engine | Connection) -> Dialect:
        return cls.POSTGRES if bind.dialect.name == "postgresql" else cls.SQLITE


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def create_database_engine(url: str | sa.URL) -> Engine:
    engine = sa.create_engine(url, json_serializer=_compact_json, hide_parameters=True)
    if engine.dialect.name != "sqlite":
        return engine

    @sa.event.listens_for(engine, "connect")
    def _sqlite_functions(dbapi_conn: Any, _: Any) -> None:
        dbapi_conn.execute("PRAGMA foreign_keys = ON")
        # Contracts' uuid(): ext/misc/uuid.c in other drivers, registered here.
        dbapi_conn.create_function("uuid", 0, lambda: str(uuid4()))

    return engine


def contract_dialect(engine: Engine | Connection) -> Dialect:
    return Dialect.of(engine)


class UtcTimestamp(sa.TypeDecorator[datetime]):
    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.Dialect) -> sa.TypeEngine[Any]:
        return dialect.type_descriptor(sa.Text() if dialect.name == "sqlite" else self.impl)

    def process_bind_param(self, value: datetime | None, dialect: sa.Dialect) -> Any:
        if value is None or dialect.name != "sqlite":
            return value
        # Contracts' TEXT format (millisecond precision, Z) so ordering survives mixed writers.
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        stamp = value.astimezone(UTC)
        return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{stamp.microsecond // 1000:03d}Z"

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> datetime | None:
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)  # SQLite CURRENT_TIMESTAMP is UTC without offset
        return value


class RecordUuid(sa.TypeDecorator[UUID]):
    # Native UUID on Postgres; on SQLite the hyphenated text uuid() writes,
    # so lookups match the stored form.
    impl = sa.Uuid
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.Dialect) -> sa.TypeEngine[Any]:
        return dialect.type_descriptor(sa.Text() if dialect.name == "sqlite" else self.impl)

    def process_bind_param(self, value: UUID | None, dialect: sa.Dialect) -> Any:
        return str(value) if value is not None and dialect.name == "sqlite" else value

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> UUID | None:
        return UUID(value) if isinstance(value, str) else value


class _GeneratedUuid(sa.FunctionElement[UUID]):
    name = "generated_uuid"
    inherit_cache = True


@compiles(_GeneratedUuid, "postgresql")
def _postgres_uuid(element: Any, compiler: Any, **kw: Any) -> str:
    return "gen_random_uuid()"


@compiles(_GeneratedUuid, "sqlite")
def _sqlite_uuid(element: Any, compiler: Any, **kw: Any) -> str:
    return "uuid()"


class _DbNow(sa.FunctionElement[datetime]):
    name = "db_now"
    inherit_cache = True


@compiles(_DbNow, "postgresql")
def _postgres_now(element: Any, compiler: Any, **kw: Any) -> str:
    return "statement_timestamp()"


@compiles(_DbNow, "sqlite")
def _sqlite_now(element: Any, compiler: Any, **kw: Any) -> str:
    # Contracts' TEXT timestamp format, millisecond precision.
    return "strftime('%Y-%m-%dT%H:%M:%fZ','now')"


class UtcMonth(sa.FunctionElement[str]):
    """YYYY-MM of a timestamp column, in UTC, on either dialect."""

    type = sa.Text()
    name = "utc_month"
    inherit_cache = True


@compiles(UtcMonth, "postgresql")
def _postgres_month(element: Any, compiler: Any, **kw: Any) -> str:
    return f"to_char({compiler.process(element.clauses, **kw)} AT TIME ZONE 'UTC', 'YYYY-MM')"


@compiles(UtcMonth, "sqlite")
def _sqlite_month(element: Any, compiler: Any, **kw: Any) -> str:
    # Contracts' TEXT timestamps are already UTC ISO-8601.
    return f"substr({compiler.process(element.clauses, **kw)}, 1, 7)"


def record_columns() -> tuple[sa.Column[UUID], sa.Column[datetime], sa.Column[datetime]]:
    """Mutable base columns: UUIDv4 id; the touch trigger keeps updated_at."""
    return (
        sa.Column("id", RecordUuid, primary_key=True, server_default=_GeneratedUuid()),
        sa.Column("created_at", UtcTimestamp, nullable=False, server_default=_DbNow()),
        sa.Column("updated_at", UtcTimestamp, nullable=False, server_default=_DbNow()),
    )


def append_only_columns() -> tuple[sa.Column[UUID], sa.Column[datetime]]:
    """Append-only base columns: UUIDv4 id and created_at, no updated_at."""
    return (
        sa.Column("id", RecordUuid, primary_key=True, server_default=_GeneratedUuid()),
        sa.Column("created_at", UtcTimestamp, nullable=False, server_default=_DbNow()),
    )


def apply_schema(engine: Engine, statements: Iterable[str]) -> None:
    try:
        with engine.begin() as conn:
            # Raw cursor, no params: a '%' in DDL text is never parsed as a placeholder.
            cursor = conn.connection.cursor()
            try:
                for stmt in statements:
                    cursor.execute(stmt)
            finally:
                cursor.close()
    except SQLAlchemyError as e:
        raise RepositoryError("apply schema failed", operation="apply_schema") from e


class SqlUnitOfWork:
    """Re-entrant shared transaction; a failed nested scope makes it rollback-only."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._connection: Connection | None = None
        self._depth = 0
        self._rollback_only = False
        self._after_commit: list[Callable[[], None]] = []

    @property
    def connection(self) -> Connection:
        if self._connection is None:
            raise RepositoryError(f"{type(self).__name__}: used outside a 'with' block")
        return self._connection

    def _open_repositories(self) -> None:
        pass

    def __enter__(self) -> Self:
        if self._depth == 0:
            try:
                self._connection = self._engine.connect()
            except SQLAlchemyError as e:
                name = type(self).__name__
                raise RepositoryError(f"{name}: connect failed", operation=f"{name}.connect") from e
            self._open_repositories()
            self.connection.info[_WRITE_INTENT] = False
            self._rollback_only = False
        self._depth += 1
        return self

    @contextmanager
    def write(self) -> Iterator[Self]:
        """Take SQLite write intent before admission reads; ordinary reads remain unchanged."""
        with self:
            connection = self.connection
            if connection.dialect.name == "sqlite":
                driver = connection.connection.driver_connection
                if driver.in_transaction and not connection.info.get(_WRITE_INTENT):
                    raise RepositoryError(
                        "SQLite read transaction cannot safely acquire write intent"
                    )
                if not driver.in_transaction:
                    try:
                        connection.exec_driver_sql("BEGIN IMMEDIATE")
                    except SQLAlchemyError as error:
                        raise RepositoryError(
                            "cannot acquire SQLite write intent", operation="SqlUnitOfWork.write"
                        ) from error
                    connection.info[_WRITE_INTENT] = True
            yield self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self._rollback_only = True
        self._depth -= 1
        if self._depth > 0:
            return  # nested use: the outer owner owns the transaction
        try:
            self.rollback()
        finally:
            self.connection.close()
            self._connection = None

    def after_commit(self, event: Callable[[], None]) -> None:
        """Emit a service outcome only when the owning transaction has committed."""
        context = copy_context()
        if self._depth:
            self._after_commit.append(lambda: context.run(event))
        else:
            context.run(event)

    def commit(self) -> None:
        """Only the outer owner commits; a failed transaction requires rollback first."""
        connection = self.connection
        if self._depth == 1:
            if self._rollback_only:
                raise RepositoryError("cannot commit a rollback-only transaction; roll back first")
            connection.commit()
            connection.info[_WRITE_INTENT] = False
            events, self._after_commit = self._after_commit, []
            for event in events:
                event()

    def rollback(self) -> None:
        self._after_commit.clear()
        self.connection.rollback()
        self.connection.info[_WRITE_INTENT] = False
        self._rollback_only = False


class SqlRepository:
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def _insert_record(
        self, operation: str, table: sa.Table, values: Mapping[str, Any]
    ) -> dict[str, UUID | datetime]:
        """INSERT domain columns; returns the database-generated base columns the table has."""
        returning = [table.c.id, table.c.created_at]
        if "updated_at" in table.c:
            returning.append(table.c.updated_at)
        stmt = sa.insert(table).values(**values).returning(*returning)
        return dict(self._execute(operation, stmt).mappings().one())

    def _update_record(
        self, operation: str, table: sa.Table, record_id: UUID, values: Mapping[str, Any]
    ) -> dict[str, UUID | datetime]:
        """UPDATE by id; returns the saved base columns (the touch trigger keeps updated_at)."""
        stmt = (
            sa.update(table)
            .where(table.c.id == record_id)
            .values(**values)
            .returning(table.c.id, table.c.created_at, table.c.updated_at)
        )
        row = self._execute(operation, stmt).mappings().first()
        if row is None:
            raise NotFoundError(f"{type(self).__name__}: {operation}: not found")
        saved = dict(row)
        if self._connection.dialect.name == "sqlite":
            # SQLite's AFTER UPDATE trigger fires after RETURNING is computed.
            saved["updated_at"] = (
                self._execute(
                    f"reread {record_id}",
                    sa.select(table.c.updated_at).where(table.c.id == record_id),
                )
                .scalars()
                .one()
            )
        return saved

    def _execute(
        self,
        operation: str,
        stmt: sa.Executable | str,
        params: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    ) -> CursorResult[Any]:
        statement = sa.text(stmt) if isinstance(stmt, str) else stmt
        name = type(self).__name__
        if isinstance(params, Sequence):
            bound: Any = [dict(p) for p in params]
        else:
            bound = dict(params or {})
        try:
            result = self._connection.execute(statement, bound)
            if self._connection.dialect.name == "sqlite" and isinstance(
                statement, sa.sql.dml.UpdateBase
            ):
                self._connection.info[_WRITE_INTENT] = True
            return result
        except IntegrityError as e:
            raise ConflictError(f"{name}: constraint violation") from e
        except SQLAlchemyError as e:
            raise RepositoryError(
                f"{name}: database operation failed", operation=f"{name}.execute"
            ) from e
