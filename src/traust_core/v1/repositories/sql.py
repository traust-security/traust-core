from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from types import TracebackType
from typing import Any, Literal, Self

import sqlalchemy as sa
from sqlalchemy.engine import Connection, CursorResult, Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from traust_core.v1.errors import ConflictError, RepositoryError

STORAGE_SCHEMA = "traust_storage"
LEDGER_SCHEMA = "traust_ledger"


def _compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def create_database_engine(url: str | sa.URL) -> Engine:
    engine = sa.create_engine(url, json_serializer=_compact_json)
    if engine.dialect.name != "sqlite":
        return engine

    @sa.event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn: Any, _: Any) -> None:
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    return engine.execution_options(
        schema_translate_map={STORAGE_SCHEMA: None, LEDGER_SCHEMA: None}
    )


def contract_dialect(engine: Engine | Connection) -> Literal["sqlite", "postgres"]:
    return "postgres" if engine.dialect.name == "postgresql" else "sqlite"


class UtcTimestamp(sa.TypeDecorator[datetime]):
    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.Dialect) -> sa.TypeEngine[Any]:
        return dialect.type_descriptor(sa.Text() if dialect.name == "sqlite" else self.impl)

    def process_bind_param(self, value: datetime | None, dialect: sa.Dialect) -> Any:
        return value.isoformat() if value is not None and dialect.name == "sqlite" else value

    def process_result_value(self, value: Any, dialect: sa.Dialect) -> datetime | None:
        return datetime.fromisoformat(value) if isinstance(value, str) else value


def apply_schema(engine: Engine, statements: Iterable[str]) -> None:
    try:
        with engine.begin() as conn:
            for stmt in statements:
                conn.exec_driver_sql(stmt)
    except SQLAlchemyError as e:
        raise RepositoryError(f"apply schema failed: {e}") from e


class SqlUnitOfWork:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._connection: Connection | None = None

    @property
    def connection(self) -> Connection:
        if self._connection is None:
            raise RepositoryError(f"{type(self).__name__}: used outside a 'with' block")
        return self._connection

    def _open_repositories(self) -> None:
        pass

    def __enter__(self) -> Self:
        try:
            self._connection = self._engine.connect()
        except SQLAlchemyError as e:
            raise RepositoryError(f"{type(self).__name__}: connect failed: {e}") from e
        self._open_repositories()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            self.rollback()
        finally:
            self.connection.close()
            self._connection = None

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()


class SqlRepository:
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

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
            return self._connection.execute(statement, bound)
        except IntegrityError as e:
            raise ConflictError(f"{name}: {operation}: {e.orig}") from e
        except SQLAlchemyError as e:
            raise RepositoryError(f"{name}: {operation} failed: {e}") from e


def schema_drift(engine: Engine, metadata: sa.MetaData) -> list[str]:
    inspector = sa.inspect(engine)
    translate = engine.get_execution_options().get("schema_translate_map", {})
    problems: list[str] = []
    for table in metadata.sorted_tables:
        schema = translate.get(table.schema, table.schema)
        if not inspector.has_table(table.name, schema=schema):
            problems.append(f"{table.name}: missing in database")
            continue
        actual = {c["name"]: c for c in inspector.get_columns(table.name, schema=schema)}
        for column in table.columns:
            found = actual.pop(column.name, None)
            if found is None:
                problems.append(f"{table.name}.{column.name}: missing in database")
            elif found["nullable"] != column.nullable and not column.primary_key:
                problems.append(
                    f"{table.name}.{column.name}: nullable {found['nullable']} in database, "
                    f"{column.nullable} in Table"
                )
        problems += [f"{table.name}.{name}: not declared in Table" for name in sorted(actual)]
    return problems
