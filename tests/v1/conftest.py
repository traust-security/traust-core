from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.example import repository as example_repository
from traust_core.v1 import contracts
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import contract_dialect

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]
CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))


def apply_contract_ddl(engine: Engine, area: contracts.Area) -> None:
    apply_schema(engine, contracts.ddl(area, contract_dialect(engine)))


def apply_contract_db(engine: Engine) -> None:
    apply_schema(engine, contracts.database_ddl(contract_dialect(engine)))


def _engine(kind: str, tmp_path: Path) -> Engine:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db")


@contextmanager
def database(
    kind: str, tmp_path: Path, metadata: sa.MetaData = example_repository.metadata
) -> Generator[Engine]:
    if kind == "postgres":
        # A fresh database per test: parallel workers must not share traust_test.
        with _fresh_postgres() as eng:
            metadata.create_all(eng)
            try:
                yield eng
            finally:
                eng.dispose()
        return
    eng = _engine(kind, tmp_path)
    metadata.create_all(eng)
    try:
        yield eng
    finally:
        metadata.drop_all(eng)
        eng.dispose()


@contextmanager
def contract_db(kind: str, tmp_path: Path) -> Generator[Engine]:
    """A fresh database holding the whole contracts db (every namespace).

    The DDL runs once per session into a template; each test gets a copy - a file
    copy on SQLite, CREATE DATABASE ... TEMPLATE on Postgres - so tests stay
    isolated without re-bootstrapping 31 tables and their triggers every time.
    """
    if kind == "postgres":
        with _postgres_copy() as eng:
            yield eng
        return
    target = tmp_path / "contract.db"
    shutil.copyfile(_sqlite_template(), target)
    eng = create_database_engine(f"sqlite:///{target}")
    try:
        yield eng
    finally:
        eng.dispose()


@cache
def _sqlite_template() -> Path:
    path = Path(tempfile.mkdtemp(prefix="traust-contract-")) / "template.db"
    eng = create_database_engine(f"sqlite:///{path}")
    apply_contract_db(eng)
    eng.dispose()
    return path


_PG_TEMPLATE = f"traust_contract_tmpl_{os.getpid()}"


def _pg_admin() -> Engine:
    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return sa.create_engine(PG_URL, isolation_level="AUTOCOMMIT")


@cache
def _postgres_template() -> str:
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {_PG_TEMPLATE} WITH (FORCE)")
        conn.exec_driver_sql(f"CREATE DATABASE {_PG_TEMPLATE}")
    admin.dispose()
    eng = create_database_engine(sa.make_url(PG_URL).set(database=_PG_TEMPLATE))
    apply_contract_db(eng)
    eng.dispose()  # a template database must have no open connections to be copied
    return _PG_TEMPLATE


@contextmanager
def _postgres_copy() -> Generator[Engine]:
    template = _postgres_template()
    name = f"traust_contract_{uuid4().hex[:12]}"
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name} TEMPLATE {template}")
    eng = create_database_engine(sa.make_url(PG_URL).set(database=name))
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


def pytest_sessionfinish(session: pytest.Session) -> None:
    if PG_URL and _postgres_template.cache_info().currsize:
        admin = _pg_admin()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {_PG_TEMPLATE} WITH (FORCE)")
        admin.dispose()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if mark := item.get_closest_marker("todo"):
            item.add_marker(pytest.mark.skip(reason=f"todo({mark.args[0]}): parked"))


@contextmanager
def _fresh_postgres() -> Generator[Engine]:
    name = f"traust_example_{uuid4().hex[:12]}"
    admin = _pg_admin()
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name} TEMPLATE template0")
    eng = create_database_engine(sa.make_url(PG_URL).set(database=name))
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with database(request.param, tmp_path) as eng:
        yield eng
