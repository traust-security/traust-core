from __future__ import annotations

import os
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.example.repository import metadata
from traust_core.v1 import contracts
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import contract_dialect

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]
CLOCK = FixedClock(datetime(2026, 10, 5, tzinfo=UTC))


def apply_contract_ddl(engine: Engine, area: contracts.Area) -> None:
    apply_schema(engine, contracts.ddl(area, contract_dialect(engine)))


def _engine(kind: str, tmp_path: Path) -> Engine:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    return create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db")


@contextmanager
def database(kind: str, tmp_path: Path) -> Generator[Engine]:
    eng = _engine(kind, tmp_path)
    metadata.create_all(eng)
    try:
        yield eng
    finally:
        metadata.drop_all(eng)
        eng.dispose()


@contextmanager
def storage_db(kind: str, tmp_path: Path) -> Generator[Engine]:
    eng = _engine(kind, tmp_path)
    apply_contract_ddl(eng, "storage")
    try:
        yield eng
    finally:
        if kind == "postgres":
            with eng.begin() as conn:
                conn.exec_driver_sql("DROP SCHEMA traust_storage CASCADE")
        eng.dispose()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with database(request.param, tmp_path) as eng:
        yield eng
