from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.example.repository import metadata
from traust_core.v1.repositories import create_database_engine

PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
SQL_BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.integration)]


@contextmanager
def database(kind: str, tmp_path: Path) -> Iterator[Engine]:
    if kind == "postgres" and not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    eng = create_database_engine(PG_URL if kind == "postgres" else f"sqlite:///{tmp_path}/t.db")
    metadata.create_all(eng)
    try:
        yield eng
    finally:
        metadata.drop_all(eng)
        eng.dispose()


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with database(request.param, tmp_path) as eng:
        yield eng
