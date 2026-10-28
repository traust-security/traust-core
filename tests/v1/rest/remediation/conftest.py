from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.services.test_verification import make_context
from traust_core.v1.context import Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.services.identity import IdentityConfig


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    return make_context(
        engine,
        tmp_path,
        identity=IdentityConfig(trust_local=True),
        recording=RecordingConfig(verification=("verify",)),
    )
