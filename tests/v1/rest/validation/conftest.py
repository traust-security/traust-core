from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.v1.services.test_validation import ValidationHarness
from tests.v1.services.test_validation import engine as engine
from tests.v1.services.test_validation import harness as harness
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig


@pytest.fixture
def context(harness: ValidationHarness, tmp_path: Path) -> Iterator[Context]:
    context = Context(
        Config(
            home=tmp_path / "rest",
            database=DatabaseConfig(url=harness.engine.url.render_as_string(hide_password=False)),
            identity=IdentityConfig(trust_local=True),
            ledger=LedgerConfig(),
        ),
        object_store=harness.objects,
    )
    try:
        yield context
    finally:
        context.database.dispose()
