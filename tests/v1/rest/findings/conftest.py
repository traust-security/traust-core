"""Findings endpoints on SQLite: alice is a verified human; admin may restate."""

from __future__ import annotations

from pathlib import Path

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.services.identity import IdentityConfig

ADMIN = "admin@example.com"
ANALYST = "alice@example.com"


@pytest.fixture
def context(tmp_path: Path) -> Context:
    identity = IdentityConfig(trust_local=True, admins=(ADMIN,))
    return Context(Config(home=tmp_path, identity=identity))
