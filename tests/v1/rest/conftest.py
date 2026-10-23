"""A REST client over a real Context; tokens come from its local issuer (no network)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from traust_core.v1.context import Config, Context
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig


@pytest.fixture
def context(tmp_path: Path) -> Context:
    return Context(Config(home=tmp_path, identity=IdentityConfig(trust_local=True)))


@pytest.fixture
def client(context: Context) -> Iterator[TestClient]:
    with TestClient(create_app(context), raise_server_exceptions=False) as c:
        yield c


def bearer(context: Context, identity: str = "alice@example.com") -> dict[str, str]:
    token = context.local_issuer.mint(identity).token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}


def same_as_in_process(body: object, expected: BaseModel) -> None:
    """The HTTP answer is the in-process answer, serialized: routes add nothing."""
    assert body == expected.model_dump(mode="json")
