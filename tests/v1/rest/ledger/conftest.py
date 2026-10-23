"""A ledger-on deployment with decisions appended; alice is an admin, bob is not."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Config, Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.ledger import LedgerConfig

IDENTITY = IdentityConfig(trust_local=True, admins=("alice@example.com",))


@dataclass(frozen=True)
class Ledgered:
    context: Context
    client: TestClient
    repository_id: UUID
    layer_id: UUID
    admin: dict[str, str]
    reader: dict[str, str]


def deployment(home: Path, **ledger: object) -> Context:
    return Context(Config(home=home, identity=IDENTITY, ledger=LedgerConfig.model_validate(ledger)))


@pytest.fixture
def ledgered(tmp_path: Path) -> Iterator[Ledgered]:
    context = deployment(tmp_path)
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository()
        made = [seed.decision() for _ in range(3)]
        uow.commit()
    assert repository.id is not None
    services = context.services()
    assert services.ledger is not None
    receipts = [services.ledger.append_decision(d, repository.id) for d in made]
    layer_id = receipts[-1].checkpoint.layer.id
    assert layer_id is not None
    with TestClient(create_app(context), raise_server_exceptions=False) as client:
        yield Ledgered(
            context,
            client,
            repository.id,
            layer_id,
            bearer(context, "alice@example.com"),
            bearer(context, "bob@example.com"),
        )


def tamper(context: Context, layer_id: UUID) -> None:
    """Rewrite one event behind the app's back (this test's own SQLite file)."""
    with context.database.begin() as conn:
        conn.execute(sa.text("DROP TRIGGER IF EXISTS ledger_events_reject_update"))
        conn.execute(
            sa.text("UPDATE ledger_events SET event_payload = :p WHERE layer_id = :l AND seq = 0"),
            {"p": b'{"forged": true}', "l": str(layer_id)},
        )
