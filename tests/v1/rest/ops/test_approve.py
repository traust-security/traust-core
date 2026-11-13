"""The approve door over REST: a person releases anything, a granted machine what its
`recording.start` scope covers — the same authority the service test states, carried by
HTTP unchanged."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.models.operations import RecordingStartScope
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.identity import IdentityConfig

URL = "/v1/orders/{order_id}/approve"


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    with SqlTraustUnitOfWork(engine) as uow:
        repository = Seed(uow).repository()
        uow.commit()
    assert repository.id is not None
    context = Context(
        Config(
            home=tmp_path,
            identity=IdentityConfig(trust_local=True),
            recording=RecordingConfig(
                start=(
                    RecordingStartScope(
                        principal="machine:runner-7",
                        assets=("full_audit",),
                        repository_ids=(repository.id,),
                    ),
                )
            ),
        )
    )
    context.__dict__["database"] = engine
    return context


@pytest.fixture
def awaiting(context: Context) -> dict[str, str]:
    """One full_audit order held for approval on the granted repository."""
    scope = context.config.recording.start[0]
    with SqlTraustUnitOfWork(context.database) as uow:
        order = Seed(uow).run_order(
            asset="full_audit", state="awaiting_approval", repository_id=scope.repository_ids[0]
        )
        uow.commit()
    assert order.id is not None
    return {"id": str(order.id), "repository": str(scope.repository_ids[0])}


def test_a_person_approves_an_awaiting_order(
    context: Context, client: TestClient, awaiting: dict[str, str]
) -> None:
    approved = client.post(
        URL.format(order_id=awaiting["id"]), headers=bearer(context, "operator@example.com")
    )
    assert approved.status_code == 200 and approved.json()["state"] == "queued"


def test_a_granted_machine_approves_what_its_scope_covers(
    context: Context, client: TestClient, awaiting: dict[str, str]
) -> None:
    approved = client.post(URL.format(order_id=awaiting["id"]), headers=runner(context))
    assert approved.status_code == 200 and approved.json()["state"] == "queued"
    manifest = client.get(f"/v1/orders/{awaiting['id']}/manifest", headers=runner(context))
    assert manifest.status_code == 200
    assert manifest.json()["approval"]["approver"] == "machine:runner-7"


def test_a_machine_outside_its_scope_is_refused(
    context: Context, client: TestClient, awaiting: dict[str, str]
) -> None:
    """An order on a repository the grant does not name: the door refuses, the order stays
    held — a machine never learns to widen its own scope."""
    with SqlTraustUnitOfWork(context.database) as uow:
        other_repository = Seed(uow).repository(url="https://github.com/org/other")
        other = Seed(uow).run_order(
            asset="full_audit", state="awaiting_approval", repository_id=other_repository.id
        )
        uow.commit()
    assert other.id is not None
    refused = client.post(URL.format(order_id=str(other.id)), headers=runner(context))
    assert refused.status_code == 403
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.run_orders.get(other.id).state == "awaiting_approval"


def test_an_ungranted_machine_is_refused_before_the_order_is_read(
    context: Context, client: TestClient
) -> None:
    """A machine the config granted nothing hears forbidden, not found — no existence
    oracle on an unknown order id."""
    refused = client.post(URL.format(order_id=uuid4()), headers=runner(context, "other-runner"))
    assert refused.status_code == 403
    assert refused.headers["content-type"] == "application/problem+json"
