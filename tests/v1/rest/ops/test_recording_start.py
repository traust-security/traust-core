from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import RecordingConfig
from traust_core.v1.errors import ForbiddenError, ValidationError
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.identity import Credential, Principal
from traust_core.v1.models.operations import (
    OrderFilter,
    OrderRequest,
    RecordingStartScope,
    RunOrder,
    StartRecordingRequest,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.identity import IdentityConfig

URL = "/v1/orders/start"


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
                verification=("verify",),
                start=(
                    RecordingStartScope(
                        principal="machine:runner-7",
                        assets=("verify",),
                        repository_ids=(repository.id,),
                    ),
                ),
            ),
        )
    )
    context.__dict__["database"] = engine
    return context


def request(context: Context) -> StartRecordingRequest:
    return StartRecordingRequest(
        order=OrderRequest(
            asset="verify",
            priority=1,
            repository_id=context.config.recording.start[0].repository_ids[0],
        ),
        lease_seconds=300,
    )


def principal(context: Context) -> Principal:
    assert context.identity is not None
    token = context.local_issuer.mint("runner-7", machine=True).token
    return context.identity.authenticate(Credential(token=token))


def orders(context: Context) -> Page[RunOrder]:
    return context.services().ops.list(
        OrderFilter(states=("planned", "queued", "awaiting_approval", "leased"), asset="verify"),
        PageRequest(),
    )


def test_verified_machine_starts_its_scoped_run_and_can_record(
    context: Context, client: TestClient
) -> None:
    body = request(context)
    response = client.post(URL, json=body.model_dump(mode="json"), headers=runner(context))
    assert response.status_code == 200, response.text
    order = context.services().ops.get(UUID(response.json()["id"]))
    same_as_in_process(response.json(), order)
    assert (order.state, order.lease_holder, order.requested_by) == (
        "leased",
        "machine:runner-7",
        "machine:runner-7",
    )
    assert order.started_at is not None and order.lease_expires_at is not None
    assert order.lease_expires_at - order.started_at == timedelta(seconds=300)
    assert order.id is not None and order.repository_id is not None
    provenance = Provenance(
        run_id=order.id,
        source=SourceType.VERIFICATION_REPORT,
        occurred_at=order.started_at,
    )
    with context.services().ops.recording(
        order.id, principal(context), "verification", order.repository_id, provenance
    ):
        pass
    assert context.services().ops.get(order.id) == order


@pytest.mark.parametrize("state", ["planned", "queued"])
def test_start_reuses_waiting_order_without_replacing_its_admission_fields(
    context: Context, client: TestClient, state: str
) -> None:
    body = request(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        held = Seed(uow).run_order(
            asset="verify", repository_id=body.order.repository_id, state=state, priority=8
        )
        uow.commit()
    response = client.post(URL, json=body.model_dump(mode="json"), headers=runner(context))
    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(held.id)
    assert response.json()["priority"] == held.priority
    assert response.json()["requested_by"] == held.requested_by
    same_as_in_process(response.json(), context.services().ops.get(held.id))
    assert len(orders(context).items) == 1


@pytest.mark.parametrize("state", ["leased", "awaiting_approval"])
def test_start_never_steals_an_active_lease_or_bypasses_approval(
    context: Context, client: TestClient, state: str
) -> None:
    body = request(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        held = Seed(uow).run_order(
            asset="verify",
            repository_id=body.order.repository_id,
            state=state,
            **(
                {
                    "lease_holder": "machine:another-runner",
                    "lease_expires_at": T0 + timedelta(days=1),
                }
                if state == "leased"
                else {}
            ),
        )
        uow.commit()
    response = client.post(URL, json=body.model_dump(mode="json"), headers=runner(context))
    assert response.status_code == 409, response.text
    assert context.services().ops.get(held.id) == held


@pytest.mark.parametrize(
    "fault",
    ["human", "unrelated", "no-start-grant", "no-kind-grant", "asset", "repository", "fleet"],
)
def test_start_requires_server_owned_identity_asset_and_repository_capabilities(
    context: Context, client: TestClient, fault: str
) -> None:
    body = request(context).model_dump(mode="json")
    headers = runner(context)
    if fault == "human":
        headers = bearer(context)
    elif fault == "unrelated":
        headers = runner(context, "another-runner")
    elif fault in {"no-start-grant", "no-kind-grant"}:
        field = "start" if fault == "no-start-grant" else "verification"
        context.config = context.config.model_copy(
            update={"recording": context.config.recording.model_copy(update={field: ()})}
        )
    elif fault == "asset":
        body["order"]["asset"] = "unconfigured"
    elif fault == "repository":
        body["order"]["repository_id"] = str(uuid4())
    else:
        body["order"]["repository_id"] = None
    before = orders(context)
    response = client.post(URL, json=body, headers=headers)
    assert response.status_code == 403, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert orders(context) == before


def test_even_an_explicitly_granted_repository_must_exist(
    context: Context, client: TestClient
) -> None:
    missing = uuid4()
    scope = context.config.recording.start[0].model_copy(update={"repository_ids": (missing,)})
    context.config = context.config.model_copy(
        update={"recording": context.config.recording.model_copy(update={"start": (scope,)})}
    )
    before = orders(context)
    response = client.post(
        URL, json=request(context).model_dump(mode="json"), headers=runner(context)
    )
    assert response.status_code == 404, response.text
    assert orders(context) == before


@pytest.mark.parametrize("seconds", [0, -1, 86401])
def test_start_rejects_unbounded_or_nonpositive_leases(
    context: Context, client: TestClient, seconds: int
) -> None:
    body = request(context).model_dump(mode="json")
    body["lease_seconds"] = seconds
    assert client.post(URL, json=body, headers=runner(context)).status_code == 422
    with pytest.raises(ValidationError):
        context.services().ops.start_recording(
            request(context).order, principal(context), timedelta(seconds=seconds)
        )
    assert not orders(context).items


@pytest.mark.parametrize("field", ["worker", "lease_holder", "principal", "recording_kind"])
def test_start_body_cannot_supply_worker_identity_or_capabilities(
    context: Context, client: TestClient, field: str
) -> None:
    body = request(context).model_dump(mode="json")
    body[field] = "machine:somebody-else"
    assert client.post(URL, json=body, headers=runner(context)).status_code == 422
    assert not orders(context).items


def test_start_needs_authentication(context: Context, client: TestClient) -> None:
    assert client.post(URL, json=request(context).model_dump(mode="json")).status_code == 401
    assert not orders(context).items


def test_in_process_start_rejects_unverified_machine(context: Context) -> None:
    unverified = principal(context).model_copy(update={"verified_by": None})
    with pytest.raises(ForbiddenError, match="verified machine"):
        context.services().ops.start_recording(
            request(context).order, unverified, timedelta(minutes=5)
        )
    assert not orders(context).items


def test_start_correlates_native_order_in_access_log(
    context: Context, client: TestClient, tmp_path: Path
) -> None:
    context.configure_logging()
    response = client.post(
        URL,
        json=request(context).model_dump(mode="json"),
        headers={**runner(context), "X-Request-ID": "native-start"},
    )
    assert response.status_code == 200, response.text
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "traust.log").read_text().splitlines()
    ]
    (access,) = [record for record in records if record["logger"] == "traust_core.rest.access"]
    assert (access["request_id"], access["order_id"]) == ("native-start", response.json()["id"])
    spec = client.get("/openapi.json").json()
    operation = spec["paths"][URL]["post"]
    assert operation["operationId"] == "start_v1_orders_start_post"
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/StartRecordingRequest"
    }
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RunOrder"
    }
