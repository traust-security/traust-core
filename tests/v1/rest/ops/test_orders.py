from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import OrderFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

CLAIM = {"lease_seconds": 300}


def seed_orders(context: Context, **kw: object) -> list:
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).run_order(**kw)
        uow.commit()
    return made


# claim -------------------------------------------------------------------------------------------


def test_a_runner_claims_the_next_queued_order(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        first = seed.run_order(priority=1)
        seed.run_order(priority=5)
        uow.commit()
    body = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    assert body["id"] == str(first.id)
    assert (body["state"], body["lease_holder"]) == ("leased", "machine:runner-7")


def test_claim_returns_204_when_nothing_is_queued(context: Context, client: TestClient) -> None:
    claimed = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context))
    assert claimed.status_code == 204 and claimed.content == b""


def test_claim_filters_by_asset(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        seed.run_order(asset="audit")
        wanted = seed.run_order(asset="feeds_cache", lane=None)
        uow.commit()
    body = {"lease_seconds": 300, "assets": ["feeds_cache"]}
    claimed = client.post("/v1/orders/claim", json=body, headers=runner(context)).json()
    assert claimed["id"] == str(wanted.id)


def test_a_person_cannot_claim(context: Context, client: TestClient) -> None:
    seed_orders(context)
    denied = client.post("/v1/orders/claim", json=CLAIM, headers=bearer(context))
    assert denied.status_code == 403
    assert denied.headers["content-type"] == "application/problem+json"


def test_claim_without_a_token_is_401(context: Context, client: TestClient) -> None:
    unauthenticated = client.post("/v1/orders/claim", json=CLAIM)
    assert unauthenticated.status_code == 401


def test_claim_rejects_a_non_positive_lease(context: Context, client: TestClient) -> None:
    bad = client.post("/v1/orders/claim", json={"lease_seconds": 0}, headers=runner(context))
    assert bad.status_code == 422


# heartbeat ---------------------------------------------------------------------------------------


def test_heartbeat_extends_the_lease(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    beat = client.post(
        f"/v1/orders/{order['id']}/heartbeat", json={"lease_seconds": 600}, headers=runner(context)
    ).json()
    assert beat["lease_expires_at"] > order["lease_expires_at"]


def test_heartbeat_unknown_order_is_404(context: Context, client: TestClient) -> None:
    gone = client.post(
        f"/v1/orders/{uuid4()}/heartbeat", json={"lease_seconds": 600}, headers=runner(context)
    )
    assert gone.status_code == 404


def test_heartbeat_an_unleased_order_is_409(context: Context, client: TestClient) -> None:
    order = seed_orders(context)
    conflict = client.post(
        f"/v1/orders/{order.id}/heartbeat", json={"lease_seconds": 600}, headers=runner(context)
    )
    assert conflict.status_code == 409


def test_heartbeat_by_another_runner_is_409(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context, "runner-a")).json()
    conflict = client.post(
        f"/v1/orders/{order['id']}/heartbeat",
        json={"lease_seconds": 600},
        headers=runner(context, "runner-b"),
    )
    assert conflict.status_code == 409


# complete ----------------------------------------------------------------------------------------


def test_complete_finishes_the_runners_order(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    done = client.post(
        f"/v1/orders/{order['id']}/complete",
        json={"result": {"outcome": "succeeded"}},
        headers=runner(context),
    ).json()
    assert done["state"] == "succeeded" and done["lease_holder"] is None


def test_complete_is_idempotent(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    url = f"/v1/orders/{order['id']}/complete"
    body = {"result": {"outcome": "failed", "reason": "runner-crashed"}}
    first = client.post(url, json=body, headers=runner(context)).json()
    again = client.post(url, json=body, headers=runner(context)).json()
    # a retried complete returns the same finished order, never re-finishing it
    assert again["id"] == first["id"] and again["started_at"] == first["started_at"]
    assert (again["state"], again["reason"], again["lease_holder"]) == (
        "failed",
        "runner-crashed",
        None,
    )


def test_complete_an_unleased_order_is_409(context: Context, client: TestClient) -> None:
    order = seed_orders(context)
    conflict = client.post(
        f"/v1/orders/{order.id}/complete",
        json={"result": {"outcome": "succeeded"}},
        headers=runner(context),
    )
    assert conflict.status_code == 409


def test_complete_rejects_an_unknown_outcome(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    bad = client.post(
        f"/v1/orders/{order['id']}/complete",
        json={"result": {"outcome": "exploded"}},
        headers=runner(context),
    )
    assert bad.status_code == 422


# reads -------------------------------------------------------------------------------------------


def test_list_orders_matches_in_process(context: Context, client: TestClient) -> None:
    seed_orders(context)
    listed = client.get("/v1/orders", params={"states": "queued"}, headers=bearer(context))
    expected = context.services().ops.list(
        OrderFilter(states=("queued",)),
        PageRequest(limit=100),  # type: ignore[arg-type]
    )
    same_as_in_process(listed.json(), expected)


def test_list_pages_by_created_at(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        for _ in range(3):
            seed.run_order()
            uow.commit()  # distinct created_at
    seen, cursor = [], None
    while True:
        params = {"states": "queued", "limit": 2, **({"cursor": cursor} if cursor else {})}
        page = client.get("/v1/orders", params=params, headers=bearer(context)).json()
        seen += [o["id"] for o in page["items"]]
        if not (cursor := page["next"]):
            break
    assert len(seen) == 3 and len(set(seen)) == 3


def test_list_without_an_indexed_filter_is_422(context: Context, client: TestClient) -> None:
    empty = client.get("/v1/orders", headers=bearer(context))
    assert empty.status_code == 422


def test_get_one_order_and_an_unknown_id(context: Context, client: TestClient) -> None:
    order = seed_orders(context)
    one = client.get(f"/v1/orders/{order.id}", headers=bearer(context))
    same_as_in_process(one.json(), context.services().ops.get(order.id))
    assert client.get(f"/v1/orders/{uuid4()}", headers=bearer(context)).status_code == 404


def test_known_order_id_is_logged_only_for_its_request(
    context: Context, client: TestClient, tmp_path: Path
) -> None:
    order = seed_orders(context)
    context.configure_logging()
    assert (
        client.get(
            f"/v1/orders/{order.id}", headers={**bearer(context), "X-Request-ID": "order-1"}
        ).status_code
        == 200
    )
    assert client.get("/v1/healthz", headers={"X-Request-ID": "health-2"}).status_code == 200
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "traust.log").read_text().splitlines()
    ]
    access = [record for record in records if record["logger"] == "traust_core.rest.access"]
    assert [(record["request_id"], record["order_id"]) for record in access] == [
        ("order-1", str(order.id)),
        ("health-2", None),
    ]


def test_reads_need_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/orders", params={"states": "queued"}).status_code == 401
    assert client.get(f"/v1/orders/{uuid4()}").status_code == 401
