from __future__ import annotations

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_the_feed_is_empty_before_anything_finishes(context: Context, client: TestClient) -> None:
    assert client.get("/v1/feed", headers=bearer(context)).json() == {"items": [], "next": None}


def test_a_finished_order_reaches_the_feed(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).run_order()
        uow.commit()
    order = client.post("/v1/orders/claim", json={"lease_seconds": 300}, headers=runner(context))
    oid = order.json()["id"]
    client.post(
        f"/v1/orders/{oid}/complete",
        json={"result": {"outcome": "succeeded"}},
        headers=runner(context),
    )
    body = client.get("/v1/feed", headers=bearer(context)).json()
    assert [e["order"]["id"] for e in body["items"]] == [oid]
    same_as_in_process(body, context.services().feed.list(PageRequest(limit=100)))


def test_the_feed_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/feed").status_code == 401
