from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.ops.conftest import runner
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import (
    OrderFilter,
    OrderQueryPage,
    OrderQueryRequest,
    OrderState,
    RunOrder,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import OpsService

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


def test_a_runner_can_claim_only_the_selected_queued_order(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        other = seed.run_order(priority=1)
        selected = seed.run_order(priority=9)
        uow.commit()
    body = {**CLAIM, "order_id": str(selected.id)}
    claimed = client.post("/v1/orders/claim", json=body, headers=runner(context))
    assert claimed.status_code == 200 and claimed.json()["id"] == str(selected.id)
    assert client.post("/v1/orders/claim", json=body, headers=runner(context)).status_code == 204
    with SqlTraustUnitOfWork(context.database) as uow:
        assert uow.run_orders.get(other.id).state == "queued"


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


def test_complete_rejects_an_unregistered_reason(context: Context, client: TestClient) -> None:
    seed_orders(context)
    order = client.post("/v1/orders/claim", json=CLAIM, headers=runner(context)).json()
    bad = client.post(
        f"/v1/orders/{order['id']}/complete",
        json={"result": {"outcome": "refused", "reason": "pack version mismatch"}},
        headers=runner(context),
    )
    assert bad.status_code == 422
    assert context.services().ops.get(UUID(order["id"])).state == "leased"


# submit ------------------------------------------------------------------------------------------

PACK = {"name": "pack:smoke", "digest": "a" * 64}
SUBMIT = {"order": {"asset": "command_result", "priority": 1}, "config": [PACK]}


def test_a_person_submits_an_order_with_its_pack_version(
    context: Context, client: TestClient
) -> None:
    submitted = client.post("/v1/orders", json=SUBMIT, headers=bearer(context))
    assert submitted.status_code == 200, submitted.text
    order = submitted.json()
    assert (order["state"], order["requested_by"]) == ("queued", "human:alice@example.com")
    manifest = client.get(f"/v1/orders/{order['id']}/manifest", headers=bearer(context))
    same_as_in_process(manifest.json(), context.services().ops.manifest(UUID(order["id"])))
    assert manifest.json()["config"] == [{**PACK, "artifact_id": None}]


def test_a_submitted_order_is_claimable(context: Context, client: TestClient) -> None:
    order = client.post("/v1/orders", json=SUBMIT, headers=bearer(context)).json()
    body = {"lease_seconds": 300, "assets": ["command_result"]}
    claimed = client.post("/v1/orders/claim", json=body, headers=runner(context)).json()
    assert claimed["id"] == order["id"]


def test_an_order_without_config_has_an_empty_manifest(
    context: Context, client: TestClient
) -> None:
    body = {"order": {"asset": "command_result", "priority": 1}}
    order = client.post("/v1/orders", json=body, headers=bearer(context)).json()
    manifest = client.get(f"/v1/orders/{order['id']}/manifest", headers=bearer(context))
    assert manifest.json() == {"config": [], "approval": None}


@pytest.mark.parametrize(
    "fork",
    [
        {"fork_url": "https://github.com/attacker/fork", "fork_branch": "fix/anything"},
        {"fork_url": "https://github.com/attacker/fork", "fork_branch": "../../etc"},
    ],
)
def test_the_orders_door_refuses_fork_facts(
    context: Context, client: TestClient, fork: dict[str, str]
) -> None:
    """Fork facts are the scheduling door's to set, after its fork-policy and branch checks."""
    order = {"asset": "remediate_finding", "priority": 0, "work_item_id": str(uuid4()), **fork}
    refused = client.post("/v1/orders", json={"order": order}, headers=bearer(context))
    assert refused.status_code == 422, refused.text
    queued = OrderFilter(states=tuple(OrderState))
    assert context.services().ops.list(queued, PageRequest()).items == ()


def test_a_machine_cannot_submit(context: Context, client: TestClient) -> None:
    refused = client.post("/v1/orders", json=SUBMIT, headers=runner(context))
    assert refused.status_code == 403
    assert refused.headers["content-type"] == "application/problem+json"


def test_submit_without_a_token_is_401(client: TestClient) -> None:
    assert client.post("/v1/orders", json=SUBMIT).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"order": {"asset": "command_result"}},
        {"order": {"asset": "command_result", "priority": 1}, "config": [{"name": "pack:x"}]},
        {"order": {"asset": "command_result", "priority": 1}, "id": str(uuid4())},
    ],
)
def test_submit_rejects_a_malformed_body(
    context: Context, client: TestClient, body: dict[str, object]
) -> None:
    assert client.post("/v1/orders", json=body, headers=bearer(context)).status_code == 422


def test_the_manifest_of_an_unknown_order_is_404(context: Context, client: TestClient) -> None:
    missing = client.get(f"/v1/orders/{uuid4()}/manifest", headers=bearer(context))
    assert missing.status_code == 404


def test_the_manifest_needs_a_token(client: TestClient) -> None:
    assert client.get(f"/v1/orders/{uuid4()}/manifest").status_code == 401


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


def test_failed_and_unauthorized_order_requests_keep_their_safe_id(
    context: Context, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order = seed_orders(context)
    context.configure_logging()
    secret = "synthetic-only-never-a-real-credential"

    def fail(_service: OpsService, _order_id: UUID) -> RunOrder:
        raise RuntimeError(secret)

    monkeypatch.setattr(OpsService, "get", fail)
    path = f"/v1/orders/{order.id}"
    assert (
        client.get(path, headers={**bearer(context), "X-Request-ID": "failed-1"}).status_code == 500
    )
    assert client.get(path, headers={"X-Request-ID": "denied-2"}).status_code == 401
    assert client.get("/v1/healthz", headers={"X-Request-ID": "health-3"}).status_code == 200
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "traust.log").read_text().splitlines()
    ]
    (error,) = [record for record in records if record["logger"].endswith("common.problems")]
    assert (error["request_id"], error["order_id"]) == ("failed-1", str(order.id))
    access = [record for record in records if record["logger"] == "traust_core.rest.access"]
    assert [(record["request_id"], record["order_id"]) for record in access] == [
        ("failed-1", str(order.id)),
        ("denied-2", str(order.id)),
        ("health-3", None),
    ]
    assert secret not in json.dumps(records)


def test_reads_need_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/orders", params={"states": "queued"}).status_code == 401
    assert client.get(f"/v1/orders/{uuid4()}").status_code == 401


@pytest.mark.parametrize("machine", [False, True])
def test_query_returns_the_typed_service_page_for_authenticated_readers(
    context: Context, client: TestClient, machine: bool
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://forge.example/org/query")
        for _ in range(3):
            seed.run_order(repository_id=repository.id)
        uow.commit()
    query = OrderQueryRequest(q="ORG/QUERY", limit=2)
    headers = runner(context) if machine else bearer(context)
    response = client.post("/v1/orders/query", json=query.model_dump(mode="json"), headers=headers)
    assert response.status_code == 200
    expected = context.services().ops.query(query)
    same_as_in_process(response.json(), expected)
    page = OrderQueryPage.model_validate(response.json())
    assert len(page.items) == 2 and page.next == page.items[-1].cursor
    assert page.items[0].repository_url == repository.url
    assert all(isinstance(item.order, RunOrder) and item.cursor for item in page.items)


def test_query_needs_a_token(client: TestClient) -> None:
    response = client.post("/v1/orders/query", json={})
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize(
    "body",
    [
        {"limit": 0},
        {"limit": 1001},
        {"states": ["not-a-state"]},
        {"repository_id": "not-a-uuid"},
        {"repository_ids": ["not-a-uuid"]},
        {"run_batch_id": "not-a-uuid"},
        {"ids": ["not-a-uuid"]},
        {"exclude_ids": ["not-a-uuid"]},
        {"sort_by": "priority"},
        {"sort_order": "sideways"},
        {"sort_by": "ids"},
        {"cursor": "not a cursor!"},
        {"cursor": "e30="},
    ],
)
def test_query_rejects_invalid_requests_as_problem_details(
    context: Context, client: TestClient, body: dict[str, object]
) -> None:
    response = client.post("/v1/orders/query", json=body, headers=bearer(context))
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"]


def test_query_rejects_duplicate_sequence_ids(context: Context, client: TestClient) -> None:
    order = seed_orders(context)
    response = client.post(
        "/v1/orders/query",
        json={"sort_by": "ids", "ids": [str(order.id), str(order.id)]},
        headers=bearer(context),
    )
    assert response.status_code == 422
    assert "distinct" in response.json()["detail"]


def test_query_item_cursors_resume_consumed_rows_with_a_different_page_size(
    context: Context, client: TestClient
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        orders = [seed.run_order() for _ in range(5)]
        uow.commit()
    headers = bearer(context)
    body = {"sort_by": "id", "sort_order": "asc", "limit": 3}
    first = client.post("/v1/orders/query", json=body, headers=headers)
    assert first.status_code == 200
    page = OrderQueryPage.model_validate(first.json())
    expected = sorted(order.id for order in orders)
    assert [item.order.id for item in page.items] == expected[:3]
    resumed = client.post(
        "/v1/orders/query",
        json={**body, "limit": 1000, "cursor": page.items[0].cursor},
        headers=headers,
    )
    assert resumed.status_code == 200
    rest = OrderQueryPage.model_validate(resumed.json())
    assert [item.order.id for item in rest.items] == expected[1:]
    assert rest.next is None
    assert all(item.repository_url is None for item in rest.items)
    end = client.post(
        "/v1/orders/query",
        json={**body, "cursor": rest.items[-1].cursor},
        headers=headers,
    )
    assert end.status_code == 200 and end.json() == {"items": [], "next": None}


@pytest.mark.parametrize(
    "changed",
    [
        {"q": "audit"},
        {"sort_order": "asc"},
        {"sort_by": "id"},
        {"states": ["queued"]},
        {"ids": []},
        {"exclude_ids": [str(uuid4())]},
    ],
)
def test_query_rejects_cursors_from_a_different_query(
    context: Context, client: TestClient, changed: dict[str, object]
) -> None:
    seed_orders(context)
    headers = bearer(context)
    first = client.post("/v1/orders/query", json={}, headers=headers)
    assert first.status_code == 200
    cursor = first.json()["items"][0]["cursor"]
    response = client.post("/v1/orders/query", json={**changed, "cursor": cursor}, headers=headers)
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert "cursor" in response.json()["detail"]


def test_query_accepts_unfiltered_and_empty_id_reads_without_changing_get(
    context: Context, client: TestClient
) -> None:
    order = seed_orders(context)
    headers = bearer(context)
    queried = client.post("/v1/orders/query", json={}, headers=headers)
    assert queried.status_code == 200
    assert [item["order"]["id"] for item in queried.json()["items"]] == [str(order.id)]
    empty = client.post("/v1/orders/query", json={"sort_by": "ids", "ids": []}, headers=headers)
    assert empty.status_code == 200 and empty.json() == {"items": [], "next": None}
    assert client.get("/v1/orders", headers=headers).status_code == 422
    listed = client.get("/v1/orders", params={"states": "queued"}, headers=headers)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["id"] == str(order.id)
