from __future__ import annotations

from uuid import uuid4

import pytest

from tests.v1.rest.conftest import same_as_in_process
from tests.v1.rest.ledger.conftest import Ledgered, tamper
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.services.ledger import LedgerService


def service(ledgered: Ledgered) -> LedgerService:
    found = ledgered.context.services().ledger
    assert found is not None
    return found


def test_a_repositorys_layers_and_one_layer(ledgered: Ledgered) -> None:
    client, layer_id = ledgered.client, ledgered.layer_id
    listed = client.get(
        f"/v1/repositories/{ledgered.repository_id}/ledger/layers", headers=ledgered.reader
    )
    assert listed.status_code == 200
    assert listed.json() == [
        layer.model_dump(mode="json") for layer in service(ledgered).layers(ledgered.repository_id)
    ]
    one = client.get(f"/v1/ledger/layers/{layer_id}", headers=ledgered.reader)
    same_as_in_process(one.json(), service(ledgered).layer(layer_id))
    assert one.json()["merkle_size"] == 3
    unknown = client.get(f"/v1/repositories/{uuid4()}/ledger/layers", headers=ledgered.reader)
    assert unknown.json() == []


@pytest.mark.parametrize(
    ("limit", "pages"),
    [(10, [[0, 1, 2]]), (2, [[0, 1], [2]]), (1, [[0], [1], [2]])],
    ids=["one page", "a last short page", "one each"],
)
def test_events_page_by_seq(ledgered: Ledgered, limit: int, pages: list[list[int]]) -> None:
    url, seen, cursor = f"/v1/ledger/layers/{ledgered.layer_id}/events", [], None
    while True:
        params = {"limit": limit, **({"cursor": cursor} if cursor else {})}
        body = ledgered.client.get(url, params=params, headers=ledgered.reader).json()
        expected = service(ledgered).events(
            ledgered.layer_id, PageRequest(limit=limit, cursor=Cursor(cursor) if cursor else None)
        )
        same_as_in_process(body, expected)
        seen.append([e["seq"] for e in body["items"]])
        if not (cursor := body["next"]):
            break
    assert seen == pages


def test_an_empty_page_past_the_end(ledgered: Ledgered) -> None:
    url = f"/v1/ledger/layers/{ledgered.layer_id}/events"
    body = ledgered.client.get(url, params={"cursor": "2"}, headers=ledgered.reader).json()
    assert body == {"items": [], "next": None}


@pytest.mark.parametrize(
    ("params", "status"),
    [({"limit": 0}, 422), ({"limit": 1001}, 422), ({"cursor": "seven"}, 422)],
)
def test_bad_paging_is_a_422_problem(ledgered: Ledgered, params: dict, status: int) -> None:
    url = f"/v1/ledger/layers/{ledgered.layer_id}/events"
    response = ledgered.client.get(url, params=params, headers=ledgered.reader)
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"


def test_verification_of_a_clean_and_a_tampered_layer(ledgered: Ledgered) -> None:
    url = f"/v1/ledger/layers/{ledgered.layer_id}/verification"
    clean = ledgered.client.get(url, headers=ledgered.reader).json()
    same_as_in_process(clean, service(ledgered).verify(ledgered.layer_id))
    assert clean["passed"] is True
    tamper(ledgered.context, ledgered.layer_id)
    tampered = ledgered.client.get(url, headers=ledgered.reader).json()
    assert tampered["passed"] is False and tampered["errors"]


@pytest.mark.parametrize(
    "path",
    [
        "/v1/ledger/layers/{id}",
        "/v1/ledger/layers/{id}/events",
        "/v1/ledger/layers/{id}/verification",
    ],
)
def test_an_unknown_layer_is_a_404_problem(ledgered: Ledgered, path: str) -> None:
    response = ledgered.client.get(path.format(id=uuid4()), headers=ledgered.reader)
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize(
    "path",
    [
        "/v1/repositories/{repo}/ledger/layers",
        "/v1/ledger/layers/{layer}",
        "/v1/ledger/layers/{layer}/events",
        "/v1/ledger/layers/{layer}/verification",
    ],
)
def test_reads_need_a_verified_caller(ledgered: Ledgered, path: str) -> None:
    url = path.format(repo=ledgered.repository_id, layer=ledgered.layer_id)
    for headers in ({}, {"Authorization": "Bearer not.a.token"}):
        assert ledgered.client.get(url, headers=headers).status_code == 401
