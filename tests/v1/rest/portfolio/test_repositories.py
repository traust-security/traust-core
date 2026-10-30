from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        ref = s.repository_ref(repo)
        uow.commit()
    return repo, ref


def test_list_repositories_matches_in_process(context: Context, client: TestClient) -> None:
    seed(context)
    body = client.get("/v1/repositories", headers=bearer(context)).json()
    expected = context.services().portfolio.list_repositories(
        RepositoryFilter(), PageRequest(limit=100)
    )
    same_as_in_process(body, expected)


def test_get_repository_and_its_refs(context: Context, client: TestClient) -> None:
    repo, ref = seed(context)
    one = client.get(f"/v1/repositories/{repo.id}", headers=bearer(context))
    same_as_in_process(one.json(), context.services().portfolio.get_repository(repo.id))
    refs = client.get(f"/v1/repositories/{repo.id}/refs", headers=bearer(context)).json()
    assert [r["id"] for r in refs] == [str(ref.id)]
    assert refs == [
        r.model_dump(mode="json") for r in context.services().portfolio.inventory.list_refs(repo.id)
    ]


def test_get_a_ref(context: Context, client: TestClient) -> None:
    _, ref = seed(context)
    one = client.get(f"/v1/refs/{ref.id}", headers=bearer(context))
    same_as_in_process(one.json(), context.services().portfolio.inventory.get_ref(ref.id))


def test_owners_and_products_of_a_repository_match_in_process(
    context: Context, client: TestClient
) -> None:
    repo, _ = seed(context)
    svc = context.services().portfolio
    owners = client.get(f"/v1/repositories/{repo.id}/owners", headers=bearer(context)).json()
    assert owners == [t.model_dump(mode="json") for t in svc.list_owners(repo.id)]
    prods = client.get(f"/v1/repositories/{repo.id}/products", headers=bearer(context)).json()
    assert prods == [p.model_dump(mode="json") for p in svc.list_products_of(repo.id)]


def test_unknown_repository_and_ref_are_404(context: Context, client: TestClient) -> None:
    assert client.get(f"/v1/repositories/{uuid4()}", headers=bearer(context)).status_code == 404
    assert client.get(f"/v1/refs/{uuid4()}", headers=bearer(context)).status_code == 404


def test_reads_need_a_token_and_reject_a_bad_id(context: Context, client: TestClient) -> None:
    repo, _ = seed(context)
    assert client.get("/v1/repositories").status_code == 401
    assert client.get(f"/v1/repositories/{repo.id}").status_code == 401
    assert client.get("/v1/repositories/not-a-uuid", headers=bearer(context)).status_code == 422


# consumer lookups and inventory writes --------------------------------------------------------

SHA = "0" * 39 + "1"


def test_a_repository_is_found_by_url(context: Context, client: TestClient) -> None:
    repo, _ = seed(context)
    found = client.get("/v1/repositories", params={"url": repo.url}, headers=bearer(context))
    assert [r["id"] for r in found.json()["items"]] == [str(repo.id)]
    expected = context.services().portfolio.list_repositories(
        RepositoryFilter(url=repo.url), PageRequest(limit=100)
    )
    same_as_in_process(found.json(), expected)


def test_an_unregistered_url_finds_nothing(context: Context, client: TestClient) -> None:
    seed(context)
    params = {"url": "https://github.com/example/missing"}
    found = client.get("/v1/repositories", params=params, headers=bearer(context)).json()
    assert found == {"items": [], "next": None}


def test_refs_narrow_to_one_commit(context: Context, client: TestClient) -> None:
    repo, ref = seed(context)
    url = f"/v1/repositories/{repo.id}/refs"
    hit = client.get(url, params={"sha": ref.sha}, headers=bearer(context)).json()
    assert [r["id"] for r in hit] == [str(ref.id)]
    assert client.get(url, params={"sha": SHA}, headers=bearer(context)).json() == []
    assert client.get(url, params={"sha": "nope"}, headers=bearer(context)).status_code == 422


def test_registering_a_ref_is_idempotent(context: Context, client: TestClient) -> None:
    repo, _ = seed(context)
    url = f"/v1/repositories/{repo.id}/refs"
    body = {"sha": SHA, "name": "main", "kind": "branch"}
    first = client.post(url, json=body, headers=bearer(context))
    again = client.post(url, json=body, headers=bearer(context))
    assert first.status_code == 200, first.text
    assert first.json() == again.json()
    assert (first.json()["sha"], first.json()["name"]) == (SHA, "main")
    listed = client.get(url, params={"sha": SHA}, headers=bearer(context)).json()
    assert [r["id"] for r in listed] == [first.json()["id"]]


@pytest.mark.parametrize(
    "body",
    [
        {"sha": "not-a-sha"},
        {"sha": SHA, "name": "main"},
        {"sha": SHA, "kind": "branch"},
        {"sha": SHA, "name": "main", "kind": "nonsense"},
        {"sha": SHA, "repository_id": str(uuid4())},
    ],
)
def test_registering_a_malformed_ref_is_422(
    context: Context, client: TestClient, body: dict[str, str]
) -> None:
    repo, _ = seed(context)
    bad = client.post(f"/v1/repositories/{repo.id}/refs", json=body, headers=bearer(context))
    assert bad.status_code == 422


def test_registering_a_ref_needs_a_token(context: Context, client: TestClient) -> None:
    repo, _ = seed(context)
    assert client.post(f"/v1/repositories/{repo.id}/refs", json={"sha": SHA}).status_code == 401


def test_owners_sync_opens_and_closes_ownership_on_cores_clock(
    context: Context, client: TestClient
) -> None:
    repo, _ = seed(context)
    url = f"/v1/repositories/{repo.id}/owners"
    first = client.put(url, json={"teams": ["red", "blue"]}, headers=bearer(context))
    assert first.status_code == 200, first.text
    assert len(first.json()["added"]) == 2
    second = client.put(url, json={"teams": ["blue"]}, headers=bearer(context)).json()
    assert (len(second["unchanged"]), len(second["removed"])) == (1, 1)
    assert [t["name"] for t in client.get(url, headers=bearer(context)).json()] == ["blue"]
    with SqlTraustUnitOfWork(context.database) as uow:
        (closed,) = [uow.ownerships.get(i) for i in map(UUID, second["removed"])]
        (kept,) = uow.ownerships.current(repo.id)
    assert closed.valid_to is not None and closed.valid_to > closed.valid_from
    assert kept.valid_to is None and kept.valid_from <= closed.valid_to
    again = client.put(url, json={"teams": ["blue", "red"]}, headers=bearer(context)).json()
    assert len(again["added"]) == 1 and again["added"] != second["removed"]


def test_a_team_lists_the_repositories_it_owns(context: Context, client: TestClient) -> None:
    repo, _ = seed(context)
    owners = f"/v1/repositories/{repo.id}/owners"
    client.put(owners, json={"teams": ["blue"]}, headers=bearer(context))
    (team,) = client.get(f"/v1/repositories/{repo.id}/owners", headers=bearer(context)).json()
    owned = client.get(f"/v1/teams/{team['id']}/repositories", headers=bearer(context)).json()
    assert owned == [str(repo.id)]
    unknown = client.get(f"/v1/teams/{uuid4()}/repositories", headers=bearer(context))
    assert unknown.status_code == 404


def test_owners_sync_rejects_a_supplied_time_and_an_unknown_repository(
    context: Context, client: TestClient
) -> None:
    repo, _ = seed(context)
    timed = {"teams": ["blue"], "at": "2026-10-01T00:00:00+00:00"}
    url = f"/v1/repositories/{repo.id}/owners"
    assert client.put(url, json=timed, headers=bearer(context)).status_code == 422
    gone = f"/v1/repositories/{uuid4()}/owners"
    missing = client.put(gone, json={"teams": []}, headers=bearer(context))
    assert missing.status_code == 404
