from __future__ import annotations

from uuid import uuid4

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
