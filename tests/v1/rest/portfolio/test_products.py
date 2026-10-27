from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_product(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).product()
        uow.commit()
    return made


def test_list_products_matches_in_process(context: Context, client: TestClient) -> None:
    seed_product(context)
    body = client.get("/v1/products", headers=bearer(context)).json()
    same_as_in_process(body, context.services().portfolio.list_products(PageRequest(limit=100)))


def test_get_a_product_and_its_refs(context: Context, client: TestClient) -> None:
    product = seed_product(context)
    svc = context.services().portfolio
    one = client.get(f"/v1/products/{product.id}", headers=bearer(context))
    same_as_in_process(one.json(), svc.get_product(product.id))
    refs = client.get(f"/v1/products/{product.id}/refs", headers=bearer(context)).json()
    assert refs == [r.model_dump(mode="json") for r in svc.list_product_refs(product.id)]


def test_unknown_product_is_404(context: Context, client: TestClient) -> None:
    assert client.get(f"/v1/products/{uuid4()}", headers=bearer(context)).status_code == 404


def test_product_reads_need_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/products").status_code == 401
