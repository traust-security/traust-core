from __future__ import annotations

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_a_view_is_its_in_process_model_for_the_scope(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        product = Seed(uow).product()
        uow.commit()
    params = {"product_id": str(product.id)}
    body = client.get("/v1/views/findings-rollup", params=params, headers=bearer(context)).json()
    expected = context.services().insight.build(
        ViewName.FINDINGS_ROLLUP, ViewFilter(product_ids=(product.id,))
    )
    same_as_in_process(body, expected)
    assert body  # the view's own fields, not the empty base model


def test_an_unknown_view_is_422_and_views_need_a_token(
    context: Context, client: TestClient
) -> None:
    assert client.get("/v1/views/nonsense", headers=bearer(context)).status_code == 422
    assert client.get("/v1/views/findings-rollup").status_code == 401
    bad = client.get("/v1/views/findings-rollup", params={"team_id": "x"}, headers=bearer(context))
    assert bad.status_code == 422
