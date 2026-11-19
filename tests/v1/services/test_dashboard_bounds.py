"""Bounds on every list: ids per filter, values per where key, group_by,
where keys, order, limit and the request body each refuse cleanly — the
model's ValidationError in process, a 422 problem response over HTTP. At the
bound, the request is served."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import ValidationError as Refusal

from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Config, Context
from traust_core.v1.models.dashboard import DashboardQuery
from traust_core.v1.rest.app import create_app
from traust_core.v1.services.identity import IdentityConfig

QUERY = {"subject": "findings", "measures": ["findings"]}
MEBIBYTE = 1_048_576
_ID_FIELDS = ("repository_ids", "product_ids", "team_ids")


@pytest.fixture
def context(tmp_path: Path) -> Context:
    return Context(Config(home=tmp_path, identity=IdentityConfig(trust_local=True)))


@pytest.fixture
def client(context: Context) -> Iterator[TestClient]:
    with TestClient(create_app(context), raise_server_exceptions=False) as c:
        yield c


def _ids(count: int) -> list[str]:
    return [str(uuid4()) for _ in range(count)]


def _validate(body: dict[str, object]) -> DashboardQuery:
    return DashboardQuery.model_validate(body)


def _post(client: TestClient, context: Context, body: dict[str, object]) -> Response:
    return client.post("/v1/dashboards:query", json=body, headers=bearer(context))


def _problem(response: Response) -> None:
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize("field", _ID_FIELDS)
def test_more_than_a_thousand_ids_per_filter_is_refused(field: str) -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate({**QUERY, field: _ids(1001)})


@pytest.mark.parametrize("field", _ID_FIELDS)
def test_a_thousand_ids_per_filter_is_served(field: str) -> None:
    assert len(getattr(_validate({**QUERY, field: _ids(1000)}), field)) == 1000


def test_more_than_a_hundred_values_per_where_key_is_refused() -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate({**QUERY, "where": {"category": ["x"] * 101}})


def test_a_hundred_values_per_where_key_is_served() -> None:
    assert len(_validate({**QUERY, "where": {"category": ["x"] * 100}}).where["category"]) == 100


def test_a_fourth_group_by_dimension_is_refused() -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate(
            {**QUERY, "group_by": ["repository", "state", "severity", "category"]}
        )


def test_three_group_by_dimensions_are_served() -> None:
    assert len(_validate({**QUERY, "group_by": ["severity", "state", "category"]}).group_by) == 3


def test_a_ninth_where_key_is_refused() -> None:
    dimensions = [
        "repository",
        "product",
        "team",
        "state",
        "severity",
        "category",
        "decided",
        "sla_status",
        "age_bucket",
    ]
    with pytest.raises(Refusal):
        DashboardQuery.model_validate({**QUERY, "where": {d: ["x"] for d in dimensions}})


def test_a_fourth_order_entry_is_refused() -> None:
    order = [{"by": measure} for measure in ("findings", "repositories", "cvss_sum", "state")]
    with pytest.raises(Refusal):
        DashboardQuery.model_validate({**QUERY, "order": order})


def test_a_limit_above_the_row_cap_is_refused() -> None:
    with pytest.raises(Refusal):
        DashboardQuery.model_validate({**QUERY, "limit": 1001})


def test_a_limit_at_the_row_cap_is_served() -> None:
    assert _validate({**QUERY, "limit": 1000}).limit == 1000


@pytest.mark.parametrize("field", _ID_FIELDS)
def test_more_than_a_thousand_ids_over_http_is_a_422_problem(
    context: Context, client: TestClient, field: str
) -> None:
    _problem(_post(client, context, {**QUERY, field: _ids(1001)}))


def test_a_hundred_and_one_where_values_over_http_is_a_422_problem(
    context: Context, client: TestClient
) -> None:
    _problem(_post(client, context, {**QUERY, "where": {"category": ["x"] * 101}}))


def test_a_fourth_group_by_over_http_is_a_422_problem(context: Context, client: TestClient) -> None:
    _problem(
        _post(
            client,
            context,
            {**QUERY, "group_by": ["repository", "state", "severity", "category"]},
        )
    )


def test_a_limit_above_the_row_cap_over_http_is_a_422_problem(
    context: Context, client: TestClient
) -> None:
    _problem(_post(client, context, {**QUERY, "limit": 1001}))


def test_a_body_over_one_mebibyte_is_a_422_problem(context: Context, client: TestClient) -> None:
    response = _post(client, context, {**QUERY, "where": {"category": ["A" * (MEBIBYTE + 1024)]}})
    _problem(response)
    assert "1 MiB" in response.json()["detail"]


def test_a_body_just_under_one_mebibyte_is_served(context: Context, client: TestClient) -> None:
    response = _post(client, context, {**QUERY, "where": {"category": ["A" * (MEBIBYTE - 2048)]}})
    assert response.status_code == 200
    assert response.json()["rows"] == [{"groups": {}, "measures": {"findings": 0.0}}]


def test_the_bounds_at_their_limits_over_http_are_served(
    context: Context, client: TestClient
) -> None:
    at_the_bounds = {
        **QUERY,
        "repository_ids": _ids(1000),
        "where": {"category": ["x"] * 100},
        "group_by": ["severity", "state", "category"],
        "limit": 1000,
    }
    response = _post(client, context, at_the_bounds)
    assert response.status_code == 200
    assert response.json()["rows"] == []
