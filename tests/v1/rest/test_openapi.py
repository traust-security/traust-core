from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from traust_core.v1.models.insight import ReportFormat
from traust_core.v1.rest.roles import serving_role


def test_swagger_redoc_and_the_spec_are_served(client: TestClient) -> None:
    docs = client.get("/docs")
    assert docs.status_code == 200 and "text/html" in docs.headers["content-type"]
    assert '"persistAuthorization": true' in docs.text  # the token survives a reload
    assert client.get("/redoc").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_the_spec_is_served_more_than_once_in_one_process(client: TestClient) -> None:
    """The contract components are inserted into the cached document: a second request
    must answer the same spec, not trip the component-clash check on the cached dict."""
    first = client.get("/openapi.json")
    again = client.get("/openapi.json")
    assert (first.status_code, again.status_code) == (200, 200)
    assert again.json() == first.json()


def test_the_spec_documents_auth_and_the_domains(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert spec["info"]["description"] and spec["info"]["summary"]
    assert "HTTPBearer" in spec["components"]["securitySchemes"]
    tags = {t["name"] for t in spec["tags"]}
    assert {"ops", "findings", "portfolio", "assessments", "exposure"} <= tags
    assert all(t.get("description") for t in spec["tags"])


def test_a_protected_route_requires_the_bearer_scheme(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert spec["paths"]["/v1/orders/claim"]["post"]["security"] == [{"HTTPBearer": []}]


def test_operation_ids_are_the_route_names_without_path_or_method(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"].values()
    ids = [operation["operationId"] for path in paths for operation in path.values()]
    assert len(ids) == len(set(ids))
    assert [i for i in ids if not re.fullmatch(r"[a-z]+(_[a-z]+)*", i)] == []


def test_finding_report_times_remain_nullable_datetimes_in_the_sdk_contract(
    client: TestClient,
) -> None:
    spec = client.get("/openapi.json").json()
    properties = spec["components"]["schemas"]["FindingView"]["properties"]
    for name in ("first_reported_at", "last_reported_at"):
        assert {"type": "string", "format": "date-time"} in properties[name]["anyOf"]
        assert {"type": "null"} in properties[name]["anyOf"]


_OPERATIONS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


def _operations(spec: dict) -> list[tuple[str, str, dict]]:
    """Every (method, path, operation) the spec documents."""
    return [
        (method, path, operation)
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in _OPERATIONS
    ]


def test_every_operation_carries_exactly_one_serving_role(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    operations = _operations(spec)
    assert len(operations) > 50  # the real route list, not an empty one
    for method, path, operation in operations:
        stamped = [value for key, value in operation.items() if key == "x-traust-role"]
        assert stamped == [serving_role(path, method)], (method, path)


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [
        ("get", "/v1/healthz", "every"),  # health and identity serve in every role
        ("get", "/v1/whoami", "every"),
        ("get", "/v1/repositories/{repository_id}/findings", "query"),
        ("post", "/v1/dashboards:query", "query"),
        ("post", "/v1/findings/{finding_id}/decisions", "command"),
        ("post", "/v1/orders/claim", "ops"),
        ("get", "/v1/orders", "ops"),
    ],
)
def test_a_sample_operation_from_each_role(
    client: TestClient, method: str, path: str, role: str
) -> None:
    operation = client.get("/openapi.json").json()["paths"][path][method]
    assert operation["x-traust-role"] == role


def test_the_report_file_route_declares_the_media_types_the_handler_serves(
    client: TestClient,
) -> None:
    """Every format the route can return is typed, so an SDK can type the download: json is
    the report document (an object; its shape varies by report), the rest are text renders."""
    response = client.get("/openapi.json").json()["paths"]["/v1/reports/{order_id}/file"]["get"][
        "responses"
    ]["200"]
    assert set(response["content"]) == {f.media_type for f in ReportFormat}
    assert next(iter(response["content"])) == "application/json"  # generators read the first
    assert response["content"]["application/json"]["schema"] == {"type": "object"}
    for media in ("text/markdown", "text/html", "text/csv"):
        assert response["content"][media]["schema"] == {"type": "string"}
    assert "Content-Disposition" in response["headers"]
