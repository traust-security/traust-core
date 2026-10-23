from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"X-Request-ID": "req-123"}, "req-123"),
        ({"traceparent": TRACE}, "4bf92f3577b34da6a3ce929d0e0e4736"),
        ({"X-Request-ID": "req-1", "traceparent": TRACE}, "req-1"),
    ],
    ids=["caller's request id", "traceparent's trace id", "request id wins"],
)
def test_the_request_id_comes_from_the_caller(
    client: TestClient, headers: dict[str, str], expected: str
) -> None:
    assert client.get("/v1/healthz", headers=headers).headers["X-Request-ID"] == expected


@pytest.mark.parametrize("given", ["has space", "x" * 200, "new\nline"])
def test_an_unsafe_request_id_is_replaced(client: TestClient, given: str) -> None:
    assert (
        client.get("/v1/healthz", headers={"X-Request-ID": given}).headers["X-Request-ID"] != given
    )


def test_every_request_gets_one_access_line(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.rest.access"):
        client.get("/v1/healthz", headers={"X-Request-ID": "r9"})
    (line,) = [r.getMessage() for r in caplog.records if r.name == "traust_core.rest.access"]
    assert line.startswith("GET /v1/healthz 200 ") and line.endswith("request_id=r9")


def test_openapi_documents_the_routes_and_their_problems(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert {"/v1/healthz", "/v1/whoami"} <= set(spec["paths"])
    unauthorized = spec["paths"]["/v1/whoami"]["get"]["responses"]["401"]
    assert "application/problem+json" in unauthorized["content"]
