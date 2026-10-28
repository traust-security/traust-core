from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.providers.correlation import current_correlation
from traust_core.v1.rest.app import create_app

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


def test_authenticated_access_has_safe_json_fields(
    context: Context, client: TestClient, tmp_path: Path
) -> None:
    context.configure_logging()
    response = client.get("/v1/whoami", headers={**bearer(context), "X-Request-ID": "auth-1"})
    assert response.status_code == 200
    records = [
        json.loads(line) for line in (tmp_path / "logs" / "traust.log").read_text().splitlines()
    ]
    (access,) = [record for record in records if record["logger"] == "traust_core.rest.access"]
    assert {
        key: access[key] for key in ("method", "route", "status", "request_id", "actor_kind")
    } == {
        "method": "GET",
        "route": "/v1/whoami",
        "status": 200,
        "request_id": "auth-1",
        "actor_kind": "human",
    }
    assert access["duration_ms"] >= 0
    assert "alice@example.com" not in json.dumps(access)


def test_unknown_http_method_does_not_enter_the_access_log(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "SYNTHETICNEVERREALTOKEN"
    with caplog.at_level(logging.INFO, logger="traust_core.rest.access"):
        client.request(secret, "/v1/healthz")
    assert secret not in caplog.text
    assert "<other>" in caplog.text


def test_rest_scope_is_cleared_between_requests(context: Context) -> None:
    app = create_app(context)

    @app.get("/trace")
    def trace() -> str:
        value = current_correlation()
        assert value is not None
        return value.request_id

    with TestClient(app) as client:
        assert client.get("/trace", headers={"X-Request-ID": "first"}).json() == "first"
        assert client.get("/trace", headers={"X-Request-ID": "second"}).json() == "second"
    assert current_correlation() is None


def test_concurrent_rest_requests_have_independent_scopes(context: Context) -> None:
    app = create_app(context)
    barrier = Barrier(2)

    @app.get("/parallel")
    def parallel() -> str:
        barrier.wait(timeout=5)
        value = current_correlation()
        assert value is not None
        return value.request_id

    with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as pool:
        left = pool.submit(client.get, "/parallel", headers={"X-Request-ID": "left"})
        right = pool.submit(client.get, "/parallel", headers={"X-Request-ID": "right"})
        assert {left.result(timeout=10).json(), right.result(timeout=10).json()} == {
            "left",
            "right",
        }
    assert current_correlation() is None


def test_zero_trace_id_is_not_reused(client: TestClient) -> None:
    invalid = "00-" + "0" * 32 + "-00f067aa0ba902b7-01"
    assert client.get("/v1/healthz", headers={"traceparent": invalid}).headers["X-Request-ID"] != (
        "0" * 32
    )


def test_openapi_documents_the_routes_and_their_problems(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert {"/v1/healthz", "/v1/whoami"} <= set(spec["paths"])
    unauthorized = spec["paths"]["/v1/whoami"]["get"]["responses"]["401"]
    assert "application/problem+json" in unauthorized["content"]
