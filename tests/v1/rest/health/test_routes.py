from __future__ import annotations

from fastapi.testclient import TestClient


def test_healthz_answers_without_auth_and_carries_a_request_id(client: TestClient) -> None:
    response = client.get("/v1/healthz")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    assert len(response.headers["X-Request-ID"]) == 32
