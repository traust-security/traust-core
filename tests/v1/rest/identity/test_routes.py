from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import SecretStr

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Config, Context
from traust_core.v1.models.identity import Credential
from traust_core.v1.rest.app import create_app


def test_whoami_is_the_in_process_principal(client: TestClient, context: Context) -> None:
    headers = bearer(context)
    response = client.get("/v1/whoami", headers=headers)
    assert response.status_code == 200
    token = Credential(token=SecretStr(headers["Authorization"].removeprefix("Bearer ")))
    assert context.identity is not None
    same_as_in_process(response.json(), context.identity.authenticate(token))
    assert response.json()["identity"] == "alice@example.com"


def test_no_token_or_a_bad_one_is_a_401_problem(client: TestClient) -> None:
    for headers in ({}, {"Authorization": "Bearer not.a.token"}, {"Authorization": "Basic x"}):
        response = client.get("/v1/whoami", headers=headers)
        assert response.status_code == 401
        assert response.headers["content-type"] == "application/problem+json"
        assert response.headers["WWW-Authenticate"] == "Bearer"


def test_a_deployment_without_an_identity_section_verifies_nobody(tmp_path: Path) -> None:
    context = Context(Config(home=tmp_path))
    with TestClient(create_app(context)) as client:
        response = client.get("/v1/whoami", headers={"Authorization": "Bearer x"})
    assert response.status_code == 401
    assert "verifies no callers" in response.json()["detail"]
