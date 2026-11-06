from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.providers.model_catalog import RegistryModelCatalog

CONNECTIONS = (
    Path(__file__).parents[3] / "fixtures" / "operations" / "model-registry-connections.yaml"
)


@pytest.fixture
def registry(context: Context, tmp_path: Path) -> RegistryModelCatalog:
    shutil.copy(CONNECTIONS, tmp_path / "model-registry.yaml")
    context.register_model_catalog(tmp_path / "model-registry.yaml")
    assert isinstance(context.model_catalog, RegistryModelCatalog)
    return context.model_catalog


def test_the_resolved_routing_is_its_in_process_model(
    registry: RegistryModelCatalog, context: Context, client: TestClient
) -> None:
    url, params = "/v1/registry/resolve", {"role": "deep-work", "tier": "opus-class"}
    body = client.get(url, params=params, headers=bearer(context)).json()
    same_as_in_process(body, registry.resolve_routing("deep-work", "opus-class"))


def test_the_gateway_connection_travels_whole(
    registry: RegistryModelCatalog, context: Context, client: TestClient
) -> None:
    """What an executor needs to deliver: the wire, the endpoint, the harness, the credential
    reference — and the note that a type the SCI worker cannot serve yet is unsupported."""
    response = client.get(
        "/v1/registry/resolve", params={"role": "deep-work"}, headers=bearer(context)
    )
    assert response.json() == {
        "model": "glm-5-3",
        "provider": "rits",
        "connection": {
            "type": "openai-compatible",
            "base_url": "https://enmaas.example.invalid/v1",
            "harness": "omp",
            "credential": {
                "source": "secret",
                "name": "sci-enmaas-model",
                "key": "GATEWAY_API_KEY",
            },
            "supported": True,
        },
    }
    vision = client.get("/v1/registry/resolve", params={"role": "vision"}, headers=bearer(context))
    assert vision.json()["connection"]["supported"] is False


def test_a_provider_without_a_connection_block_answer_with_the_default(
    registry: RegistryModelCatalog, context: Context, client: TestClient
) -> None:
    """The default routing, spelled out: the Anthropic wire, no endpoint override, no harness,
    the credential already in the worker's environment."""
    response = client.get(
        "/v1/registry/resolve", params={"role": "fact-judge"}, headers=bearer(context)
    )
    assert response.json() == {
        "model": "claude-haiku-5-5",
        "provider": "anthropic",
        "connection": {
            "type": "anthropic",
            "base_url": None,
            "harness": None,
            "credential": {"source": "env", "name": None, "key": None},
            "supported": True,
        },
    }


def test_an_unknown_role_is_404_and_an_unresolvable_one_is_422(
    registry: RegistryModelCatalog, context: Context, client: TestClient
) -> None:
    unknown = client.get("/v1/registry/resolve", params={"role": "nobody"}, headers=bearer(context))
    assert unknown.status_code == 404
    assert "unknown role 'nobody'" in unknown.json()["detail"]
    unresolvable = client.get(
        "/v1/registry/resolve",
        params={"role": "fact-judge", "tier": "opus-class"},
        headers=bearer(context),
    )
    assert unresolvable.status_code == 422
    assert "no approved model at or above opus-class" in unresolvable.json()["detail"]
    for refused in (unknown, unresolvable):
        assert refused.headers["content-type"] == "application/problem+json"


def test_resolving_a_role_needs_a_token(client: TestClient) -> None:
    assert client.get("/v1/registry/resolve", params={"role": "deep-work"}).status_code == 401


def test_a_deployment_without_a_registry_cannot_answer_routing(
    context: Context, client: TestClient
) -> None:
    response = client.get(
        "/v1/registry/resolve", params={"role": "deep-work"}, headers=bearer(context)
    )
    assert response.status_code == 500
