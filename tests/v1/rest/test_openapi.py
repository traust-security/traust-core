from __future__ import annotations

import re

from fastapi.testclient import TestClient


def test_swagger_redoc_and_the_spec_are_served(client: TestClient) -> None:
    docs = client.get("/docs")
    assert docs.status_code == 200 and "text/html" in docs.headers["content-type"]
    assert '"persistAuthorization": true' in docs.text  # the token survives a reload
    assert client.get("/redoc").status_code == 200
    assert client.get("/openapi.json").status_code == 200


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
