from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_assessment_record import REPORT
from traust_core.v1.context import Config, Context
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_core.v1.services.identity import IdentityConfig


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as database:
        yield database


@pytest.fixture
def context(engine: Engine, tmp_path: Path) -> Context:
    context = Context(Config(home=tmp_path, identity=IdentityConfig(trust_local=True)))
    context.__dict__["database"] = engine
    return context


def test_authenticated_metadata_and_content_are_the_existing_publishers_results(
    context: Context, client: TestClient
) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(type(REPORT))))
    published = publisher.publish_ref(REPORT)
    path = f"/v1/artifacts/{published.id}"
    metadata = client.get(path, headers=bearer(context))
    assert metadata.status_code == 200, metadata.text
    same_as_in_process(metadata.json(), publisher.metadata(published.id))
    content = client.get(f"{path}/content", headers=bearer(context))
    assert content.status_code == 200, content.text
    assert content.headers["content-type"] == "application/octet-stream"
    assert content.content == publisher.payload(published.id) == REPORT.payload
    assert client.get(path).status_code == 401
    assert client.get(f"{path}/content").status_code == 401


@pytest.mark.parametrize("suffix", ["", "/content"])
def test_missing_artifact_reads_return_native_problem_details(
    context: Context, client: TestClient, suffix: str
) -> None:
    response = client.get(f"/v1/artifacts/{uuid4()}{suffix}", headers=bearer(context))
    assert response.status_code == 404, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_corrupt_artifact_content_is_never_returned_as_original_evidence(
    context: Context, client: TestClient
) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(type(REPORT))))
    published = publisher.publish_ref(REPORT)
    metadata = publisher.metadata(published.id)
    context.object_store.put(ObjectKey.parse(metadata.uri), b"corrupt evidence")
    response = client.get(f"/v1/artifacts/{published.id}/content", headers=bearer(context))
    assert response.status_code == 409, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert b"corrupt evidence" not in response.content


def test_artifact_operations_describe_native_metadata_and_unparsed_binary_content(
    client: TestClient,
) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    metadata = paths["/v1/artifacts/{artifact_id}"]["get"]
    content = paths["/v1/artifacts/{artifact_id}/content"]["get"]
    assert metadata["operationId"] == "get_artifact_v1_artifacts__artifact_id__get"
    assert content["operationId"] == "get_artifact_content_v1_artifacts__artifact_id__content_get"
    assert metadata["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Artifact"
    }
    assert content["responses"]["200"]["content"] == {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
    }
