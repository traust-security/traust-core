from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_assessment_record import REPORT
from tests.v1.services.test_remediation import REPORT as REMEDIATION_REPORT
from traust_core.v1 import contracts
from traust_core.v1.context import Config, Context
from traust_core.v1.models.analysis_results import ResultKind
from traust_core.v1.models.artifacts import (
    CONTENT_MEDIA_TYPES,
    ArtifactKind,
    RemediationArtifact,
)
from traust_core.v1.models.assessment import Artifact
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs, record_artifact
from traust_core.v1.services.identity import IdentityConfig

DIFF = b"+bounded\n"


def served_type(header: str) -> str:
    return header.partition(";")[0]


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
    same_as_in_process(metadata.json(), publisher.describe(published.id))
    content = client.get(f"{path}/content", headers=bearer(context))
    assert content.status_code == 200, content.text
    assert served_type(content.headers["content-type"]) == "application/json"
    assert content.headers["traust-artifact-kind"] == "report"
    assert content.headers["etag"] == f'"{published.digest}"'
    assert content.content == publisher.payload(published.id) == REPORT.payload
    assert client.get(path).status_code == 401
    assert client.get(f"{path}/content").status_code == 401


def test_metadata_states_what_the_artifact_is_never_where_core_keeps_it(
    context: Context, client: TestClient
) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(type(REPORT))))
    published = publisher.publish_ref(REPORT)
    body = client.get(f"/v1/artifacts/{published.id}", headers=bearer(context)).json()
    assert set(body) == {
        "id",
        "assessment_id",
        "run_order_id",
        "created_at",
        "kind",
        "digest",
        "media_type",
        "size",
    }
    assert body["kind"] == "report"
    assert body["digest"] == published.digest
    assert body["media_type"] == "application/json"
    assert body["size"] == len(REPORT.payload)


def test_a_companions_content_is_served_as_its_kind(context: Context, client: TestClient) -> None:
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(RemediationArtifact)))
    raw = json.loads(json.dumps(REMEDIATION_REPORT))
    raw["patch"]["diff_sha256"] = sha256_hex(DIFF)
    ref = publisher.publish_companion(
        RemediationArtifact.from_document(raw), ResultKind.REMEDIATION_PATCH, DIFF
    )
    described = client.get(f"/v1/artifacts/{ref.id}", headers=bearer(context))
    assert described.status_code == 200, described.text
    assert described.json()["kind"] == "remediation-patch.diff"
    assert described.json()["media_type"] == "text/x-diff"
    content = client.get(f"/v1/artifacts/{ref.id}/content", headers=bearer(context))
    assert content.status_code == 200, content.text
    assert served_type(content.headers["content-type"]) == "text/x-diff"
    assert content.headers["traust-artifact-kind"] == "remediation-patch.diff"
    assert content.headers["etag"] == f'"{sha256_hex(DIFF)}"'
    assert content.headers["content-length"] == str(len(DIFF))
    assert content.content == DIFF


@pytest.mark.parametrize(
    ("kind", "key", "payload", "media_type"),
    [
        (ArtifactKind.FEED, "feeds/osv/{}/changes.csv", b"id,package\n", "text/csv"),
        (
            ArtifactKind.FEED,
            "feeds/kev/{}/known_exploited_vulnerabilities.json",
            b"{}",
            "application/json",
        ),
        (ArtifactKind.SBOM, "sboms/{}.json.gz", b"\x1f\x8bcompressed", "application/gzip"),
    ],
)
def test_feed_and_sbom_content_is_served_in_its_stored_format(
    context: Context,
    client: TestClient,
    kind: ArtifactKind,
    key: str,
    payload: bytes,
    media_type: str,
) -> None:
    stored = context.object_store.put(ObjectKey.parse(key.format(sha256_hex(payload))), payload)
    with SqlTraustUnitOfWork(context.database) as uow:
        row = record_artifact(
            uow, Artifact(digest=stored.sha256, kind=kind.value, uri=str(stored.key))
        )
        uow.commit()
    described = client.get(f"/v1/artifacts/{row.id}", headers=bearer(context))
    assert described.status_code == 200, described.text
    assert described.json()["media_type"] == media_type
    content = client.get(f"/v1/artifacts/{row.id}/content", headers=bearer(context))
    assert content.status_code == 200, content.text
    assert served_type(content.headers["content-type"]) == media_type
    assert content.headers["traust-artifact-kind"] == kind.value
    assert content.headers["etag"] == f'"{stored.sha256}"'
    assert content.content == payload


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


def test_artifact_operations_declare_the_typed_view_and_the_content_they_serve(
    client: TestClient,
) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    metadata = paths["/v1/artifacts/{artifact_id}"]["get"]
    content = paths["/v1/artifacts/{artifact_id}/content"]["get"]
    assert metadata["operationId"] == "get_artifact"
    assert content["operationId"] == "get_artifact_content"
    assert metadata["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ArtifactView"
    }
    served = content["responses"]["200"]
    assert set(served["content"]) == set(CONTENT_MEDIA_TYPES)
    assert set(served["headers"]) == {"Content-Length", "ETag", "Traust-Artifact-Kind"}
    assert served["headers"]["Traust-Artifact-Kind"]["schema"] == {
        "$ref": "#/components/schemas/ArtifactKind"
    }


def test_every_contract_artifact_schema_is_a_tagged_component(client: TestClient) -> None:
    """SDKs generate the pinned schemas core validates documents against, kind for kind."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    tagged = {
        schema["x-traust-artifact-kind"]: name
        for name, schema in schemas.items()
        if "x-traust-artifact-kind" in schema
    }
    assert set(tagged) == set(contracts.schema_names())
    for kind, name in tagged.items():
        assert name == "".join(part.capitalize() for part in kind.split("-")) + "Artifact"
    assert set(schemas["ArtifactKind"]["enum"]) >= {
        "report",
        "remediation-patch.diff",
        "feed",
        "sbom",
    }


def _refs(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _refs(value)


def _resolves(spec: dict, ref: str) -> bool:
    node: object = spec
    for raw in ref.removeprefix("#/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def test_every_ref_in_the_spec_resolves(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert [ref for ref in _refs(spec) if not _resolves(spec, ref)] == []
