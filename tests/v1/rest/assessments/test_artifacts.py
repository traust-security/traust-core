from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed, apart
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import ArtifactKind, ArtifactView
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import ObjectKey

VIEW_FIELDS = {
    "id",
    "assessment_id",
    "run_order_id",
    "kind",
    "digest",
    "media_type",
    "size",
    "created_at",
}


@dataclass(frozen=True)
class World:
    assessment_id: UUID
    artifacts: list[ArtifactView]


def seed(context: Context, kinds: tuple[str, ...] = ()) -> World:
    """One assessment with a stored document per kind, each a statement apart (creation
    order): the rows and the bytes both real, so the listing's views state them honestly."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seeded = Seed(uow)
        assessment = seeded.assessment(seeded.repository_ref())
        for kind in kinds:
            payload = f"document of {kind}\n".encode()
            stored = context.object_store.put(
                ObjectKey.parse(f"artifacts/{kind}/{sha256_hex(payload)}.json"), payload
            )
            seeded.artifact(assessment, kind=kind, digest=stored.sha256, uri=str(stored.key))
            apart()
        uow.commit()
    assert assessment.id is not None
    views = context.services().assessment.list_artifacts(assessment.id)
    assert [view.kind for view in views] == [ArtifactKind(kind) for kind in kinds]
    return World(assessment.id, views)


def test_the_listing_serves_one_assessments_documents(context: Context, client: TestClient) -> None:
    world = seed(context, ("report",))
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts", headers=bearer(context)
    )
    assert response.status_code == 200, response.text
    expected = context.services().assessment.list_artifacts(world.assessment_id)
    assert response.json() == [artifact.model_dump(mode="json") for artifact in expected]
    assert response.json() == [artifact.model_dump(mode="json") for artifact in world.artifacts]


def test_the_listing_serves_every_document_in_creation_order(
    context: Context, client: TestClient
) -> None:
    world = seed(context, ("report", "remediation-patch.diff"))
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts", headers=bearer(context)
    )
    assert response.status_code == 200, response.text
    assert [doc["kind"] for doc in response.json()] == ["report", "remediation-patch.diff"]
    assert [doc["media_type"] for doc in response.json()] == ["application/json", "text/x-diff"]
    # what each document is, never where core keeps the bytes
    assert set(response.json()[0]) == VIEW_FIELDS
    assert all("uri" not in doc for doc in response.json())


def test_the_listing_serves_a_validation_assessments_recorded_companion(
    context: Context, client: TestClient
) -> None:
    """A validation recording is no contract schema, but its row belongs to the assessment:
    one such companion must not take the whole listing down with it."""
    world = seed(context, ("report", "validation-recording"))
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts", headers=bearer(context)
    )
    assert response.status_code == 200, response.text
    assert [doc["kind"] for doc in response.json()] == ["report", "validation-recording"]
    assert [doc["media_type"] for doc in response.json()] == [
        "application/json",
        "application/json",
    ]
    assert set(response.json()[0]) == VIEW_FIELDS
    assert all("uri" not in doc for doc in response.json())


def test_the_listing_serves_one_kind_on_request(context: Context, client: TestClient) -> None:
    world = seed(context, ("report", "remediation-patch.diff"))
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts",
        params={"kind": "remediation-patch.diff"},
        headers=bearer(context),
    )
    assert response.status_code == 200, response.text
    assert [doc["kind"] for doc in response.json()] == ["remediation-patch.diff"]


def test_an_unknown_kind_filter_is_rejected_rather_than_answered_empty(
    context: Context, client: TestClient
) -> None:
    world = seed(context, ("report",))
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts",
        params={"kind": "sarif"},
        headers=bearer(context),
    )
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/problem+json"


def test_a_known_assessment_with_no_documents_answers_an_empty_array(
    context: Context, client: TestClient
) -> None:
    world = seed(context)
    response = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts", headers=bearer(context)
    )
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_an_unknown_assessment_is_a_native_404_never_an_empty_listing(
    context: Context, client: TestClient
) -> None:
    response = client.get(f"/v1/assessments/{uuid4()}/artifacts", headers=bearer(context))
    assert response.status_code == 404, response.text
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_a_machine_principal_reads_as_freely_as_a_person(
    context: Context, client: TestClient
) -> None:
    world = seed(context, ("report",))
    assert context.identity is not None
    token = context.local_issuer.mint("triage/1.0", machine=True).token.get_secret_value()
    machine = client.get(
        f"/v1/assessments/{world.assessment_id}/artifacts",
        headers={"Authorization": f"Bearer {token}"},
    )
    person = client.get(f"/v1/assessments/{world.assessment_id}/artifacts", headers=bearer(context))
    assert machine.status_code == 200, machine.text
    assert machine.json() == person.json()


def test_the_listing_requires_a_bearer_token(context: Context, client: TestClient) -> None:
    world = seed(context)
    assert client.get(f"/v1/assessments/{world.assessment_id}/artifacts").status_code == 401


def test_the_door_is_the_operation_name_the_sdk_generates(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    operation = paths["/v1/assessments/{assessment_id}/artifacts"]["get"]
    assert operation["operationId"] == "list_assessment_artifacts"
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["items"] == {
        "$ref": "#/components/schemas/ArtifactView"
    }
