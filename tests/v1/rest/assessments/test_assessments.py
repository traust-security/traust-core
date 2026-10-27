from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import AssessmentFilter
from traust_core.v1.models.common import PageRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        ref = s.repository_ref(repo)
        assessment = s.assessment(ref)
        uow.commit()
    return repo, ref, assessment


def test_list_a_refs_assessments_matches_in_process(context: Context, client: TestClient) -> None:
    _, ref, _ = seed(context)
    body = client.get(
        "/v1/assessments", params={"repository_ref_id": str(ref.id)}, headers=bearer(context)
    ).json()
    expected = context.services().assessment.list(
        AssessmentFilter(repository_ref_id=ref.id), PageRequest(limit=100)
    )
    same_as_in_process(body, expected)


def test_list_without_a_ref_is_422(context: Context, client: TestClient) -> None:
    assert client.get("/v1/assessments", headers=bearer(context)).status_code == 422


def test_list_rejects_an_unknown_kind(context: Context, client: TestClient) -> None:
    _, ref, _ = seed(context)
    bad = client.get(
        "/v1/assessments",
        params={"repository_ref_id": str(ref.id), "kind": "telepathy"},
        headers=bearer(context),
    )
    assert bad.status_code == 422


def test_get_an_assessment_and_an_unknown_id(context: Context, client: TestClient) -> None:
    _, _, assessment = seed(context)
    one = client.get(f"/v1/assessments/{assessment.id}", headers=bearer(context))
    same_as_in_process(one.json(), context.services().assessment.get(assessment.id))
    assert client.get(f"/v1/assessments/{uuid4()}", headers=bearer(context)).status_code == 404


def test_a_repositorys_assessments(context: Context, client: TestClient) -> None:
    repo, _, _ = seed(context)
    svc = context.services().assessment
    body = client.get(f"/v1/repositories/{repo.id}/assessments", headers=bearer(context)).json()
    assert body == [a.model_dump(mode="json") for a in svc.list_for_repository(repo.id)]


def test_reads_need_a_token(context: Context, client: TestClient) -> None:
    _, ref, assessment = seed(context)
    assert (
        client.get("/v1/assessments", params={"repository_ref_id": str(ref.id)}).status_code == 401
    )
    assert client.get(f"/v1/assessments/{assessment.id}").status_code == 401
