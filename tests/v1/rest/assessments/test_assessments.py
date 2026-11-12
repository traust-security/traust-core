from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import (
    ASSESSMENT_COMPLETED,
    ASSESSMENT_DEGRADED,
    AssessmentFilter,
    AssessmentKind,
)
from traust_core.v1.models.common import PageRequest
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed(context: Context, url: str | None = None):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository(**({"url": url} if url else {}))
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


# the cross-repository batch assessments listing
def test_the_batch_assessments_listing_matches_in_process(
    context: Context, client: TestClient
) -> None:
    repo, ref, _ = seed(context)
    other, other_ref, _ = seed(context, "https://github.com/org/other")
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        s.assessment(ref, kind="triage", occurred_at=T0 + timedelta(days=1))
        s.assessment(other_ref)
        uow.commit()
    svc = context.services().assessment
    body = client.get(
        "/v1/assessments/in",
        params={"repository_ids": [str(repo.id), str(other.id)]},
        headers=bearer(context),
    )
    assert body.status_code == 200
    expected = svc.list_for_repositories([repo.id, other.id])
    assert body.json() == [a.model_dump(mode="json") for a in expected]


def test_the_batch_assessments_listing_serves_one_kind(
    context: Context, client: TestClient
) -> None:
    repo, ref, _ = seed(context)
    with SqlTraustUnitOfWork(context.database) as uow:
        Seed(uow).assessment(ref, kind="triage")
        uow.commit()
    svc = context.services().assessment
    body = client.get(
        "/v1/assessments/in",
        params={"repository_ids": [str(repo.id)], "kind": "triage"},
        headers=bearer(context),
    )
    assert body.status_code == 200
    expected = svc.list_for_repositories([repo.id], AssessmentKind.TRIAGE)
    assert body.json() == [a.model_dump(mode="json") for a in expected]
    assert {row["kind"] for row in body.json()} == {"triage"}


def test_the_batch_assessments_listing_refuses_no_set_and_oversized_sets(
    context: Context, client: TestClient
) -> None:
    repo, _, _ = seed(context)
    assert client.get("/v1/assessments/in", headers=bearer(context)).status_code == 422
    many = [str(repo.id)] * 501
    assert (
        client.get(
            "/v1/assessments/in", params={"repository_ids": many}, headers=bearer(context)
        ).status_code
        == 422
    )


def test_the_batch_assessments_listing_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/assessments/in").status_code == 401


@pytest.mark.parametrize(
    "requested", [AssessmentKind.CLOUD_CONFIG, AssessmentKind.CLOUD_CONFIG_CANONICAL]
)
@pytest.mark.parametrize("status", [ASSESSMENT_COMPLETED, ASSESSMENT_DEGRADED])
def test_latest_recorded_matches_in_process_and_excludes_unrecorded_rows(
    context: Context, client: TestClient, requested: AssessmentKind, status: str
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        main = s.repository_ref(repo)
        branch = s.repository_ref(repo, name="release", sha="b" * 40)
        s.assessment(main, kind=AssessmentKind.CLOUD_CONFIG_CANONICAL, occurred_at=T0)
        latest = s.assessment(
            branch,
            kind=AssessmentKind.CLOUD_CONFIG,
            status=status,
            occurred_at=T0 + timedelta(days=1),
        )
        for excluded in ("pending", "failed", "future-status"):
            s.assessment(
                main,
                kind=AssessmentKind.CLOUD_CONFIG_CANONICAL,
                status=excluded,
                occurred_at=T0 + timedelta(days=2),
            )
        s.assessment(
            main, kind=AssessmentKind.SECURE_CODE_CANONICAL, occurred_at=T0 + timedelta(days=3)
        )
        s.assessment(kind=AssessmentKind.CLOUD_CONFIG_CANONICAL, occurred_at=T0 + timedelta(days=4))
        uow.commit()
    response = client.get(
        f"/v1/repositories/{repo.id}/assessments/latest",
        params={"kind": requested},
        headers=bearer(context),
    )
    assert response.status_code == 200
    assert response.json()["id"] == str(latest.id)
    assert response.json()["kind"] == AssessmentKind.CLOUD_CONFIG_CANONICAL
    assert response.json()["status"] == status
    same_as_in_process(
        response.json(), context.services().assessment.latest_recorded(repo.id, requested)
    )


@pytest.mark.parametrize("state", ["unknown", "no-refs", "empty", "unrecorded", "other-kind"])
def test_latest_recorded_missing_match_is_problem_404(
    context: Context, client: TestClient, state: str
) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        if state in ("empty", "unrecorded", "other-kind"):
            ref = s.repository_ref(repo)
            if state == "unrecorded":
                s.assessment(ref, kind=AssessmentKind.CLOUD_CONFIG_CANONICAL, status="failed")
            elif state == "other-kind":
                s.assessment(ref, kind=AssessmentKind.SECURE_CODE_CANONICAL)
        uow.commit()
    repository_id = uuid4() if state == "unknown" else repo.id
    response = client.get(
        f"/v1/repositories/{repository_id}/assessments/latest",
        params={"kind": AssessmentKind.CLOUD_CONFIG},
        headers=bearer(context),
    )
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


@pytest.mark.parametrize("params", [{}, {"kind": "telepathy"}])
def test_latest_recorded_requires_a_known_kind(
    context: Context, client: TestClient, params: dict[str, str]
) -> None:
    repo, _, _ = seed(context)
    response = client.get(
        f"/v1/repositories/{repo.id}/assessments/latest", params=params, headers=bearer(context)
    )
    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


def test_latest_recorded_requires_a_caller(context: Context, client: TestClient) -> None:
    repo, _, _ = seed(context)
    response = client.get(
        f"/v1/repositories/{repo.id}/assessments/latest",
        params={"kind": AssessmentKind.CLOUD_CONFIG},
    )
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


def test_reads_need_a_token(context: Context, client: TestClient) -> None:
    _, ref, assessment = seed(context)
    assert (
        client.get("/v1/assessments", params={"repository_ref_id": str(ref.id)}).status_code == 401
    )
    assert client.get(f"/v1/assessments/{assessment.id}").status_code == 401


def test_an_orders_assessments_are_what_it_recorded(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        order = s.run_order()
        ref = s.repository_ref()
        recorded = s.assessment(ref, run_order_id=order.id)
        s.assessment(ref)
        uow.commit()
    body = client.get(f"/v1/orders/{order.id}/assessments", headers=bearer(context)).json()
    assert [a["id"] for a in body] == [str(recorded.id)]
    assert body == [
        a.model_dump(mode="json") for a in context.services().assessment.list_for_order(order.id)
    ]
    assert client.get(f"/v1/orders/{uuid4()}/assessments", headers=bearer(context)).json() == []
    assert client.get(f"/v1/orders/{order.id}/assessments").status_code == 401
