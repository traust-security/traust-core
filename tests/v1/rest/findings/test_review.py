from __future__ import annotations

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import ReviewFilter


def test_the_review_queue_matches_in_process(context: Context, client: TestClient) -> None:
    body = client.get("/v1/findings/review-queue", headers=bearer(context)).json()
    expected = context.services().findings.review.queue(
        ReviewFilter(status="pending"),
        PageRequest(limit=100),  # type: ignore[arg-type]
    )
    same_as_in_process(body, expected)


def test_the_review_queue_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/findings/review-queue").status_code == 401


def test_the_review_queue_rejects_an_unknown_status(context: Context, client: TestClient) -> None:
    bad = client.get(
        "/v1/findings/review-queue", params={"status": "whenever"}, headers=bearer(context)
    )
    assert bad.status_code == 422


def test_the_review_queue_filter_matches_in_process_by_repository_set(
    context: Context, client: TestClient
) -> None:
    from tests.v1.repositories.tables.conftest import Seed
    from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        finding = seed.finding(repo)
        run = seed.assessment(seed.repository_ref(repo), kind="triage")
        seed.decision(finding, validity="false_positive", actor=None, assessment_id=run.id)
        other = seed.repository()
        other_finding = seed.finding(other)
        other_run = seed.assessment(seed.repository_ref(other), kind="triage")
        seed.decision(
            other_finding, validity="false_positive", actor=None, assessment_id=other_run.id
        )
        uow.commit()
    body = client.get(
        "/v1/findings/review-queue",
        params={"repository_ids": [str(repo.id)]},
        headers=bearer(context),
    )
    assert body.status_code == 200
    expected = context.services().findings.review.queue(
        ReviewFilter(status="pending", repository_ids=(repo.id,)),  # type: ignore[arg-type]
        PageRequest(limit=100),  # type: ignore[arg-type]
    )
    same_as_in_process(body.json(), expected)
    served = {case["finding_id"] for case in body.json()["items"]}
    assert served == {str(finding.id)}
