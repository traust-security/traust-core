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
