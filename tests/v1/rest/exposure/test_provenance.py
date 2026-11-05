from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_exposure_feeds import FakeFeed
from tests.v1.services.test_exposure_provenance import PAGE, SSRF, stored
from tests.v1.services.test_exposure_provenance_bulk import corpus
from traust_core.v1.context import Context
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

URL = "/v1/provenance-reconciliations"


def refresh(context: Context) -> None:
    feed = FakeFeed(PAGE.read_bytes())
    feed.name, feed.filename = FeedName("rh-cve"), "rh_cve.json"
    context.feeds.register(feed.name, lambda: feed)
    context.services().exposure.refresh_feed(feed.name)


def test_bulk_rest_dry_run_is_the_typed_service_result_then_apply_is_idempotent(
    context: Context, client: TestClient
) -> None:
    first, second, _ = corpus(context.database)
    refresh(context)
    expected = context.services().exposure.reconcile_all_provenance()
    response = client.post(URL, headers=bearer(context))
    assert response.status_code == 200
    same_as_in_process(response.json(), expected)
    assert stored(context.database, first.id).advisory_id is None
    assert stored(context.database, second.id).advisory_id is None
    response = client.post(URL, params={"apply": "true"}, headers=bearer(context))
    assert response.status_code == 200
    assert (response.json()["links_written"], response.json()["findings_linked"]) == (2, 2)
    with SqlTraustUnitOfWork(context.database) as uow:
        saved = uow.findings.get(first.id)
        assert saved.advisory_id is not None
        assert uow.advisories.get(saved.advisory_id).identifier == SSRF
    repeated = client.post(URL, params={"apply": "true"}, headers=bearer(context))
    assert repeated.status_code == 200
    assert (repeated.json()["links_written"], repeated.json()["findings_linked"]) == (0, 0)
    assert stored(context.database, first.id) == saved


@pytest.mark.parametrize("score", ["-0.1", "1.1", "nan", "inf"])
def test_bulk_rest_invalid_threshold_is_a_problem_not_a_write(
    context: Context, client: TestClient, score: str
) -> None:
    first, _, _ = corpus(context.database)
    response = client.post(
        URL, params={"min_score": score, "apply": "true"}, headers=bearer(context)
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert stored(context.database, first.id).advisory_id is None


def test_bulk_rest_requires_a_caller_and_a_real_snapshot(
    context: Context, client: TestClient
) -> None:
    assert client.post(URL).status_code == 401
    response = client.post(URL, headers=bearer(context))
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
