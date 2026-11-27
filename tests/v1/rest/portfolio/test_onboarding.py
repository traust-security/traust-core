from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.services.test_portfolio_sync import Forge
from traust_core.v1.context import Context
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.onboarding import OnboardingRequest
from traust_core.v1.models.vocabulary import LivenessStatus
from traust_core.v1.providers.sources import SourceError

REPO = "https://github.com/example-org/api"


def test_plan_is_a_dry_run_matching_in_process(context: Context, client: TestClient) -> None:
    req = {"product": "example", "label": "Example", "repositories": [{"url": REPO}]}
    body = client.post("/v1/onboarding/plan", json=req, headers=bearer(context)).json()
    # the repo URL crosses the wire as a plain string and coerces to HttpsRepoUrl
    expected = context.services().onboarding.plan(OnboardingRequest.model_validate(req))
    same_as_in_process(body, expected)
    # dry run writes nothing: no product registered
    assert client.get("/v1/products", headers=bearer(context)).json()["items"] == []


def test_plan_reports_a_gap_for_an_unregistered_product(
    context: Context, client: TestClient
) -> None:
    # no label and the product isn't registered yet -> a gap, not an error
    body = client.post("/v1/onboarding/plan", json={"product": "example"}, headers=bearer(context))
    assert body.status_code == 200 and body.json()["gaps"]


def test_onboard_registers_a_product(context: Context, client: TestClient) -> None:
    made = client.post(
        "/v1/onboarding", json={"product": "example", "label": "Example"}, headers=bearer(context)
    )
    assert made.status_code == 200
    body = made.json()
    assert body["product_id"] and body["repository_ids"] == [] and body["order_ids"] == []
    listed = client.get("/v1/products", headers=bearer(context)).json()["items"]
    assert [p["id"] for p in listed] == [body["product_id"]]


def test_onboard_a_new_product_without_a_label_is_422(context: Context, client: TestClient) -> None:
    bad = client.post("/v1/onboarding", json={"product": "example"}, headers=bearer(context))
    assert bad.status_code == 422
    assert bad.headers["content-type"] == "application/problem+json"


def test_onboard_rejects_an_unknown_field(context: Context, client: TestClient) -> None:
    body = {"product": "example", "label": "Example", "surprise": True}
    assert client.post("/v1/onboarding", json=body, headers=bearer(context)).status_code == 422


def test_onboarding_needs_a_token(context: Context, client: TestClient) -> None:
    req = {"product": "example", "label": "Example"}
    assert client.post("/v1/onboarding", json=req).status_code == 401
    assert client.post("/v1/onboarding/plan", json=req).status_code == 401


def test_onboard_a_repository_the_forge_says_does_not_exist_is_a_404(
    context: Context, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The forge answered no — a request core can't satisfy is the caller's 404 naming
    what the forge said, not a relayed outage."""
    missing = Forge(
        info_error=SourceError(
            f"{REPO}: the forge reports no such repository",
            ComparisonStatus.ERROR,
            liveness_status=LivenessStatus.MISSING,
        )
    )
    monkeypatch.setattr("traust_core.v1.context.context.command_source", lambda *a, **k: missing)
    made = client.post(
        "/v1/onboarding",
        json={"product": "example", "label": "Example", "repositories": [{"url": REPO}]},
        headers=bearer(context),
    )
    assert made.status_code == 404
    assert made.headers["content-type"] == "application/problem+json"
    assert "no such repository" in made.json()["detail"]
    listed = client.get("/v1/repositories", headers=bearer(context)).json()["items"]
    assert listed == []  # nothing was written for the repository


def test_onboard_fails_closed_with_502_when_the_forge_doesnt_answer(
    context: Context, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forge outage is the caller's to see (502, the host and the reason), never a
    half-registered repository."""
    down = Forge(info_error=SourceError("forge down", ComparisonStatus.UNREACHABLE))
    monkeypatch.setattr("traust_core.v1.context.context.command_source", lambda *a, **k: down)
    made = client.post(
        "/v1/onboarding",
        json={"product": "example", "label": "Example", "repositories": [{"url": REPO}]},
        headers=bearer(context),
    )
    assert made.status_code == 502
    assert made.headers["content-type"] == "application/problem+json"
    detail = made.json()["detail"]
    assert REPO in detail and "unreachable" in detail and "forge down" in detail
    listed = client.get("/v1/repositories", headers=bearer(context)).json()["items"]
    assert listed == []  # nothing was written for the repository


def test_a_relayed_forge_failure_writes_the_structured_error_line(
    context: Context,
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The 502 problem() relays is logged like a 500: one structured line naming where the
    error was raised, never the message (nothing the forge's error text holds can leak)."""
    down = Forge(info_error=SourceError("forge down", ComparisonStatus.UNREACHABLE))
    monkeypatch.setattr("traust_core.v1.context.context.command_source", lambda *a, **k: down)
    with caplog.at_level(logging.ERROR, logger="traust_core.v1.rest.common.problems"):
        made = client.post(
            "/v1/onboarding",
            json={"product": "example", "label": "Example", "repositories": [{"url": REPO}]},
            headers=bearer(context),
        )
    assert made.status_code == 502
    (record,) = caplog.records
    assert record.getMessage() == "POST /v1/onboarding failed"
    assert record.error_type == "SourceError" and "onboarding" in record.error_source
    assert "forge down" not in caplog.text


def test_plan_fails_closed_with_502_when_the_forge_listing_doesnt_answer(
    context: Context, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    down = Forge(error=SourceError("forge down", ComparisonStatus.UNREACHABLE))
    monkeypatch.setattr("traust_core.v1.context.context.command_source", lambda *a, **k: down)
    made = client.post(
        "/v1/onboarding/plan",
        json={"product": "example", "label": "Example", "org": "example-org"},
        headers=bearer(context),
    )
    assert made.status_code == 502
    detail = made.json()["detail"]
    assert "org example-org on github.com" in detail and "unreachable" in detail
