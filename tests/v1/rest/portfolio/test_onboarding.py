from __future__ import annotations

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.onboarding import OnboardingRequest

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
