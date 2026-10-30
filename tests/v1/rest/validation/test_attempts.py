from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.validation import ValidationFilter


def test_validation_attempts_match_in_process(context: Context, client: TestClient) -> None:
    body = client.get("/v1/validation-attempts", headers=bearer(context)).json()
    expected = context.services().validation.list(ValidationFilter(), PageRequest(limit=100))
    same_as_in_process(body, expected)


def test_an_unknown_findings_attempts_are_404(context: Context, client: TestClient) -> None:
    params = {"finding_id": str(uuid4())}
    gone = client.get("/v1/validation-attempts", params=params, headers=bearer(context))
    assert gone.status_code == 404


def test_validation_attempts_reject_a_bad_verdict_and_need_a_token(
    context: Context, client: TestClient
) -> None:
    bad = client.get("/v1/validation-attempts", params={"verdict": "x"}, headers=bearer(context))
    assert bad.status_code == 422
    assert client.get("/v1/validation-attempts").status_code == 401
