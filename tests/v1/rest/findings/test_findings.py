from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_finding(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).finding()
        uow.commit()
    return made


def test_get_a_finding_matches_in_process(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    one = client.get(f"/v1/findings/{finding.id}", headers=bearer(context, ANALYST))
    same_as_in_process(one.json(), context.services().findings.get(finding.id))


def test_an_unknown_finding_is_404(context: Context, client: TestClient) -> None:
    gone = client.get(f"/v1/findings/{uuid4()}", headers=bearer(context, ANALYST))
    assert gone.status_code == 404
    assert gone.headers["content-type"] == "application/problem+json"


def test_a_finding_read_needs_a_token(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    assert client.get(f"/v1/findings/{finding.id}").status_code == 401


def test_a_non_uuid_finding_id_is_422(context: Context, client: TestClient) -> None:
    bad = client.get("/v1/findings/not-a-uuid", headers=bearer(context, ANALYST))
    assert bad.status_code == 422
