from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.remediation import VerificationFilter, WorkItemFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def opened(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = s.repository_ref(repo)
        finding = s.finding(repo)
        s.decision(finding, validity="confirmed", severity="high", actor="human:a@example.com")
        uow.commit()
    item = context.services().remediation.open([finding.id], ref.id)
    return repo, item


def test_work_items_and_their_inputs_match_in_process(context: Context, client: TestClient) -> None:
    repo, item = opened(context)
    svc = context.services()
    listed = client.get(f"/v1/repositories/{repo.id}/work-items", headers=bearer(context)).json()
    expected = svc.remediation.list(WorkItemFilter(repository_id=repo.id), PageRequest(limit=100))
    same_as_in_process(listed, expected)
    assert [w["work_item_id"] for w in listed["items"]] == [str(item.work_item_id)]
    base = f"/v1/work-items/{item.work_item_id}"
    fix = client.get(f"{base}/remediation-input", headers=bearer(context))
    same_as_in_process(fix.json(), svc.remediation.prepare(item.work_item_id))
    check = client.get(f"{base}/verification-input", headers=bearer(context))
    same_as_in_process(check.json(), svc.verification.prepare(item.work_item_id))


def test_a_repositorys_verifications_match_in_process(context: Context, client: TestClient) -> None:
    repo, item = opened(context)
    url = f"/v1/repositories/{repo.id}/verifications"
    body = client.get(url, params={"work_item_id": str(item.work_item_id)}, headers=bearer(context))
    expected = context.services().verification.list(
        VerificationFilter(repository_id=repo.id, work_item_id=item.work_item_id),
        PageRequest(limit=100),
    )
    same_as_in_process(body.json(), expected)


def test_an_unknown_work_items_inputs_are_404(context: Context, client: TestClient) -> None:
    for suffix in ("remediation-input", "verification-input"):
        gone = client.get(f"/v1/work-items/{uuid4()}/{suffix}", headers=bearer(context))
        assert gone.status_code == 404, suffix


def test_work_item_reads_reject_a_bad_status_and_need_a_token(
    context: Context, client: TestClient
) -> None:
    url = f"/v1/repositories/{uuid4()}/work-items"
    bad = client.get(url, params={"status": "nonsense"}, headers=bearer(context))
    assert bad.status_code == 422
    assert client.get(url).status_code == 401
