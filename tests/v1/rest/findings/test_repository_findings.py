from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.findings import FindingDimension, FindingFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_reported(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        repo = s.repository()
        assessment = s.assessment(s.repository_ref(repo))
        for _ in range(3):
            s.occurrence(s.finding(repo), assessment)
        uow.commit()
    return repo


def test_a_repositorys_findings_page_like_in_process(context: Context, client: TestClient) -> None:
    repo = seed_reported(context)
    url = f"/v1/repositories/{repo.id}/findings"
    first = client.get(url, params={"limit": 2}, headers=bearer(context, ANALYST)).json()
    svc = context.services().findings
    same_as_in_process(first, svc.list(FindingFilter(repository_id=repo.id), PageRequest(limit=2)))
    assert len(first["items"]) == 2 and first["next"]
    rest = client.get(
        url, params={"limit": 2, "cursor": first["next"]}, headers=bearer(context, ANALYST)
    ).json()
    assert len(rest["items"]) == 1 and rest["next"] is None


def test_a_repositorys_finding_summary_and_timeline(context: Context, client: TestClient) -> None:
    repo = seed_reported(context)
    svc, scope = context.services().findings, FindingFilter(repository_id=repo.id)
    base = f"/v1/repositories/{repo.id}/findings"
    summary = client.get(
        f"{base}/summary", params={"group_by": "severity"}, headers=bearer(context, ANALYST)
    ).json()
    assert summary == [
        r.model_dump(mode="json") for r in svc.summary(scope, FindingDimension.SEVERITY)
    ]
    assert sum(r["findings"] for r in summary) == 3
    series = client.get(
        f"{base}/timeline", params={"bucket": "week"}, headers=bearer(context, ANALYST)
    ).json()
    assert series == [p.model_dump(mode="json") for p in svc.timeline(scope, TimeBucket.WEEK)]


def test_an_empty_repository_has_no_findings(context: Context, client: TestClient) -> None:
    url = f"/v1/repositories/{uuid4()}/findings"
    assert client.get(url, headers=bearer(context, ANALYST)).json() == {"items": [], "next": None}


@pytest.mark.parametrize(
    ("suffix", "params"),
    [("/summary", {}), ("/summary", {"group_by": "nonsense"}), ("", {"validity": "nonsense"})],
)
def test_finding_reads_reject_bad_parameters(
    context: Context, client: TestClient, suffix: str, params: dict[str, str]
) -> None:
    url = f"/v1/repositories/{uuid4()}/findings{suffix}"
    assert client.get(url, params=params, headers=bearer(context, ANALYST)).status_code == 422


def test_finding_reads_need_a_token(client: TestClient) -> None:
    assert client.get(f"/v1/repositories/{uuid4()}/findings").status_code == 401
