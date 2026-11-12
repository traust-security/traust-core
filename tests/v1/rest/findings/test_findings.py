from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import (
    FindingSetFilter,
    FindingSort,
    SortDirection,
)
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.service import FindingWindow


def seed_finding(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).finding()
        uow.commit()
    return made


def seed_reported(context: Context, count: int = 2) -> list:
    """`count` findings on as many repositories, each with an occurrence so the fold
    serves a full view."""
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        made = []
        for _ in range(count):
            repo = seed.repository()
            finding = seed.finding(repo)
            run = seed.assessment(seed.repository_ref(repo))
            seed.occurrence(finding, run)
            made.append(finding)
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


# the cross-repository batch listing
def test_the_batch_listing_matches_in_process_and_serves_the_union(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=3)
    in_set = [str(f.repository_id) for f in findings[:2]]
    body = client.get(
        "/v1/findings", params={"repository_ids": in_set}, headers=bearer(context, ANALYST)
    )
    assert body.status_code == 200
    expected = context.services().findings.list_in(
        FindingSetFilter(repository_ids=tuple(f.repository_id for f in findings[:2])),
        PageRequest(limit=100),
    )
    same_as_in_process(body.json(), expected)
    served = {item["finding"]["id"] for item in body.json()["items"]}
    assert served == {str(f.id) for f in findings[:2]}


def test_the_batch_listing_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/findings").status_code == 401


def test_the_batch_listing_refuses_no_repository_set(context: Context, client: TestClient) -> None:
    bad = client.get("/v1/findings", headers=bearer(context, ANALYST))
    assert bad.status_code == 422


def test_the_batch_listing_refuses_more_than_a_pages_worth_of_repositories(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=1)
    many = [str(findings[0].repository_id)] * 501
    bad = client.get(
        "/v1/findings", params={"repository_ids": many}, headers=bearer(context, ANALYST)
    )
    assert bad.status_code == 422


# The worklist's pushed-down cut and sorted windows (the S1 slice).
def test_the_batch_listing_filters_by_exposure_and_severity(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=2)
    in_set = [str(f.repository_id) for f in findings]
    body = client.get(
        "/v1/findings",
        params={"repository_ids": in_set, "exposure": "open", "severity": "high"},
        headers=bearer(context, ANALYST),
    )
    assert body.status_code == 200
    expected = context.services().findings.list_in(
        FindingSetFilter(
            repository_ids=tuple(f.repository_id for f in findings),
            exposure="open",
            severity=("high",),
        ),
        PageRequest(limit=100),
    )
    same_as_in_process(body.json(), expected)


def test_the_batch_listing_refuses_an_unknown_exposure(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=1)
    bad = client.get(
        "/v1/findings",
        params={"repository_ids": [str(findings[0].repository_id)], "exposure": "sideways"},
        headers=bearer(context, ANALYST),
    )
    assert bad.status_code == 422


def test_the_batch_listing_serves_a_sorted_window(context: Context, client: TestClient) -> None:
    findings = seed_reported(context, count=3)
    in_set = [str(f.repository_id) for f in findings]
    body = client.get(
        "/v1/findings",
        params={"repository_ids": in_set, "sort": "severity", "direction": "desc"},
        headers=bearer(context, ANALYST),
    )
    assert body.status_code == 200
    expected = context.services().findings.list_in(
        FindingSetFilter(repository_ids=tuple(f.repository_id for f in findings)),
        PageRequest(limit=100),
        FindingWindow(column=FindingSort.SEVERITY, direction=SortDirection.DESC),
    )
    same_as_in_process(body.json(), expected)
    assert body.json()["next"] is None  # a window pages by a wider limit, never a cursor


def test_the_batch_listing_refuses_a_cursor_on_a_sorted_window(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=1)
    bad = client.get(
        "/v1/findings",
        params={
            "repository_ids": [str(findings[0].repository_id)],
            "sort": "severity",
            "cursor": "2026-01-01T00:00:00+00:00|00000000-0000-0000-0000-000000000000",
        },
        headers=bearer(context, ANALYST),
    )
    assert bad.status_code == 422


def test_the_count_matches_the_filtered_listing_in_process(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=2)
    in_set = [str(f.repository_id) for f in findings]
    body = client.get(
        "/v1/findings/count",
        params={"repository_ids": in_set, "exposure": "open"},
        headers=bearer(context, ANALYST),
    )
    assert body.status_code == 200
    expected = context.services().findings.count_in(
        FindingSetFilter(repository_ids=tuple(f.repository_id for f in findings), exposure="open")
    )
    same_as_in_process(body.json(), expected)


def test_the_count_route_is_not_a_finding_id(context: Context, client: TestClient) -> None:
    seed_reported(context, count=1)
    gone = client.get("/v1/findings/count", headers=bearer(context, ANALYST))
    assert gone.status_code == 422  # the count refuses the missing set, never 404s


def test_the_count_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/findings/count").status_code == 401
