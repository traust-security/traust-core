from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from tests.v1.rest.findings.conftest import ANALYST
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import ReportArtifact
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import PageRequest, Provenance
from traust_core.v1.models.findings import (
    FindingCandidate,
    FindingSetFilter,
    FindingSort,
    Label,
    SortDirection,
)
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.findings.service import FindingWindow

AUDIT = json.loads(
    (Path(__file__).parents[3] / "fixtures" / "reporting" / "widget-report.json").read_text()
)
WHEN = datetime(2026, 10, 23, 9, tzinfo=UTC)


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


def test_a_scored_finding_sends_its_computed_band_not_a_word(
    context: Context, client: TestClient
) -> None:
    # the defect over the wire: reported medium, judged low, scored 9.8 — the body says critical
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        finding = seed.finding(repo)
        run = seed.assessment(seed.repository_ref(repo))
        seed.occurrence(
            finding,
            run,
            severity="medium",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=Decimal("9.8"),
        )
        seed.decision(finding, severity="low", rationale="the triage rubric said so")
        uow.commit()
    body = client.get(f"/v1/findings/{finding.id}", headers=bearer(context, ANALYST)).json()
    assert body["effective_severity"] == "critical"
    assert body["cvss"] == {
        "score": "9.8",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "basis": "computed",
        "authority_scores": [],  # no advisory: the scanner's own statement is the selected one
        "selected": {
            "source": "scanner",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": "9.8",
            "band": "critical",
            "scored_by": None,
            "document": f"occurrence:{body['occurrence']['id']}",
            "acquired_at": None,
            "reason": "precedence",
        },
        "conflict": False,
    }


def test_get_a_finding_matches_in_process(context: Context, client: TestClient) -> None:
    finding = seed_finding(context)
    one = client.get(f"/v1/findings/{finding.id}", headers=bearer(context, ANALYST))
    same_as_in_process(one.json(), context.services().findings.get(finding.id))


@pytest.mark.parametrize("reported", [False, True])
def test_finding_detail_and_lists_return_canonical_report_times(
    context: Context, client: TestClient, reported: bool
) -> None:
    first = datetime(2026, 10, 1, tzinfo=UTC)
    last = first + timedelta(days=10)
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        ref = seed.repository_ref(repo)
        finding = seed.finding(repo)
        if reported:
            for at in (last, first, first + timedelta(days=5)):
                seed.occurrence(finding, seed.assessment(ref, occurred_at=at))
        uow.commit()
    for url, params in (
        (f"/v1/findings/{finding.id}", {}),
        (f"/v1/repositories/{repo.id}/findings", {}),
        ("/v1/findings", {"repository_ids": str(repo.id)}),
    ):
        response = client.get(url, params=params, headers=bearer(context, ANALYST))
        assert response.status_code == 200
        body = response.json()
        if "items" in body:
            assert len(body["items"]) == 1
            body = body["items"][0]
        if reported:
            assert datetime.fromisoformat(body["first_reported_at"]) == first
            assert datetime.fromisoformat(body["last_reported_at"]) == last
        else:
            assert body["first_reported_at"] is None
            assert body["last_reported_at"] is None


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


def test_the_count_route_is_not_a_finding_id(context: Context, client: TestClient) -> None:
    seed_reported(context, count=1)
    gone = client.get("/v1/findings/count", headers=bearer(context, ANALYST))
    assert gone.status_code == 422  # the count refuses the missing set, never 404s


def test_the_count_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/findings/count").status_code == 401


# the cross-repository batch summaries


def test_the_batch_summaries_refuse_no_set_and_oversized_sets(
    context: Context, client: TestClient
) -> None:
    findings = seed_reported(context, count=1)
    assert client.get("/v1/findings/summaries", headers=bearer(context, ANALYST)).status_code == 422
    many = [str(findings[0].repository_id)] * 501
    bad = client.get(
        "/v1/findings/summaries", params={"repository_ids": many}, headers=bearer(context, ANALYST)
    )
    assert bad.status_code == 422


def test_the_batch_summaries_needs_a_token(context: Context, client: TestClient) -> None:
    assert client.get("/v1/findings/summaries").status_code == 401


def test_a_finding_recorded_from_a_report_carries_its_prose(
    context: Context, client: TestClient
) -> None:
    services = context.services()
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        repo = seed.repository(url=f"https://github.com/example-org/svc-{uuid4().hex[:8]}")
        ref = seed.repository_ref(repo)
        uow.commit()
    raw = json.loads(json.dumps(AUDIT))
    del raw["metadata"]["additional"]  # a legacy, unstamped report: identity is recomputed
    raw["remediation_roadmap"] = [  # recorded canonically, so priorities are the canonical enum
        {**item, "priority": item["priority"].lower()} for item in raw["remediation_roadmap"]
    ]
    rows = [{k: v for k, v in f.items() if k != "fingerprint"} for f in raw["findings"]]
    rows[0]["evidence"] = [{"code": 'q := "SELECT * FROM t WHERE id = " + id', "language": "go"}]
    doc = ReportArtifact.parse(json.dumps({**raw, "findings": rows}).encode())
    audit = services.assessment.record(
        doc,
        ref.id,
        AssessmentKind.SECURE_CODE_CANONICAL,
        "skill:audit",
        "1",
        Provenance(run_id=uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=WHEN),
    )
    taken = services.findings.intake.accept(
        audit.id, FindingCandidate.of_report(doc.findings[:1], repo.id)
    )
    matched = taken.findings[Label(rows[0]["id"])]
    body = client.get(f"/v1/findings/{matched}", headers=bearer(context, ANALYST)).json()
    assert body["description"] == rows[0]["description"]
    assert body["remediation"] == rows[0]["remediation"]
    assert body["evidence"] == [
        {"code": 'q := "SELECT * FROM t WHERE id = " + id', "language": "go", "caption": None}
    ]
    assert sorted(loc["path"] for loc in body["locations"]) == [
        "pkg/db/other.go",
        "pkg/db/query.go",
    ]
    bare = seed_finding(context)
    empty = client.get(f"/v1/findings/{bare.id}", headers=bearer(context, ANALYST)).json()
    assert (empty["description"], empty["evidence"], empty["remediation"]) == (None, [], None)
