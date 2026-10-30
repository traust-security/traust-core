from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.dependencies import ExposureDimension, ExposureFilter, ImpactFilter
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def test_impacts_summary_and_timeline_match_in_process(
    context: Context, client: TestClient
) -> None:
    svc = context.services().exposure
    impacts = client.get("/v1/impacts", headers=bearer(context)).json()
    same_as_in_process(impacts, svc.impacts(ImpactFilter(), PageRequest(limit=100)))
    summary = client.get(
        "/v1/exposure/summary", params={"group_by": "advisory"}, headers=bearer(context)
    ).json()
    assert summary == [
        r.model_dump(mode="json") for r in svc.summary(ExposureFilter(), ExposureDimension.ADVISORY)
    ]
    series = client.get("/v1/exposure/timeline", headers=bearer(context)).json()
    expected = svc.timeline(ExposureFilter(), TimeBucket.MONTH)
    assert series == [p.model_dump(mode="json") for p in expected]


def test_a_findings_advisories_canonical_first(context: Context, client: TestClient) -> None:
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        canonical = s.advisory()
        alias = s.advisory(alias_of_id=canonical.id)
        finding = s.finding(advisory_id=alias.id, advisory_match="confirmed")
        uow.commit()
    found = client.get(f"/v1/findings/{finding.id}/advisories", headers=bearer(context)).json()
    assert [a["id"] for a in found] == [str(canonical.id), str(alias.id)]
    assert found == [
        a.model_dump(mode="json") for a in context.services().exposure.advisories_for(finding.id)
    ]
    gone = client.get(f"/v1/findings/{uuid4()}/advisories", headers=bearer(context))
    assert gone.status_code == 404


def test_feed_statuses_match_in_process(context: Context, client: TestClient) -> None:
    feeds = client.get("/v1/feeds", headers=bearer(context)).json()
    assert feeds == [f.model_dump(mode="json") for f in context.services().exposure.feed_statuses()]


@pytest.mark.parametrize(
    ("url", "params"),
    [
        ("/v1/exposure/summary", {}),
        ("/v1/exposure/summary", {"group_by": "nonsense"}),
        ("/v1/impacts", {"classification": "nonsense"}),
        ("/v1/exposure/timeline", {"ecosystem": "nonsense"}),
    ],
)
def test_exposure_reads_reject_bad_parameters(
    context: Context, client: TestClient, url: str, params: dict[str, str]
) -> None:
    assert client.get(url, params=params, headers=bearer(context)).status_code == 422


@pytest.mark.parametrize("url", ["/v1/impacts", "/v1/exposure/summary", "/v1/feeds"])
def test_exposure_reads_need_a_token(client: TestClient, url: str) -> None:
    assert client.get(url).status_code == 401
