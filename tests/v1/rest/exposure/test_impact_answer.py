"""The impact answer and its fill door over REST: the HTTP answer is the in-process answer."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    ImpactState,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

AT = datetime(2026, 11, 3, tzinfo=UTC)
CVE = AdvisoryIdentifier("CVE-2026-0001")
LODASH = AdvisoryRecord(
    identifier=CVE,
    source="osv",
    affected=(
        AffectedPackage(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            spans=(AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),),
        ),
    ),
)


class Lookup:
    name = "osv"

    def __init__(self, *records: AdvisoryRecord) -> None:
        self.records = {r.identifier: r for r in records}

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        return Result(self.records.get(identifier), Acquisition(provider="osv", acquired_at=AT))


def seeded(context: Context, *, with_sbom: bool, count: int = 1) -> list[UUID]:
    with SqlTraustUnitOfWork(context.database) as uow:
        seed = Seed(uow)
        made = []
        for _ in range(count):
            sbom = seed.sbom() if with_sbom else None
            ref = seed.repository_ref(is_default=True, manifest_sbom_id=sbom.id if sbom else None)
            if sbom is not None:
                package = seed.package(ecosystem="npm", name="lodash")
                seed.dependency(sbom=sbom, package=package, version="4.17.20")
            assert ref.id is not None
            made.append(ref.id)
        uow.commit()
    return made


def test_the_impact_answer_over_http(context: Context, client: TestClient) -> None:
    context.advisories = Lookup(LODASH)  # type: ignore[assignment]
    seeded(context, with_sbom=True)
    seeded(context, with_sbom=False)

    answer = client.get(f"/v1/advisories/{CVE}/impact", headers=bearer(context))
    assert answer.status_code == 200
    same_as_in_process(answer.json(), context.services().exposure.impact(CVE))
    counts = answer.json()["counts"]
    assert counts == {ImpactState.COVERAGE_UNKNOWN.value: 1, ImpactState.NO_SBOM.value: 1}


def test_impact_by_recorded_id_unknown_and_malformed(context: Context, client: TestClient) -> None:
    context.advisories = Lookup(LODASH)  # type: ignore[assignment]
    seeded(context, with_sbom=False)
    by_id = client.get(f"/v1/advisories/{CVE}/impact", headers=bearer(context))
    advisory_id = by_id.json()["advisory_id"]
    assert (
        client.get(f"/v1/advisories/{advisory_id}/impact", headers=bearer(context)).status_code
        == 200
    )
    assert (
        client.get("/v1/advisories/CVE-0000-0000/impact", headers=bearer(context)).status_code
        == 404
    )
    assert client.get("/v1/advisories/not-an-id/impact", headers=bearer(context)).status_code == 422
    assert client.get(f"/v1/advisories/{CVE}/impact").status_code == 401


def test_the_fill_door_queues_one_batch(context: Context, client: TestClient) -> None:
    context.advisories = Lookup(LODASH)  # type: ignore[assignment]
    seeded(context, with_sbom=False, count=2)

    filled = client.post(f"/v1/advisories/{CVE}/impact/fill", headers=bearer(context))
    assert filled.status_code == 200
    batch = filled.json()
    orders = client.get("/v1/orders", params={"run_batch_id": batch["id"]}, headers=bearer(context))
    assert orders.status_code == 200
    assert sorted((o["asset"], o["state"]) for o in orders.json()["items"]) == [
        ("manifest_sbom", "queued"),
        ("manifest_sbom", "queued"),
        ("repo_state", "queued"),
        ("repo_state", "queued"),
    ]
    again = client.post(f"/v1/advisories/{CVE}/impact/fill", headers=bearer(context))
    assert again.json()["id"] == batch["id"]
    assert client.post(f"/v1/advisories/{CVE}/impact/fill").status_code == 401


def test_the_fill_door_returns_null_with_nothing_to_fill(
    context: Context, client: TestClient
) -> None:
    context.advisories = Lookup(LODASH)  # type: ignore[assignment]
    seeded(context, with_sbom=True)

    filled = client.post(f"/v1/advisories/{CVE}/impact/fill", headers=bearer(context))
    assert filled.status_code == 200
    assert filled.json() is None
