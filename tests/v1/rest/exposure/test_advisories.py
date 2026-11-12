from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
from traust_core.v1.models.dependencies import AdvisoryIdentifier, AdvisoryRecord
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_advisory(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        s = Seed(uow)
        advisory = s.advisory()
        package = s.package()
        s.advisory_package(advisory, package)
        uow.commit()
    return advisory


def test_get_an_advisory_and_an_unknown_id(context: Context, client: TestClient) -> None:
    advisory = seed_advisory(context)
    one = client.get(f"/v1/advisories/{advisory.id}", headers=bearer(context))
    same_as_in_process(one.json(), context.services().exposure.get_advisory(advisory.id))
    assert client.get(f"/v1/advisories/{uuid4()}", headers=bearer(context)).status_code == 404


def test_an_advisorys_packages_and_blast_radius(context: Context, client: TestClient) -> None:
    advisory = seed_advisory(context)
    svc = context.services().exposure
    pkgs = client.get(f"/v1/advisories/{advisory.id}/packages", headers=bearer(context)).json()
    assert pkgs == [p.model_dump(mode="json") for p in svc.packages_affected(advisory.id)]
    hit = client.get(f"/v1/advisories/{advisory.id}/affected", headers=bearer(context)).json()
    assert hit == [a.model_dump(mode="json") for a in svc.affected(advisory.id)]


def test_advisory_reads_need_a_token(context: Context, client: TestClient) -> None:
    advisory = seed_advisory(context)
    assert client.get(f"/v1/advisories/{advisory.id}").status_code == 401


AT = datetime(2026, 11, 3, tzinfo=UTC)


class Lookup:
    name = "osv"

    def __init__(self, *records: AdvisoryRecord) -> None:
        self.records = {r.identifier: r for r in records}

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        found = self.records.get(identifier)
        return Result(found, Acquisition(provider="osv", acquired_at=AT))

    def related(self, record: AdvisoryRecord) -> Result[tuple[AdvisoryRecord, ...]]:
        names = {record.identifier, *record.aliases}
        related = tuple(
            other
            for other in self.records.values()
            if other != record and names.intersection((other.identifier, *other.aliases))
        )
        return Result(related, Acquisition(provider="osv", acquired_at=AT))


def osv(identifier: str) -> AdvisoryRecord:
    raw = (Path(__file__).parents[3] / f"fixtures/dependencies/osv-{identifier}.json").read_bytes()
    return parse_osv(raw, f"https://osv.test/v1/vulns/{identifier}")


def test_find_an_advisory_by_a_cve_then_its_blast_radius(
    context: Context, client: TestClient
) -> None:
    ids = ("CVE-2023-39325", "GO-2023-2102", "GHSA-4374-p667-p6c8")
    context.advisories = Lookup(*map(osv, ids))  # type: ignore[assignment]
    found = client.get(
        "/v1/advisories", params={"identifier": "CVE-2023-39325"}, headers=bearer(context)
    )
    assert found.status_code == 200
    body = found.json()
    in_process = context.services().exposure.find_advisory(AdvisoryIdentifier("CVE-2023-39325"))
    assert in_process is not None
    same_as_in_process(body, in_process)
    assert {p["name"] for p in body["affected"]} == {"stdlib", "golang.org/x/net"}
    radius = client.get(f"/v1/advisories/{body['advisory_id']}/affected", headers=bearer(context))
    assert radius.status_code == 200


def test_find_an_advisory_unknown_malformed_or_without_a_token(
    context: Context, client: TestClient
) -> None:
    context.advisories = Lookup()  # type: ignore[assignment]
    url, auth = "/v1/advisories", bearer(context)
    assert client.get(url, params={"identifier": "CVE-2099-0001"}, headers=auth).status_code == 404
    assert client.get(url, params={"identifier": "../vulns/x"}, headers=auth).status_code == 422
    assert client.get(url, headers=auth).status_code == 422
    assert client.get(url, params={"identifier": "CVE-2099-0001"}).status_code == 401
