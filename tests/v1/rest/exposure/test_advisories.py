from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer, same_as_in_process
from traust_core.v1.context import Context
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
