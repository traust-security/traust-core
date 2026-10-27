from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.rest.conftest import bearer
from traust_core.v1.context import Context
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork


def seed_package(context: Context):
    with SqlTraustUnitOfWork(context.database) as uow:
        made = Seed(uow).package()
        uow.commit()
    return made


def test_find_a_package_by_ecosystem_and_name(context: Context, client: TestClient) -> None:
    package = seed_package(context)
    found = client.get(
        "/v1/packages",
        params={"ecosystem": package.ecosystem, "name": package.name},
        headers=bearer(context),
    )
    assert found.status_code == 200 and found.json()["id"] == str(package.id)


def test_find_an_unknown_package_is_404(context: Context, client: TestClient) -> None:
    gone = client.get(
        "/v1/packages",
        params={"ecosystem": "go", "name": "example.com/absent"},
        headers=bearer(context),
    )
    assert gone.status_code == 404


def test_find_package_validates_its_query(context: Context, client: TestClient) -> None:
    assert (
        client.get("/v1/packages", params={"ecosystem": "go"}, headers=bearer(context)).status_code
        == 422
    )
    bad_eco = client.get(
        "/v1/packages", params={"ecosystem": "cobol", "name": "x"}, headers=bearer(context)
    )
    assert bad_eco.status_code == 422


def test_dependents_of_a_package_and_an_unknown_id(context: Context, client: TestClient) -> None:
    package = seed_package(context)
    ok = client.get(f"/v1/packages/{package.id}/dependents", headers=bearer(context))
    assert ok.status_code == 200 and ok.json() == []
    assert (
        client.get(f"/v1/packages/{uuid4()}/dependents", headers=bearer(context)).status_code == 404
    )


def test_dependencies_of_a_ref_without_an_sbom_is_404(context: Context, client: TestClient) -> None:
    # fail loud: a ref with no manifest SBOM is 404, never read as "no dependencies"
    with SqlTraustUnitOfWork(context.database) as uow:
        ref = Seed(uow).repository_ref()
        uow.commit()
    body = client.get(f"/v1/refs/{ref.id}/dependencies", headers=bearer(context))
    assert body.status_code == 404


def test_dependency_reads_need_a_token(context: Context, client: TestClient) -> None:
    package = seed_package(context)
    assert client.get(f"/v1/packages/{package.id}/dependents").status_code == 401
