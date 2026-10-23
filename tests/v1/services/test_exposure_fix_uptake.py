"""ExposureService.consumes_fix on SQLite and Postgres: has a commit picked up a fix released
elsewhere? Ported from traust src/traust/cli/check_fix_propagation.py (development)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.models.dependencies import Version
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

NET = "golang.org/x/net"
FIX = Version("v0.17.0")


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


@pytest.fixture
def exposure(engine: Engine) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        portfolio=PortfolioService(uow, PortfolioPolicy()),
    )


@pytest.fixture
def commit(engine: Engine) -> RepositoryRef:
    with SqlTraustUnitOfWork(engine) as uow:
        made = Seed(uow).repository_ref()
        uow.commit()
    return made


def sbom(*pins: tuple[str, str]) -> bytes:
    components = [{"purl": f"pkg:golang/{n}@{v}"} for n, v in pins]
    return json.dumps({"bomFormat": "CycloneDX", "components": components}).encode()


def uptake(exposure: ExposureService, commit: RepositoryRef):  # type: ignore[no-untyped-def]
    assert commit.id is not None
    return exposure.consumes_fix(commit.id, Ecosystem.GO, NET, FIX)


@pytest.mark.parametrize(
    ("pins", "state", "consumed"),
    [
        ((("golang.org/x/net", "v0.17.0"),), "consumed", [True]),
        ((("golang.org/x/net", "v0.18.1"),), "consumed", [True]),
        ((("golang.org/x/net", "v0.10.0"),), "pending", [False]),
        (
            (("golang.org/x/net", "v0.17.0"), ("golang.org/x/net", "v0.10.0")),
            "pending",
            [True, False],
        ),
        ((("golang.org/x/net", "master"),), "pending", [None]),
        ((("example.com/other", "v1.0.0"),), "module_absent", []),
    ],
)
def test_the_manifest_decides(
    exposure: ExposureService,
    commit: RepositoryRef,
    pins: tuple[tuple[str, str], ...],
    state: str,
    consumed: list[bool | None],
) -> None:
    assert commit.id is not None
    exposure.ingest_sbom(sbom(*pins), commit.id)
    found = uptake(exposure, commit)
    assert found.state == state
    assert sorted(c.consumed for c in found.checked) == sorted(
        consumed, key=lambda c: (c is None, c)
    )


def test_an_image_still_shipping_the_old_version_keeps_it_pending(
    engine: Engine, exposure: ExposureService, commit: RepositoryRef
) -> None:
    assert commit.id is not None
    exposure.ingest_sbom(sbom((NET, "v0.17.0")), commit.id)
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).repository_ref(Seed(uow).repository(url="https://github.com/org/base"))
        uow.commit()
    assert other.id is not None
    old = exposure.ingest_sbom(sbom((NET, "v0.9.0")), other.id)
    with SqlTraustUnitOfWork(engine) as uow:
        image = Seed(uow).image(repository_ref_id=commit.id, sbom_id=old.id)
        uow.commit()
    found = uptake(exposure, commit)
    assert found.state == "pending"
    assert {(c.image_id, c.version, c.consumed) for c in found.checked} == {
        (None, "v0.17.0", True),
        (image.id, "v0.9.0", False),
    }


def test_a_commit_with_no_sbom_is_not_observed_never_absent(
    exposure: ExposureService, commit: RepositoryRef
) -> None:
    assert uptake(exposure, commit).state == "not_observed"


def test_an_unknown_package_is_absent(exposure: ExposureService, commit: RepositoryRef) -> None:
    assert commit.id is not None
    exposure.ingest_sbom(sbom(("example.com/other", "v1.0.0")), commit.id)
    found = exposure.consumes_fix(commit.id, Ecosystem.NPM, "never-seen", Version("1.0.0"))
    assert (found.state, found.checked) == ("module_absent", ())
