"""ExposureService advisory lookup on SQLite and Postgres, with an advisory lookup double."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Result
from traust_core.v1.providers.feeds import AdvisoryLookup, FeedProvider
from traust_core.v1.providers.osv import parse_osv
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

AT = datetime(2026, 10, 23, tzinfo=UTC)
GRPC = parse_osv(
    (Path(__file__).parents[2] / "fixtures/dependencies/osv-GHSA-m425-mq94-257g.json").read_bytes(),
    "https://osv.test/v1/vulns/GHSA-m425-mq94-257g",
)


class FakeLookup:
    name = "osv"

    def __init__(self, *records: AdvisoryRecord) -> None:
        self.records = {r.identifier: r for r in records}
        self.asked: list[str] = []

    def check(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        self.asked.append(identifier)
        return Result(self.records.get(identifier), Acquisition(provider="osv", acquired_at=AT))


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def service(engine: Engine, lookup: AdvisoryLookup | None) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        advisories=lookup,
    )


def aliases(engine: Engine, identifier: str) -> list[str]:
    with SqlTraustUnitOfWork(engine) as uow:
        canonical = uow.advisories.find_by_identifier(identifier)
        assert canonical is not None and canonical.id is not None
        return [a.identifier for a in uow.advisories.list_aliases(canonical.id)]


def test_find_keeps_the_advisory_its_aliases_and_packages(engine: Engine) -> None:
    exposure = service(engine, FakeLookup(GRPC))
    record = exposure.find_advisory(AdvisoryIdentifier("GHSA-m425-mq94-257g"))
    assert record is not None and record.advisory_id is not None
    assert record.affected == GRPC.affected
    assert aliases(engine, "GHSA-m425-mq94-257g") == ["GO-2023-2153"]
    advisory = exposure.get_advisory(record.advisory_id)
    assert advisory.published_at == GRPC.published_at
    [link] = exposure.packages_affected(record.advisory_id)
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.packages.get(link.package_id).name == "google.golang.org/grpc"


def test_finding_again_adds_nothing(engine: Engine) -> None:
    exposure = service(engine, FakeLookup(GRPC))
    first = exposure.find_advisory(AdvisoryIdentifier("GHSA-m425-mq94-257g"))
    again = exposure.find_advisory(AdvisoryIdentifier("GHSA-m425-mq94-257g"))
    assert first == again
    assert first is not None and first.advisory_id is not None
    assert len(exposure.packages_affected(first.advisory_id)) == 1
    assert aliases(engine, "GHSA-m425-mq94-257g") == ["GO-2023-2153"]


def test_an_alias_already_known_keeps_its_canonical_row(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        cve = seed.advisory(identifier="CVE-2023-44487")
        seed.advisory(identifier="GO-2023-2153", alias_of_id=cve.id)
        uow.commit()
    record = service(engine, FakeLookup(GRPC)).find_advisory(
        AdvisoryIdentifier("GHSA-m425-mq94-257g")
    )
    assert record is not None and record.advisory_id == cve.id
    with SqlTraustUnitOfWork(engine) as uow:
        assert cve.id is not None
        aliases = {a.identifier: a.published_at for a in uow.advisories.list_aliases(cve.id)}
        assert aliases == {"GO-2023-2153": None, "GHSA-m425-mq94-257g": GRPC.published_at}


def test_records_for_several_packages_link_each_one(engine: Engine) -> None:
    two = GRPC.model_copy(
        update={
            "affected": (
                *GRPC.affected,
                AffectedPackage(ecosystem=Ecosystem.NPM, name="example-lib"),
            )
        }
    )
    record = service(engine, FakeLookup(two)).find_advisory(
        AdvisoryIdentifier("GHSA-m425-mq94-257g")
    )
    assert record is not None and record.advisory_id is not None
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.packages.find("npm", "example-lib") is not None
        assert len(uow.advisory_packages.list_for_advisory(record.advisory_id)) == 2


def test_an_unknown_advisory_is_none_and_writes_nothing(engine: Engine) -> None:
    lookup = FakeLookup()
    assert service(engine, lookup).find_advisory(AdvisoryIdentifier("CVE-2099-0001")) is None
    assert lookup.asked == ["CVE-2099-0001"]
    with SqlTraustUnitOfWork(engine) as uow:
        assert uow.advisories.find_by_identifier("CVE-2099-0001") is None


def test_a_malformed_identifier_never_reaches_the_source(engine: Engine) -> None:
    lookup = FakeLookup(GRPC)
    with pytest.raises(ValidationError, match="not an advisory id"):
        service(engine, lookup).find_advisory(AdvisoryIdentifier("../vulns/x"))
    assert lookup.asked == []


def test_without_a_lookup_finding_is_a_config_error(engine: Engine) -> None:
    with pytest.raises(ConfigError, match="advisory lookup"):
        service(engine, None).find_advisory(AdvisoryIdentifier("CVE-2026-1000"))


def test_get_advisory_of_an_unknown_id_raises(engine: Engine) -> None:
    with pytest.raises(NotFoundError):
        service(engine, None).get_advisory(uuid4())
