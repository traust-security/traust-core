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
    AffectedSpan,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Result
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import AdvisoryLookup, FeedProvider
from traust_core.v1.providers.osv import ExportedAdvisoryLookup, parse_osv
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

AT = datetime(2026, 10, 23, tzinfo=UTC)
GRPC = parse_osv(
    (Path(__file__).parents[2] / "fixtures/dependencies/osv-GHSA-m425-mq94-257g.json").read_bytes(),
    "https://osv.test/v1/vulns/GHSA-m425-mq94-257g",
)


def osv(identifier: str) -> AdvisoryRecord:
    raw = (Path(__file__).parents[2] / f"fixtures/dependencies/osv-{identifier}.json").read_bytes()
    return parse_osv(raw, f"https://osv.test/v1/vulns/{identifier}")


CVE, GO, GHSA = osv("CVE-2023-39325"), osv("GO-2023-2102"), osv("GHSA-4374-p667-p6c8")


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


def test_known_aliases_still_contribute_new_identity_and_package_facts(engine: Engine) -> None:
    first = service(engine, FakeLookup(GRPC)).find_advisory(GRPC.identifier)
    assert first is not None and first.advisory_id is not None
    alias = AdvisoryRecord(
        identifier=AdvisoryIdentifier("GO-2023-2153"),
        aliases=(GRPC.identifier, AdvisoryIdentifier("CVE-2026-1000")),
        affected=(AffectedPackage(ecosystem=Ecosystem.NPM, name="grpc-bridge"),),
        source="osv/GO-2023-2153",
    )
    lookup = FakeLookup(GRPC.model_copy(update={"aliases": ()}), alias)
    exposure = service(engine, lookup)
    merged = exposure.find_advisory(GRPC.identifier)
    assert merged is not None and merged.advisory_id == first.advisory_id
    assert "GO-2023-2153" in lookup.asked
    assert {(package.ecosystem, package.name) for package in merged.affected} == {
        (Ecosystem.GO, "google.golang.org/grpc"),
        (Ecosystem.NPM, "grpc-bridge"),
    }
    assert set(aliases(engine, GRPC.identifier)) == {"GO-2023-2153", "CVE-2026-1000"}
    with SqlTraustUnitOfWork(engine) as uow:
        linked = {
            (package.ecosystem, package.name)
            for link in uow.advisory_packages.list_for_advisory(first.advisory_id)
            for package in [uow.packages.get(link.package_id)]
        }
    assert linked == {("go", "google.golang.org/grpc"), ("npm", "grpc-bridge")}


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


def test_a_cve_record_naming_no_package_takes_its_aliases_packages(engine: Engine) -> None:
    assert not CVE.affected
    lookup = FakeLookup(CVE, GO, GHSA)
    record = service(engine, lookup).find_advisory(CVE.identifier)
    assert record is not None and record.advisory_id is not None
    assert {(p.ecosystem, p.name) for p in record.affected} == {
        (Ecosystem.GO, "stdlib"),
        (Ecosystem.GO, "golang.org/x/net"),
    }
    # GO- and GHSA- both name x/net: one entry, with GO's symbols and every span
    xnet = record.package(Ecosystem.GO, "golang.org/x/net")
    go_xnet = GO.package(Ecosystem.GO, "golang.org/x/net")
    assert xnet is not None and go_xnet is not None
    assert xnet.symbols == go_xnet.symbols and set(go_xnet.spans) <= set(xnet.spans)
    assert set(record.sources) == {GHSA.source, GO.source}
    # BIT-golang-2023-39325 (Bitnami, unmodeled) is never asked
    assert "BIT-golang-2023-39325" not in lookup.asked
    with SqlTraustUnitOfWork(engine) as uow:
        assert len(uow.advisory_packages.list_for_advisory(record.advisory_id)) == 2


@pytest.mark.parametrize("first", [CVE, GO, GHSA], ids=lambda r: r.identifier)
def test_whichever_id_is_asked_first_every_alias_names_the_packages(
    engine: Engine, first: AdvisoryRecord
) -> None:
    exposure = service(engine, FakeLookup(CVE, GO, GHSA))
    found = [exposure.find_advisory(r.identifier) for r in (first, CVE, GO, GHSA)]
    assert all(r is not None and "golang.org/x/net" in {p.name for p in r.affected} for r in found)
    [canonical] = {r.advisory_id for r in found if r is not None}
    assert canonical is not None and len(exposure.packages_affected(canonical)) == 2


def test_a_record_naming_packages_never_asks_its_aliases(engine: Engine) -> None:
    lookup = FakeLookup(CVE, GO, GHSA)
    record = service(engine, lookup).find_advisory(GO.identifier)
    assert record is not None and record.affected == ()
    assert lookup.asked == ["GO-2023-2102"]


def test_aliases_stating_one_package_differently_keep_every_span(engine: Engine) -> None:
    def alias(identifier: str, introduced: str, fixed: str) -> AdvisoryRecord:
        span = AffectedSpan(introduced=Version(introduced), fixed=Version(fixed))
        lib = AffectedPackage(ecosystem=Ecosystem.NPM, name="example-lib", spans=(span,))
        return AdvisoryRecord(
            identifier=AdvisoryIdentifier(identifier), affected=(lib,), source=identifier
        )

    cve = AdvisoryRecord(
        identifier=AdvisoryIdentifier("CVE-2026-0001"),
        aliases=(AdvisoryIdentifier("GHSA-aaaa-aaaa-aaaa"), AdvisoryIdentifier("PYSEC-2026-1")),
        source="cve",
    )
    lookup = FakeLookup(
        cve, alias("GHSA-aaaa-aaaa-aaaa", "1.0.0", "1.2.0"), alias("PYSEC-2026-1", "2.0.0", "2.1.0")
    )
    record = service(engine, lookup).find_advisory(cve.identifier)
    assert record is not None
    [lib] = record.affected
    assert [lib.affects(Version(v)) for v in ("1.1.0", "2.0.5", "1.5.0")] == [True, True, False]


def test_a_withdrawn_record_takes_no_alias_packages(engine: Engine) -> None:
    lookup = FakeLookup(CVE.model_copy(update={"withdrawn": True}), GO, GHSA)
    record = service(engine, lookup).find_advisory(CVE.identifier)
    assert record is not None and record.affected == ()
    assert lookup.asked == ["CVE-2023-39325"]


def test_air_gapped_exports_listing_the_cve_first_still_fill_its_packages(
    engine: Engine, tmp_path: Path
) -> None:
    fixtures = Path(__file__).parents[2] / "fixtures/dependencies"
    ids = ("CVE-2023-39325", "GO-2023-2102", "GHSA-4374-p667-p6c8")
    lookup = ExportedAdvisoryLookup([fixtures / f"osv-{i}.json" for i in ids], clock=FixedClock(AT))
    record = service(engine, lookup).find_advisory(CVE.identifier)
    assert record is not None
    assert {p.name for p in record.affected} == {"stdlib", "golang.org/x/net"}


def test_withdrawn_or_unknown_aliases_add_no_package(engine: Engine) -> None:
    withdrawn = GHSA.model_copy(update={"withdrawn": True})
    record = service(engine, FakeLookup(CVE, withdrawn)).find_advisory(CVE.identifier)
    assert record is not None and record.affected == ()


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
