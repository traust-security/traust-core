"""ExposureService.impacts and summary on SQLite and Postgres, over impact analyses recorded through
record; vex_status until its provider exists."""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_exposure_impact import (
    AT,
    GHSA,
    GRPC,
    Lookup,
    affected_doc,
    engine,
    refs,
    sbom,
)
from traust_core.v1.errors import ConfigError, IntegrityError, NotFoundError, ValidationError
from traust_core.v1.models.common import Cursor, PageRequest, Provenance, every_item
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    ExposureDimension,
    ExposureFilter,
    ImpactAnalysis,
    ImpactFilter,
)
from traust_core.v1.models.vocabulary import Ecosystem, ImpactClassification, SourceType
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.portfolio import PortfolioPolicy, PortfolioService

__all__ = ["engine"]

AFFECTED, IN_RANGE, OUT = ("v1.56.2", True), ("v1.56.2", False), ("v1.58.3", False)
CVE = AdvisoryIdentifier("CVE-2023-44487")


def reads(
    engine: Engine, *, findings: bool = True, objects: InMemoryObjectStore | None = None
) -> ExposureService:
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=objects or InMemoryObjectStore(),
        advisories=Lookup(GRPC),  # type: ignore[arg-type]
        portfolio=PortfolioService(uow, PortfolioPolicy()),
        clock=FixedClock(AT),
        findings=finding_service(engine) if findings else None,
    )


def record(exposure: ExposureService, ref_id: UUID, version: str, reached: bool, day: int):
    exposure.ingest_sbom(sbom(("google.golang.org/grpc", version)), ref_id)
    record = exposure.find_advisory(GHSA)
    assert record is not None and record.advisory_id is not None
    prepared = exposure.prepare(record.advisory_id, ref_id)
    doc = affected_doc(prepared) if reached else prepared.document("1.0.0")
    at = AT + timedelta(days=day)
    return exposure.record(
        ref_id, doc, Provenance(run_id=uuid4(), source=SourceType("impact_report"), occurred_at=at)
    )


def fleet(engine: Engine) -> tuple[ExposureService, list[ImpactAnalysis], list[UUID]]:
    """Three commits: affected, inconclusive (in range, unreached) and out of range; then the
    first rescanned out of range."""
    exposure = reads(engine)
    made = refs(engine, 3)
    ids = [r.id for r in made if r.id is not None]
    recorded = [
        record(exposure, ref_id, *case, day)
        for day, (ref_id, case) in enumerate(zip(ids, (AFFECTED, IN_RANGE, OUT), strict=True))
    ]
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.component(seed.release(seed.product(slug="product-a")), made[0])
        seed.component(seed.release(seed.product(slug="product-b")), made[0])
        seed.component(seed.release(seed.product(slug="product-c")), made[1])
        uow.commit()
    return exposure, recorded, ids


def test_impacts_are_newest_first_with_the_finding_an_affected_one_filed(engine: Engine) -> None:
    exposure, recorded, _ = fleet(engine)
    listed = exposure.impacts(ImpactFilter(), PageRequest()).items
    assert listed == tuple(reversed(recorded))
    assert [a.finding_id is not None for a in listed] == [False, False, True]
    assert listed[-1].finding_id == recorded[0].finding_id


@pytest.mark.parametrize("limit", [1, 2, 5])
def test_impacts_page_without_gaps_or_repeats(engine: Engine, limit: int) -> None:
    exposure, recorded, _ = fleet(engine)
    paged = list(every_item(lambda p: exposure.impacts(ImpactFilter(), p), limit))
    assert paged == list(reversed(recorded))


def test_impacts_narrow_by_commit_verdict_and_advisory_alias(engine: Engine) -> None:
    exposure, recorded, ids = fleet(engine)

    def found(**narrow: object) -> list[ImpactAnalysis]:
        return list(exposure.impacts(ImpactFilter(**narrow), PageRequest()).items)

    assert found(repository_ref_id=ids[1]) == [recorded[1]]
    assert found(classification=ImpactClassification.AFFECTED) == [recorded[0]]
    with SqlTraustUnitOfWork(engine) as uow:
        alias = uow.advisories.find_by_identifier("GO-2023-2153")
        assert alias is not None and alias.alias_of_id == recorded[0].advisory_id
    assert found(advisory_id=alias.id) == list(reversed(recorded))
    with SqlTraustUnitOfWork(engine) as uow:
        unrelated = Seed(uow).advisory()
        uow.commit()
    assert found(advisory_id=unrelated.id) == []
    with pytest.raises(NotFoundError):
        found(advisory_id=uuid4())


def test_no_impacts_recorded(engine: Engine) -> None:
    page = reads(engine).impacts(ImpactFilter(), PageRequest())
    assert (page.items, page.next) == ((), None)


@pytest.mark.parametrize(
    "page", [PageRequest(limit=0), PageRequest(cursor=Cursor("nope"))], ids=["zero", "cursor"]
)
def test_impacts_reject_a_bad_page(engine: Engine, page: PageRequest) -> None:
    with pytest.raises(ValidationError):
        reads(engine).impacts(ImpactFilter(), page)


def test_an_affected_impact_needs_the_finding_service(engine: Engine) -> None:
    exposure, _, _ = fleet(engine)
    with pytest.raises(ConfigError, match="finding service"):
        reads(engine, findings=False, objects=exposure._objects).impacts(
            ImpactFilter(), PageRequest()
        )


@pytest.mark.parametrize(
    ("group_by", "expected"),
    [
        (ExposureDimension.CLASSIFICATION, {"inconclusive": 1, "version_not_in_range": 2}),
        (ExposureDimension.ADVISORY, {"GHSA-m425-mq94-257g": 3}),
        (ExposureDimension.ECOSYSTEM, {"go": 3}),
        (ExposureDimension.PACKAGE, {"go/google.golang.org/grpc": 3}),
        (ExposureDimension.PRODUCT, {"product-a": 1, "product-b": 1, "product-c": 1, None: 1}),
    ],
)
def test_summary_counts_the_latest_analysis_of_each_commit(
    engine: Engine, group_by: ExposureDimension, expected: dict[str | None, int]
) -> None:
    exposure, _, ids = fleet(engine)
    record(exposure, ids[0], *OUT, day=9)  # the affected commit, rescanned after its fix
    rollups = exposure.summary(ExposureFilter(), group_by)
    assert {r.key: r.commits for r in rollups} == expected
    assert [r.commits for r in rollups] == sorted((r.commits for r in rollups), reverse=True)


def test_summary_counts_exposure_and_verdicts(engine: Engine) -> None:
    exposure, _, _ = fleet(engine)
    [rollup] = exposure.summary(ExposureFilter(), ExposureDimension.ADVISORY)
    assert (rollup.commits, rollup.exposed, rollup.affected) == (3, 2, 1)
    assert rollup.by_classification == {
        ImpactClassification.AFFECTED: 1,
        ImpactClassification.INCONCLUSIVE: 1,
        ImpactClassification.VERSION_NOT_IN_RANGE: 1,
    }
    by_repo = exposure.summary(ExposureFilter(), ExposureDimension.REPOSITORY)
    assert len(by_repo) == 3
    assert all((r.key or "").startswith("https://github.com/") for r in by_repo)


def test_summary_narrows_by_advisory_and_ecosystem(engine: Engine) -> None:
    exposure, recorded, _ = fleet(engine)
    advisory = recorded[0].advisory_id
    assert (
        exposure.summary(ExposureFilter(ecosystem=Ecosystem.NPM), ExposureDimension.ADVISORY) == []
    )
    [kept] = exposure.summary(
        ExposureFilter(advisory_id=advisory, ecosystem=Ecosystem.GO), ExposureDimension.ADVISORY
    )
    assert kept.commits == 3
    with SqlTraustUnitOfWork(engine) as uow:
        empty = Seed(uow).advisory()
        uow.commit()
    assert exposure.summary(ExposureFilter(advisory_id=empty.id), ExposureDimension.ADVISORY) == []


def test_an_impact_naming_an_advisory_never_kept_is_an_integrity_error(engine: Engine) -> None:
    exposure, recorded, _ = fleet(engine)
    with SqlTraustUnitOfWork(engine) as uow:
        for alias in uow.advisories.list_aliases(recorded[0].advisory_id):
            uow.advisories.update(alias.model_copy(update={"identifier": f"X-{alias.id}"}))
        canonical = uow.advisories.get(recorded[0].advisory_id)
        uow.advisories.update(canonical.model_copy(update={"identifier": "GHSA-gone-0000-0000"}))
        uow.commit()
    with pytest.raises(IntegrityError, match="never kept"):
        exposure.impacts(ImpactFilter(), PageRequest())


def test_vex_status_needs_a_provider_core_lacks(engine: Engine) -> None:
    with pytest.raises(ConfigError, match=r"NEED\(provider"):
        reads(engine).vex_status(CVE, uuid4())
