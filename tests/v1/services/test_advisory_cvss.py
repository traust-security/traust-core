"""ExposureService.refresh_advisory_cvss and advisory_cvss, on SQLite and Postgres: the daily
ranked build of every authority's scores, and its read, parsed once per publication."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Engine

from tests.v1.repositories.tables.conftest import Seed
from tests.v1.services.test_advisory_names import (
    AT,
    FIXTURES,
    LOG4SHELL,
    LOG4SHELL_GHSA,
    TEMPLATES,
    Http,
    advisory,
    alias_id,
    engine,  # noqa: F401 - the SQLite and Postgres fixture
    finding,
)
from traust_core.v1.errors import ConfigError, RepositoryError, ServiceError, ValidationError
from traust_core.v1.models.cvss import AdvisoryCvss, CvssSource
from traust_core.v1.models.feed_documents import AdvisoryCvssNotBuilt
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import (
    ADVISORY_CVSS_FEED,
    AdvisoryCvssCache,
    AdvisoryCvssReader,
    ExposureService,
)
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy

NVD = "https://nvd.test/cves?cveId=CVE-2021-44228"
OSV = f"https://osv.test/v1/vulns/{LOG4SHELL_GHSA}"


class World:
    """One store and one cache shared by every service it wires, as the Context shares them."""

    def __init__(self, db: Engine, sources: tuple[str, ...] = ("nvd", "ghsa")) -> None:
        self.engine = db
        self.http = Http()
        self.objects = InMemoryObjectStore()
        self.cache = AdvisoryCvssCache()
        self.sources = sources
        self.at = AT

    def service(self) -> ExposureService:
        registry: ProviderRegistry[FeedSource] = ProviderRegistry("feed-source")
        for name in self.sources:
            template, ident = TEMPLATES[name]
            source = FeedSource(
                name, template, template=template, ident=ident, post=False, probe=None,
                http=self.http, probe_http=self.http,  # type: ignore[arg-type]
                clock=FixedClock(self.at),
            )  # fmt: skip
            registry.register(name, lambda source=source: source)
        uow = SqlTraustUnitOfWork(self.engine)
        return ExposureService(
            uow,
            FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
            feeds=ProviderRegistry[FeedProvider]("feed"),
            feed_sources=registry,
            objects=self.objects,
            clock=FixedClock(self.at),
            advisory_cvss=self.cache,
        )

    def serve_log4shell(self) -> None:
        self.http.answers[NVD] = (FIXTURES / "nvd-CVE-2021-44228.json").read_bytes()
        self.http.answers[OSV] = (FIXTURES / "osv-GHSA-jfh8-c2jp-5v3q.json").read_bytes()

    def builds(self) -> list[UUID]:
        """Each build snapshot's artifact id, oldest first."""
        with SqlTraustUnitOfWork(self.engine) as uow:
            table = uow.feed_snapshots.table
            query = sa.select(table.c.artifact_id).where(table.c.feed == ADVISORY_CVSS_FEED)
            return list(uow.connection.scalars(query.order_by(table.c.retrieved_at)))


@pytest.fixture
def world(engine: Engine) -> World:  # noqa: F811
    return World(engine)


def test_the_document_refresh_ranks_every_authoritys_scores_by_canonical_advisory(
    world: World,
) -> None:
    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    assert canonical.id is not None
    read = world.service().advisory_cvss([canonical.id])
    assert read.built_at == AT
    scores = read.scores[canonical.id]
    assert [s.source for s in scores][:1] == [CvssSource.NIST]  # precedence order
    assert {s.source for s in scores} >= {CvssSource.NIST, CvssSource.GHSA}
    assert all(s.acquired_at == AT for s in scores)  # each from its kept document
    nist = scores[0]
    assert (nist.score, nist.document) == (Decimal("10.0"), f"nvd:{LOG4SHELL}")


def test_a_finding_naming_an_alias_reads_its_canonicals_scores_with_no_lookup(
    world: World,
) -> None:
    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    alias = alias_id(world.engine, LOG4SHELL)
    finding(world.engine, alias)  # the finding names the CVE alias row, not the canonical GHSA
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    assert canonical.id is not None
    read = world.service().advisory_cvss([alias, canonical.id])
    assert set(read.scores) == {alias, canonical.id}  # the build keys both
    assert read.scores[alias] == read.scores[canonical.id]
    assert {s.source for s in read.scores[alias]} >= {CvssSource.NIST, CvssSource.GHSA}


def test_an_alias_no_finding_names_is_not_in_the_build(world: World) -> None:
    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    read = world.service().advisory_cvss([alias_id(world.engine, LOG4SHELL)])
    assert dict(read.scores) == {}  # views read by the ids findings name, and only those


def test_before_the_first_build_nothing_is_scored_and_no_build_time_is_claimed(
    world: World,
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    assert canonical.id is not None
    read = world.service().advisory_cvss([canonical.id])
    assert (dict(read.scores), read.built_at) == ({}, None)


def test_an_advisory_no_authority_scored_is_absent_and_an_unparsed_document_is_named(
    world: World,
) -> None:
    scored = advisory(world.engine, LOG4SHELL)
    bare = advisory(world.engine, "CVE-2026-0003")  # its NVD answer is `{}`: no NVD record
    finding(world.engine, scored.id)
    finding(world.engine, bare.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    build = world.service().refresh_advisory_cvss()
    assert set(build.scores) == {scored.id}
    assert build.unreadable == ("nvd:CVE-2026-0003",)
    assert bare.id is not None
    assert bare.id not in world.service().advisory_cvss([bare.id]).scores


def test_an_unchanged_day_is_one_artifact_and_a_retry_in_its_order_adds_no_build(
    world: World,
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL).id)
    world.serve_log4shell()
    with SqlTraustUnitOfWork(world.engine) as uow:
        order = Seed(uow).run_order(asset="feeds_cache", lane=None).id
        uow.commit()
    svc = world.service()
    svc.refresh_advisory_documents(order)
    svc.refresh_advisory_cvss(order)  # the retry
    assert len(world.builds()) == 1
    svc.refresh_advisory_cvss()  # another order, the same scores: a new snapshot, one artifact
    builds = world.builds()
    assert len(builds) == 2 and len(set(builds)) == 1


def test_with_no_source_registered_nothing_is_built(engine: Engine) -> None:  # noqa: F811
    world = World(engine, sources=())
    finding(engine, advisory(engine, LOG4SHELL).id)
    assert world.service().refresh_advisory_documents() == []
    with pytest.raises(ConfigError, match="no advisory document source is registered"):
        world.service().refresh_advisory_cvss()
    assert world.builds() == []


@pytest.mark.parametrize(
    ("source", "url", "answer"),
    [
        ("nvd", "https://nvd.test/cves?cveId=CVE-2026-0003", "nvd-CVE-2021-44228.json"),
        # another CVE's record that states no score at all: still not this one's
        ("cve-list", "https://cve.test/api/cve/CVE-2026-0003", "rejected"),
    ],
)
def test_a_document_for_another_record_is_unreadable_even_with_no_scores(
    engine: Engine,  # noqa: F811
    source: str,
    url: str,
    answer: str,
) -> None:
    world = World(engine, sources=(source,))
    finding(engine, advisory(engine, "CVE-2026-0003").id)
    rejected = {"cveMetadata": {"cveId": LOG4SHELL, "state": "REJECTED"}}
    world.http.answers[url] = (
        json.dumps(rejected).encode() if answer == "rejected" else (FIXTURES / answer).read_bytes()
    )
    world.service().refresh_advisory_documents()
    build = world.service().refresh_advisory_cvss()
    assert dict(build.scores) == {}
    assert build.unreadable == (f"{source}:CVE-2026-0003",)


def test_an_nvd_reply_naming_no_record_is_unreadable(engine: Engine) -> None:  # noqa: F811
    world = World(engine, sources=("nvd",))
    finding(engine, advisory(engine, "CVE-2026-0003").id)
    empty = {"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    world.http.answers["https://nvd.test/cves?cveId=CVE-2026-0003"] = json.dumps(empty).encode()
    world.service().refresh_advisory_documents()
    assert world.service().refresh_advisory_cvss().unreadable == ("nvd:CVE-2026-0003",)


def test_an_unchanged_rebuild_after_a_failed_read_serves_its_scores(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    real = AdvisoryCvss.from_bytes

    def flaky(raw: bytes) -> AdvisoryCvss:
        raise ValidationError("not an advisory CVSS build (1 problem(s))")

    monkeypatch.setattr(AdvisoryCvss, "from_bytes", staticmethod(flaky))
    assert canonical.id is not None
    assert world.service().advisory_cvss([canonical.id]).unreadable
    monkeypatch.setattr(AdvisoryCvss, "from_bytes", staticmethod(real))
    world.at = AT + timedelta(days=1)
    world.service().refresh_advisory_cvss()  # the same bytes: the same artifact, a new snapshot
    builds = world.builds()
    assert len(builds) == 2 and len(set(builds)) == 1
    read = world.service().advisory_cvss([canonical.id])
    assert not read.unreadable and read.scores[canonical.id]


def test_a_build_whose_artifact_row_is_gone_reads_as_unreadable(world: World) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    with SqlTraustUnitOfWork(world.engine) as uow:
        latest = uow.feed_snapshots.latest(ADVISORY_CVSS_FEED)
    assert latest is not None and canonical.id is not None
    lost = latest.model_copy(update={"artifact_id": uuid4()})
    with SqlTraustUnitOfWork(world.engine) as uow:  # never raises: the read and freshness fold
        assert AdvisoryCvssReader(world.objects, world.cache).parsed(uow, lost) is None


def test_a_source_with_names_that_kept_nothing_is_named_and_the_build_is_not_fresh(
    world: World,
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    world.serve_log4shell()
    world.http.answers[OSV] = ServiceError("HTTP 503", status=503)  # its first refresh fails
    outcomes = {o.source: o for o in world.service().refresh_advisory_documents()}
    assert outcomes["nvd"].ok and not outcomes["ghsa"].ok
    build = world.service().refresh_advisory_cvss()
    assert build.unreadable == ("ghsa-documents",)
    [status] = [s for s in world.service().feed_statuses() if s.name == ADVISORY_CVSS_FEED]
    assert status.fetched_at is None and status.stale(AT)
    assert status.last_error == "no readable documents from ghsa-documents"


def test_the_build_is_as_old_as_its_oldest_sources_documents(world: World) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    world.at = AT + timedelta(days=2)
    world.http.answers[NVD] = ServiceError("HTTP 503", status=503)  # NVD keeps its day-0 manifest
    world.service().refresh_advisory_documents()
    statuses = {s.name: s for s in world.service().feed_statuses()}
    status = statuses[ADVISORY_CVSS_FEED]
    assert status.fetched_at == AT and status.stale(world.at)  # not the day-2 build time
    assert statuses["ghsa-documents"].fetched_at == world.at


def test_an_unreadable_build_reads_as_unreadable_and_is_not_fresh(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()

    def corrupt(raw: bytes) -> AdvisoryCvss:
        raise ValidationError("not an advisory CVSS build (1 problem(s))")

    monkeypatch.setattr(AdvisoryCvss, "from_bytes", staticmethod(corrupt))
    assert canonical.id is not None
    read = world.service().advisory_cvss([canonical.id])
    assert (dict(read.scores), read.built_at, read.unreadable) == ({}, AT, True)
    [status] = [s for s in world.service().feed_statuses() if s.name == ADVISORY_CVSS_FEED]
    assert status.fetched_at is None and status.last_error == "the latest build is unreadable"


def test_a_store_failure_in_the_build_raises_with_the_documents_outcomes(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    world.serve_log4shell()
    svc = world.service()

    def failing(*args: object) -> AdvisoryCvss:
        raise RepositoryError("the store is unreachable", operation="put")

    monkeypatch.setattr(svc, "_record_advisory_cvss", failing)
    with pytest.raises(AdvisoryCvssNotBuilt) as raised:
        svc.refresh_advisory_documents()
    assert str(raised.value) == (
        "advisory-cvss not built (RepositoryError: the store is unreachable); "
        "the documents were kept"
    )
    outcomes = {o.source: o for o in raised.value.outcomes}
    assert set(outcomes) == {"nvd", "ghsa"} and all(o.ok for o in outcomes.values())
    assert isinstance(raised.value, ServiceError) and world.builds() == []


def test_a_build_is_parsed_once_per_publication_across_services(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    parses = counting(monkeypatch)
    assert canonical.id is not None
    first = world.service().advisory_cvss([canonical.id])
    second = world.service().advisory_cvss([canonical.id])  # a new request's service
    assert first == second and parses() == 1
    world.http.answers[NVD] = (FIXTURES / "nvd-CVE-2026-9277.json").read_bytes()  # NVD changed
    world.service().refresh_advisory_documents()
    world.service().advisory_cvss([canonical.id])
    assert parses() == 2  # the new publication, parsed once


def test_an_unreadable_build_is_remembered_until_the_next_one() -> None:
    cache, reads = AdvisoryCvssCache(), []
    one, two = uuid4(), uuid4()

    def corrupt() -> bytes:
        reads.append(1)
        return b"not json"

    assert cache.parse(one, corrupt) is None
    assert cache.parse(one, corrupt) is None and len(reads) == 1  # not again in its publication
    good = AdvisoryCvss(scores={}).to_bytes()
    assert cache.parse(two, lambda: good) == AdvisoryCvss(scores={})


def test_a_build_that_is_not_one_is_refused() -> None:
    with pytest.raises(ValidationError, match="not an advisory CVSS build"):
        AdvisoryCvss.from_bytes(b'{"scores": {"x": []}}')


def test_the_build_is_in_feed_freshness_once_made_and_names_the_document_refresh(
    world: World,
) -> None:
    finding(world.engine, advisory(world.engine, LOG4SHELL).id)
    assert ADVISORY_CVSS_FEED not in {s.name for s in world.service().feed_statuses()}
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    [status] = [s for s in world.service().feed_statuses() if s.name == ADVISORY_CVSS_FEED]
    assert (status.fetched_at, status.max_age) == (AT, timedelta(hours=24))
    assert status.refresh == "refresh the advisory documents (refresh_advisory_documents)"
    assert not status.stale(AT + timedelta(hours=23))


def counting(monkeypatch: pytest.MonkeyPatch) -> Callable[[], int]:
    calls: list[int] = []
    real = AdvisoryCvss.from_bytes

    def parse(raw: bytes) -> AdvisoryCvss:
        calls.append(1)
        return real(raw)

    monkeypatch.setattr(AdvisoryCvss, "from_bytes", staticmethod(parse))
    return lambda: len(calls)


def test_a_pinned_reader_reads_which_build_once_and_forgets_it_after(world: World) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    assert canonical.id is not None
    reader = AdvisoryCvssReader(world.objects, world.cache)
    with reader.pinned():
        with SqlTraustUnitOfWork(world.engine) as uow:
            first = reader.read(uow, [canonical.id])
        world.at = AT + timedelta(days=1)
        world.service().refresh_advisory_cvss()  # a newer publication, mid-build
        with SqlTraustUnitOfWork(world.engine) as uow:
            assert reader.read(uow, [canonical.id]).built_at == first.built_at  # the same build
    with SqlTraustUnitOfWork(world.engine) as uow:
        after = reader.read(uow, [canonical.id])  # outside the block: the newer one
    assert after.built_at is not None and first.built_at is not None
    assert after.built_at > first.built_at


def test_a_store_failure_reading_the_build_is_no_build_and_never_kept(world: World) -> None:
    canonical = advisory(world.engine, LOG4SHELL)
    finding(world.engine, canonical.id)
    world.serve_log4shell()
    world.service().refresh_advisory_documents()
    assert canonical.id is not None
    reads: list[int] = []

    def outage() -> bytes:
        reads.append(1)
        raise RepositoryError("the store is unreachable", operation="get")

    one = uuid4()
    assert world.cache.parse(one, outage) is None
    assert world.cache.parse(one, outage) is None and len(reads) == 2  # retried, never kept
    assert world.cache.parse(one, lambda: AdvisoryCvss(scores={}).to_bytes()) is not None


def test_a_new_build_restamps_the_findings_naming_its_advisories(world: World) -> None:
    """A build moves a finding's selected authority score - its effective severity - with no
    write to the finding: the build restamps it, so the stored severity is the view's."""
    from decimal import Decimal

    from traust_core.v1.services.findings.rating import RatingConfig, RatingPolicy
    from traust_core.v1.services.findings.views import FindingViewQuery

    canonical = advisory(world.engine, LOG4SHELL_GHSA, LOG4SHELL)
    with SqlTraustUnitOfWork(world.engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url="https://github.com/org/stamped")
        named = seed.finding(repository, advisory_id=canonical.id, advisory_match="confirmed")
        run = seed.assessment(seed.repository_ref(repository))
        medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3: the report's own
        seed.occurrence(
            named, run, severity="medium", cvss_vector=medium, cvss_score=Decimal("5.3")
        )
        uow.commit()

    def stored() -> str | None:
        with world.engine.connect() as conn:
            table = "finding" if world.engine.dialect.name == "sqlite" else "traust.finding"
            return conn.exec_driver_sql(
                f"SELECT current_severity FROM {table} WHERE id = '{named.id}'"
            ).scalar()

    assert stored() == "medium"
    world.serve_log4shell()
    service = world.service()
    reader = AdvisoryCvssReader(world.objects, world.cache)
    service._intake = FindingIntake(  # the Context's wiring: the intake reads the builds
        service._uow, IdentityPolicy(), TaxonomyPolicy(), cvss=reader
    )
    service.refresh_advisory_documents()

    views = FindingViewQuery(RatingPolicy(RatingConfig()), world.objects, reader)
    with SqlTraustUnitOfWork(world.engine) as uow:
        (shown,) = views.views(uow, [uow.findings.get(named.id)])
    assert stored() == shown.effective_severity == "critical"  # Log4Shell's authority band
