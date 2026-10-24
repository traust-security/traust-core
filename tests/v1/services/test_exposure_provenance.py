"""ExposureService.reconcile_provenance on SQLite and Postgres: which published CVE a finding
became, over a recorded page of the rh-cve feed (fixtures/dependencies/feeds/rh_cve_page.json)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.findings.test_reads import service as finding_service
from tests.v1.services.test_exposure_feeds import FakeFeed
from traust_core.v1.errors import ConfigError, ConflictError, NotFoundError, ValidationError
from traust_core.v1.models.dependencies import AdvisoryMatch, FeedName
from traust_core.v1.models.findings import Finding
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.feeds import FeedProvider, PublishedCve, rh_cve_records
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService, _provenance
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.findings.records import FindingRecords

PAGE = Path(__file__).parents[2] / "fixtures/dependencies/feeds/rh_cve_page.json"
SSRF = "CVE-2026-114620"  # authlib, published 2026-10-22, CWE-918


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def exposure(engine: Engine, payload: bytes | None = None, findings: bool = True):
    uow = SqlTraustUnitOfWork(engine)
    feeds: ProviderRegistry[FeedProvider] = ProviderRegistry("feed")
    feed = FakeFeed(PAGE.read_bytes() if payload is None else payload)
    feed.name, feed.filename = FeedName("rh-cve"), "rh_cve.json"
    feeds.register(feed.name, lambda: feed)
    service = ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=feeds,
        objects=InMemoryObjectStore(),
        findings=finding_service(engine) if findings else None,
    )
    service.refresh_feed(feed.name)
    return service


def finding(
    engine: Engine,
    title: str,
    repo: str = "authlib",
    cwe: str | None = None,
    reported: int | None = 0,
    **kw: object,
) -> Finding:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repository = seed.repository(url=f"https://github.com/org/{repo}")
        found = seed.finding(repository, title=title, **kw)
        if reported is not None:
            run = seed.assessment(seed.repository_ref(repository), occurred_at=T0)
            later = seed.assessment(
                seed.repository_ref(repository, name="next"),
                occurred_at=T0 + timedelta(days=reported),
            )
            seed.occurrence(found, later)
            seed.occurrence(found, run)
        if cwe:
            seed.finding_cwe(found, seed.cwe(identifier=cwe))
        uow.commit()
    return found


def stored(engine: Engine, finding_id: UUID | None) -> Finding:
    with SqlTraustUnitOfWork(engine) as uow:
        return uow.findings.get(finding_id)  # type: ignore[arg-type]


def test_the_best_match_is_recorded_once(engine: Engine) -> None:
    ours = finding(engine, "Server-side request forgery via unvalidated request URI")
    service = exposure(engine)
    check = service.reconcile_provenance(ours.id)  # type: ignore[arg-type]
    [best] = check.matches
    assert (best.identifier, best.match, best.published) == (
        SSRF,
        AdvisoryMatch.CONFIRMED,
        date(2026, 10, 22),
    )
    assert (best.lead_days, best.severity) == (17, "moderate")
    assert (check.recorded, check.linked, check.conflict) == (SSRF, True, False)
    saved = stored(engine, ours.id)
    assert saved.advisory_match == "confirmed"
    assert [a.identifier for a in service.advisories_for(ours.id)] == [SSRF]  # type: ignore[arg-type]
    again = service.reconcile_provenance(ours.id)  # type: ignore[arg-type]
    assert (again.recorded, again.linked, again.conflict) == (SSRF, False, False)
    assert stored(engine, ours.id) == saved


def test_the_first_report_dates_the_finding(engine: Engine) -> None:
    """Reported again after the CVE was public: still ours, dated by its first report."""
    ours = finding(engine, "Server-side request forgery via unvalidated request URI", reported=30)
    [best] = exposure(engine).reconcile_provenance(ours.id).matches  # type: ignore[arg-type]
    assert best.lead_days == 17


@pytest.mark.parametrize(
    ("title", "repo", "cwe"),
    [
        ("Server-side request forgery via unvalidated request URI", "other-repo", None),
        ("Hardcoded credentials in the deployment manifest", "authlib", "CWE-918"),
    ],
    ids=["another component", "unlike title"],
)
def test_no_match_records_nothing(engine: Engine, title: str, repo: str, cwe: str | None) -> None:
    ours = finding(engine, title, repo, cwe)
    check = exposure(engine).reconcile_provenance(ours.id)  # type: ignore[arg-type]
    assert (check.matches, check.recorded, check.linked) == ((), None, False)
    assert stored(engine, ours.id).advisory_id is None


def test_a_finding_naming_another_advisory_is_a_conflict_left_as_is(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        other = Seed(uow).advisory(identifier="CVE-2026-0001")
        uow.commit()
    ours = finding(
        engine,
        "Server-side request forgery via unvalidated request URI",
        advisory_id=other.id,
        advisory_match="probable",
    )
    check = exposure(engine).reconcile_provenance(ours.id)  # type: ignore[arg-type]
    assert (check.recorded, check.linked, check.conflict) == ("CVE-2026-0001", False, True)
    assert stored(engine, ours.id).advisory_id == other.id


def test_a_finding_already_naming_the_match_agrees(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        known = Seed(uow).advisory(identifier=SSRF)
        uow.commit()
    ours = finding(
        engine,
        "Server-side request forgery via unvalidated request URI",
        advisory_id=known.id,
        advisory_match="confirmed",
    )
    check = exposure(engine).reconcile_provenance(ours.id)  # type: ignore[arg-type]
    assert (check.recorded, check.linked, check.conflict) == (SSRF, False, False)


def test_a_known_cve_is_linked_not_duplicated(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        known = Seed(uow).advisory(identifier=SSRF)
        uow.commit()
    ours = finding(engine, "Server-side request forgery via unvalidated request URI")
    exposure(engine).reconcile_provenance(ours.id)  # type: ignore[arg-type]
    assert stored(engine, ours.id).advisory_id == known.id


@pytest.mark.parametrize(
    ("make", "error", "match"),
    [
        (lambda e: finding(e, "x", reported=None).id, NotFoundError, "never reported"),
        (lambda e: uuid4(), NotFoundError, "finding"),
    ],
    ids=["never reported", "unknown finding"],
)
def test_what_cant_be_reconciled(engine: Engine, make, error, match) -> None:
    finding_id = make(engine)
    with pytest.raises(error, match=match):
        exposure(engine).reconcile_provenance(finding_id)


def test_reconcile_needs_the_finding_service(engine: Engine) -> None:
    ours = finding(engine, "Server-side request forgery via unvalidated request URI")
    with pytest.raises(ConfigError, match="finding service"):
        exposure(engine, findings=False).reconcile_provenance(ours.id)  # type: ignore[arg-type]


def test_reconcile_needs_a_fetched_feed(engine: Engine) -> None:
    ours = finding(engine, "Server-side request forgery via unvalidated request URI")
    uow = SqlTraustUnitOfWork(engine)
    unfetched = ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        objects=InMemoryObjectStore(),
        findings=finding_service(engine),
    )
    with pytest.raises(NotFoundError, match="rh-cve: never fetched"):
        unfetched.reconcile_provenance(ours.id)  # type: ignore[arg-type]


def test_link_advisory_refuses_a_finding_naming_one(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        first, second = seed.advisory(), seed.advisory()
        found = seed.finding(advisory_id=first.id, advisory_match="confirmed")
        uow.commit()
    with pytest.raises(ConflictError, match="already names"):
        FindingRecords(SqlTraustUnitOfWork(engine)).link_advisory(
            found.id, second.id, AdvisoryMatch.PROBABLE
        )  # type: ignore[arg-type]


CVE_DAY = date(2026, 10, 22)


def published(title: str, cwes: tuple[str, ...] = ("CWE-863",), day: date = CVE_DAY):
    return PublishedCve(
        identifier="CVE-2026-1", published=day, component="comp", title=title, cwes=cwes
    )


@pytest.mark.parametrize(
    ("cve", "title", "cwes", "expected"),
    [
        # Jaccard alone put this real pair at 0.457; the sequence ratio rescues it.
        (
            published("Default authentication mode is no_auth"),
            "Default authentication mode is noauth",
            (),
            AdvisoryMatch.CONFIRMED,
        ),
        (published("Broker token stored in cleartext"), "Broker token stored cleartext", (), "c"),
        # Mid band: a shared CWE promotes, a sibling CWE still stamps, just weaker.
        (
            published("Tenant isolation bypass in API"),
            "Tenant isolation bypass through admin console routes",
            ("CWE-863",),
            "c",
        ),
        (
            published("Tenant isolation bypass in API"),
            "Tenant isolation bypass through admin console routes",
            ("CWE-302",),
            "p",
        ),
        (published("Unrelated thing"), "Broker token stored cleartext", ("CWE-863",), None),
        (
            published("Broker token stored cleartext", day=T0.date()),
            "Broker token stored cleartext",
            (),
            None,
        ),
    ],
)
def test_matching_rules(cve: PublishedCve, title: str, cwes: tuple[str, ...], expected) -> None:
    want = {"c": AdvisoryMatch.CONFIRMED, "p": AdvisoryMatch.PROBABLE}.get(expected, expected)
    found = _provenance(cve, "comp", T0.date(), title, cwes)
    assert (found.match if found else None) == want


def test_the_feed_page_parses_into_component_and_title() -> None:
    records = rh_cve_records(PAGE.read_bytes())
    assert [(r.identifier, r.component, r.cwes) for r in records] == [
        ("CVE-2026-114620", "authlib", ("CWE-918",)),
        ("CVE-2026-114619", "authlib", ("CWE-807",)),
        ("CVE-2026-114618", "authlib", ("CWE-358",)),
    ]
    assert records[0].title == "Server-Side Request Forgery via unvalidated request URI"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (
            {"CVE": "CVE-1", "public_date": "2026-01-02", "bugzilla_description": "no colon"},
            (None, "no colon", ()),
        ),
        (
            {"CVE": "CVE-1", "public_date": "2026-01-02T00:00:00Z", "CWE": "(CWE-1|CWE-2)->CWE-1"},
            (None, "", ("CWE-1", "CWE-2")),
        ),
    ],
)
def test_odd_records(record: dict[str, str], expected: tuple[object, ...]) -> None:
    [parsed] = rh_cve_records(json.dumps([record]).encode())
    assert (parsed.component, parsed.title, parsed.cwes) == expected


@pytest.mark.parametrize(
    ("payload", "kept"),
    [([{"public_date": "2026-01-02"}, {"CVE": "CVE-1"}], 0), ([], 0)],
)
def test_records_without_an_id_or_date_are_skipped(payload: list[object], kept: int) -> None:
    assert len(rh_cve_records(json.dumps(payload).encode())) == kept


@pytest.mark.parametrize(
    "payload",
    [
        b'{"CVE": "CVE-1"}',
        b"not json",
        json.dumps([{"CVE": "CVE-1", "public_date": "soon"}]).encode(),
    ],
)
def test_malformed_pages_raise(payload: bytes) -> None:
    with pytest.raises(ValidationError):
        rh_cve_records(payload)
