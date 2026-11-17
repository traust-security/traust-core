"""ExposureService.advisory_names (the D14 door) and refresh_advisory_documents, on SQLite and
Postgres: every advisory join goes through a finding's canonical name and all its aliases."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import Seed
from traust_core.v1.errors import RepositoryError, ServiceError
from traust_core.v1.models.cvss import CvssSource, nvd_scores
from traust_core.v1.models.dependencies import Advisory, AdvisoryMatch
from traust_core.v1.providers.base import ProviderRegistry
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.feeds import FeedProvider, FeedSource
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.repositories.objects import InMemoryObjectStore
from traust_core.v1.services.exposure import ExposureService
from traust_core.v1.services.findings import FindingIntake, IdentityPolicy, TaxonomyPolicy
from traust_core.v1.services.findings.cvss import effective

AT = datetime(2026, 11, 17, tzinfo=UTC)
FIXTURES = Path(__file__).parents[2] / "fixtures/dependencies/cvss"
LOG4SHELL, LOG4SHELL_GHSA = "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"
TEMPLATES = {
    "cve-list": ("https://cve.test/api/cve/{ident_upper}", "cve"),
    "nvd": ("https://nvd.test/cves?cveId={ident_upper}", "cve"),
    "ghsa": ("https://osv.test/v1/vulns/{ident}", "ghsa"),
}


class Http:
    """Serves each URL's queued body (default `{}`), or raises its queued error."""

    def __init__(self) -> None:
        self.answers: dict[str, bytes | Exception] = {}
        self.asked: list[str] = []

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        secret_headers: dict[str, str] | None = None,
        limit: int | None = None,
    ) -> bytes:
        self.asked.append(url)
        answer = self.answers.get(url, b"{}")
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def exposure(
    engine: Engine, http: Http, sources: tuple[str, ...] = tuple(TEMPLATES)
) -> ExposureService:
    registry: ProviderRegistry[FeedSource] = ProviderRegistry("feed-source")
    for name in sources:
        template, ident = TEMPLATES[name]
        source = FeedSource(
            name, template, template=template, ident=ident, post=False, probe=None,
            http=http, probe_http=http,  # type: ignore[arg-type]
            clock=FixedClock(AT),
        )  # fmt: skip
        registry.register(name, lambda source=source: source)
    uow = SqlTraustUnitOfWork(engine)
    return ExposureService(
        uow,
        FindingIntake(uow, IdentityPolicy(), TaxonomyPolicy()),
        feeds=ProviderRegistry[FeedProvider]("feed"),
        feed_sources=registry,
        objects=InMemoryObjectStore(),
        clock=FixedClock(AT),
    )


def advisory(engine: Engine, identifier: str, *aliases: str) -> Advisory:
    """A canonical advisory and its alias rows, as `_keep_advisory` records them."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        canonical = seed.advisory(identifier=identifier)
        for alias in aliases:
            seed.advisory(identifier=alias, alias_of_id=canonical.id)
        uow.commit()
    return canonical


def finding(engine: Engine, advisory_id: UUID | None) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        match = None if advisory_id is None else AdvisoryMatch.CONFIRMED
        seed = Seed(uow)
        repository = seed.repository(url=f"https://github.com/org/{uuid4().hex}")
        made = seed.finding(
            repository, advisory_id=advisory_id, advisory_match=match, fingerprint=uuid4().hex
        )
        uow.commit()
    assert made.id is not None
    return made.id


def alias_id(engine: Engine, identifier: str) -> UUID:
    with SqlTraustUnitOfWork(engine) as uow:
        found = uow.advisories.find_by_identifier(identifier)
    assert found is not None and found.id is not None
    return found.id


def test_a_ghsa_canonical_findings_names_carry_its_cve_alias(engine: Engine) -> None:
    canonical = advisory(engine, LOG4SHELL_GHSA, LOG4SHELL)
    one = finding(engine, canonical.id)
    names = exposure(engine, Http()).advisory_names([one])[one]
    assert names.advisory_id == canonical.id
    assert names.identifiers == (LOG4SHELL_GHSA, LOG4SHELL)  # canonical first
    assert (names.cves, names.ghsas) == ((LOG4SHELL,), (LOG4SHELL_GHSA,))


def test_a_finding_naming_an_alias_gets_the_canonical_advisorys_names(engine: Engine) -> None:
    canonical = advisory(engine, "GO-2021-1234", "CVE-2021-0002", LOG4SHELL_GHSA)
    one = finding(engine, alias_id(engine, "CVE-2021-0002"))
    names = exposure(engine, Http()).advisory_names([one])[one]
    assert names.advisory_id == canonical.id and names.identifiers[0] == "GO-2021-1234"
    assert set(names.identifiers) == {"GO-2021-1234", "CVE-2021-0002", LOG4SHELL_GHSA}


def test_a_ghsa_naming_several_cves_names_each_once_in_upper_case(engine: Engine) -> None:
    canonical = advisory(engine, LOG4SHELL_GHSA, "cve-2021-0001", "CVE-2021-0001", LOG4SHELL)
    one = finding(engine, canonical.id)
    assert exposure(engine, Http()).advisory_names([one])[one].cves == (
        "CVE-2021-0001",
        LOG4SHELL,
    )


def test_findings_without_an_advisory_are_absent_and_shared_ones_resolve_once(
    engine: Engine,
) -> None:
    canonical = advisory(engine, LOG4SHELL)
    a, b, bare = finding(engine, canonical.id), finding(engine, canonical.id), finding(engine, None)
    names = exposure(engine, Http()).advisory_names([a, b, bare])
    assert set(names) == {a, b} and names[a] == names[b]
    assert exposure(engine, Http()).advisory_names([]) == {}


def test_the_refresh_sends_cves_to_the_cve_sources_and_ghsas_to_ghsa(engine: Engine) -> None:
    finding(engine, advisory(engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    finding(engine, advisory(engine, "CVE-2026-0003").id)
    finding(engine, advisory(engine, "PYSEC-2026-1").id)  # a name no source serves
    http = Http()
    outcomes = exposure(engine, http).refresh_advisory_documents()
    assert [(o.source, o.requested, o.error) for o in outcomes] == [
        ("cve-list", 2, None),
        ("nvd", 2, None),
        ("ghsa", 1, None),
    ]  # rh-cve isn't registered here, so it is skipped
    assert sorted(http.asked) == sorted(
        [
            "https://cve.test/api/cve/CVE-2021-44228",
            "https://cve.test/api/cve/CVE-2026-0003",
            "https://nvd.test/cves?cveId=CVE-2021-44228",
            "https://nvd.test/cves?cveId=CVE-2026-0003",
            f"https://osv.test/v1/vulns/{LOG4SHELL_GHSA}",
        ]
    )


def test_a_failing_source_says_why_and_the_others_still_refresh(engine: Engine) -> None:
    finding(engine, advisory(engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    http = Http()
    nvd_url = "https://nvd.test/cves?cveId=CVE-2021-44228"
    http.answers[nvd_url] = ServiceError("HTTP 503", status=503)
    svc = exposure(engine, http)
    by_source = {o.source: o for o in svc.refresh_advisory_documents()}
    failed = by_source["nvd"]
    assert failed.refresh is None and "no document fetched" in (failed.error or "")
    assert by_source["cve-list"].refresh is not None and by_source["ghsa"].refresh is not None
    assert svc.stored_document("cve-list", LOG4SHELL) is not None


def test_with_no_ghsa_anywhere_the_ghsa_source_is_asked_for_nothing(engine: Engine) -> None:
    finding(engine, advisory(engine, LOG4SHELL).id)
    svc = exposure(engine, Http(), sources=("ghsa",))
    [outcome] = svc.refresh_advisory_documents()
    assert (outcome.requested, outcome.refresh, outcome.error) == (0, None, None)
    assert svc.document_manifest("ghsa") is None  # nothing asked, nothing written


def test_a_ghsa_canonical_finding_gets_nists_score_for_its_cve_alias(engine: Engine) -> None:
    """The plan's proof fixture (D14): a join on the canonical id finds no NVD record at all."""
    canonical = advisory(engine, LOG4SHELL_GHSA, LOG4SHELL)
    one = finding(engine, canonical.id)
    http = Http()
    nvd = (FIXTURES / "nvd-CVE-2021-44228.json").read_bytes()
    http.answers["https://nvd.test/cves?cveId=CVE-2021-44228"] = nvd
    svc = exposure(engine, http, sources=("nvd",))
    svc.refresh_advisory_documents()
    names = svc.advisory_names([one])[one]
    assert svc.stored_document("nvd", names.identifiers[0]) is None  # the naive join: nothing
    scores = [
        s
        for cve in names.cves
        if (doc := svc.stored_document("nvd", cve)) is not None
        for s in nvd_scores(doc.data, acquired_at=doc.acquired_at)
    ]
    chosen = effective(scores)
    assert chosen.source is CvssSource.NIST and chosen.score is not None
    assert json.loads(nvd)["vulnerabilities"][0]["cve"]["id"] == LOG4SHELL


def test_closed_findings_and_alias_pointing_ones_are_refreshed_in_one_spelling(
    engine: Engine,
) -> None:
    """Every linked advisory is kept (owner, 2026-11-17), however its findings stand."""
    advisory(engine, "GO-2021-0001", "cve-2021-0004", "ghsa-jfh8-c2jp-5v3q")
    closed = finding(engine, alias_id(engine, "cve-2021-0004"))
    with SqlTraustUnitOfWork(engine) as uow:
        uow.decisions.add(
            Seed(uow).new_decision(uow.findings.get(closed), validity="false_positive")
        )
        uow.commit()
    http = Http()
    exposure(engine, http).refresh_advisory_documents()
    assert sorted(http.asked) == [
        "https://cve.test/api/cve/CVE-2021-0004",
        "https://nvd.test/cves?cveId=CVE-2021-0004",
        f"https://osv.test/v1/vulns/{LOG4SHELL_GHSA}",
    ]


def test_a_source_whose_storage_fails_is_reported_and_the_rest_still_refresh(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding(engine, advisory(engine, LOG4SHELL_GHSA, LOG4SHELL).id)
    svc = exposure(engine, Http())
    real = svc.refresh_documents

    def failing(source: str, *args: object, **kw: object) -> object:
        if source == "cve-list":
            try:
                raise TimeoutError("socket closed")
            except TimeoutError as cause:
                raise RepositoryError("the store is unreachable", operation="put") from cause
        return real(source, *args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(svc, "refresh_documents", failing)
    by_source = {o.source: o for o in svc.refresh_advisory_documents()}
    failed = by_source["cve-list"]
    assert not failed.ok
    assert failed.error == "RepositoryError: the store is unreachable (cause TimeoutError, in put)"
    assert by_source["nvd"].ok and by_source["ghsa"].ok
    assert by_source["nvd"].refresh is not None and by_source["ghsa"].refresh is not None


def test_when_every_source_asked_fails_the_refresh_raises_with_each_reason(engine: Engine) -> None:
    finding(engine, advisory(engine, LOG4SHELL).id)
    http = Http()
    for url in (
        "https://cve.test/api/cve/CVE-2021-44228",
        "https://nvd.test/cves?cveId=CVE-2021-44228",
    ):
        http.answers[url] = ServiceError(f"{url}: HTTP 503", status=503)
    with pytest.raises(ServiceError) as raised:
        exposure(engine, http).refresh_advisory_documents()  # ghsa is asked for nothing
    message = str(raised.value)
    assert message.startswith("no advisory documents refreshed (cve-list: ")
    assert "; nvd: " in message and "cveId" not in message  # the query is redacted


def test_with_no_linked_advisory_nothing_is_asked_and_nothing_raises(engine: Engine) -> None:
    finding(engine, None)
    outcomes = exposure(engine, Http()).refresh_advisory_documents()
    assert [(o.requested, o.ok) for o in outcomes] == [(0, True)] * 3


@pytest.mark.parametrize(
    ("raw", "kept"),
    [
        (
            "https://nvd.test/cves?cveId=CVE-1&token=s3cret: HTTP 500",
            "https://nvd.test/cves?…: HTTP 500",
        ),
        (
            "https://u:s3cret@cve.test/api/cve/CVE-1: HTTP 404",
            "https://cve.test/api/cve/CVE-1: HTTP 404",
        ),
        ("https://u:p@h.test/x?a=s3cret#frag gave up", "https://h.test/x?…#frag gave up"),
        ("no url here: HTTP 500", "no url here: HTTP 500"),
    ],
)
def test_a_failures_text_never_carries_a_urls_credentials_or_query(raw: str, kept: str) -> None:
    from traust_core.v1.services.exposure import _redacted

    assert _redacted(raw) == kept
