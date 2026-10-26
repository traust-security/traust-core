from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AffectedSpan,
    Package,
    PackageVersion,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.osv import OsvAdvisoryLookup, parse_osv

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"
AT = datetime(2026, 10, 23, tzinfo=UTC)
GRPC = (FIXTURES / "osv-GHSA-m425-mq94-257g.json").read_bytes()
LOG4SHELL = (FIXTURES / "osv-GHSA-jfh8-c2jp-5v3q.json").read_bytes()


class FakeHttp:
    def __init__(self, outcome: bytes | Exception) -> None:
        self.outcome = outcome
        self.urls: list[str] = []

    def get(self, url: str) -> bytes:
        self.urls.append(url)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def lookup(http: FakeHttp, base: str = "https://osv.test/v1/") -> OsvAdvisoryLookup:
    return OsvAdvisoryLookup(base, http=http, clock=FixedClock(AT))  # type: ignore[arg-type]


def osv(*affected: dict[str, object], **extra: object) -> bytes:
    return json.dumps({"id": "GHSA-test", "affected": list(affected), **extra}).encode()


def affected(*ranges: dict[str, object], name: str = "lib", ecosystem: str = "Go", **kw: object):
    return {"package": {"name": name, "ecosystem": ecosystem}, "ranges": list(ranges), **kw}


def semver(*events: dict[str, str], kind: str = "SEMVER") -> dict[str, object]:
    return {"type": kind, "events": list(events)}


def test_a_real_record_merges_entries_for_one_package() -> None:
    record = parse_osv(GRPC, "https://osv.test/v1/vulns/GHSA-m425-mq94-257g")
    assert record.identifier == "GHSA-m425-mq94-257g"
    assert record.aliases == ("GO-2023-2153",)
    assert record.published_at == datetime(2023, 10, 25, 21, 17, 37, tzinfo=UTC)
    assert record.declared_severity == "HIGH"
    assert record.cvss_vectors == ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",)
    [grpc] = record.affected
    assert (grpc.ecosystem, grpc.name) == (Ecosystem.GO, "google.golang.org/grpc")
    assert grpc.vulnerable_range == "<1.56.3 || >=1.57.0 <1.57.1 || >=1.58.0 <1.58.3"
    assert grpc.affects(Version("v1.57.0")) is True
    assert grpc.fixed_in(Version("v1.58.1")) == "1.58.3"
    assert record.source.endswith("GHSA-m425-mq94-257g")


def test_a_real_maven_record_keeps_listed_versions_and_last_affected() -> None:
    record = parse_osv(LOG4SHELL, "src")
    assert record.aliases == ("CVE-2021-44228",)
    core = record.package(Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core")
    assert core is not None
    assert core.affects(Version("2.14.1")) is True
    assert core.affects(Version("2.15.0")) is False
    assert core.fixed_in(Version("2.14.1")) == "2.15.0"
    guiced = record.package(Ecosystem.MAVEN, "com.guicedee.services:log4j-core")
    assert guiced is not None and guiced.spans[0].last_affected == "1.2.1.2-jre17"
    unranged = record.package(Ecosystem.MAVEN, "org.xbib.elasticsearch:log4j")
    assert unranged is not None and unranged.spans == () and len(unranged.versions) == 1


def test_spans_follow_the_events() -> None:
    record = parse_osv(
        osv(
            affected(
                semver({"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}),
                semver({"introduced": "1.0.0"}, {"last_affected": "1.4.0"}),
                {"events": [{"fixed": "9.9.9"}]},
                semver({"introduced": "0"}, {"fixed": "abc123"}, kind="GIT"),
            )
        ),
        "src",
    )
    assert record.affected[0].spans == (
        AffectedSpan(introduced=Version("0"), fixed=Version("1.5.0")),
        AffectedSpan(introduced=Version("2.0.0")),
        AffectedSpan(introduced=Version("1.0.0"), last_affected=Version("1.4.0")),
        AffectedSpan(introduced=Version("0"), fixed=Version("9.9.9")),
    )


def test_distro_ecosystems_map_and_unknown_ones_are_listed_not_dropped() -> None:
    record = parse_osv(
        osv(
            affected(name="openssl", ecosystem="Debian:12"),
            affected(name="openssl", ecosystem="Alpine:v3.18"),
            affected(name="lib", ecosystem="Hackage"),
            {"package": {"ecosystem": "npm"}},
        ),
        "src",
    )
    assert [p.ecosystem for p in record.affected] == [Ecosystem.DEB, Ecosystem.APK]
    assert record.unmodeled_ecosystems == ("Hackage", "npm")


def test_severity_vectors_come_from_the_record_and_each_entry() -> None:
    record = parse_osv(
        osv(
            affected(severity=[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]),
            severity=[
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L"},
                {"type": "Ubuntu", "score": "x"},
            ],
            references=[
                {"type": "FIX", "url": "https://example.test/commit/1"},
                {"type": "WEB", "url": "https://example.test/advisory"},
                {"type": "FIX"},
            ],
        ),
        "src",
    )
    assert record.cvss_vectors == ("CVSS:3.1/AV:L", "CVSS:4.0/AV:N")
    assert record.fix_references == ("https://example.test/commit/1",)
    assert record.references == ("https://example.test/commit/1", "https://example.test/advisory")


@pytest.mark.parametrize(
    "raw", [b"{broken", b"[]", b'{"affected": []}', b'{"id": "X", "affected": 1}']
)
def test_a_malformed_record_is_a_validation_error(raw: bytes) -> None:
    with pytest.raises(ValidationError, match="malformed OSV record"):
        parse_osv(raw, "src")


def test_lookup_fetches_the_record_by_quoted_id_from_the_base() -> None:
    http = FakeHttp(GRPC)
    result = lookup(http).record(AdvisoryIdentifier("GHSA-m425-mq94-257g"))
    assert http.urls == ["https://osv.test/v1/vulns/GHSA-m425-mq94-257g"]
    assert result.data is not None and result.data.source == http.urls[0]
    assert (result.acquisition.provider, result.acquisition.acquired_at) == ("osv", AT)


def test_an_unknown_advisory_is_none() -> None:
    result = lookup(FakeHttp(ServiceError("HTTP 404", status=404))).record(
        AdvisoryIdentifier("CVE-2099-0001")
    )
    assert result.data is None


@pytest.mark.parametrize("status", [None, 400, 503])
def test_other_failures_raise(status: int | None) -> None:
    with pytest.raises(ServiceError):
        lookup(FakeHttp(ServiceError("down", status=status))).record(
            AdvisoryIdentifier("CVE-2099-0001")
        )


def test_go_records_publish_their_vulnerable_packages_and_symbols() -> None:
    record = parse_osv(
        osv(
            affected(
                semver({"introduced": "0"}, {"fixed": "1.56.3"}),
                name="google.golang.org/grpc",
                ecosystem_specific={
                    "imports": [
                        {
                            "path": "google.golang.org/grpc",
                            "symbols": ["Server.Serve", "NewServer"],
                        },
                        {"path": "google.golang.org/grpc/internal/transport"},
                    ]
                },
            ),
            upstream=["CVE-2023-44487"],
        ),
        "src",
    )
    [grpc] = record.affected
    assert grpc.imports == ("google.golang.org/grpc", "google.golang.org/grpc/internal/transport")
    assert grpc.symbols == (
        "google.golang.org/grpc.Server.Serve",
        "google.golang.org/grpc.NewServer",
    )
    assert record.upstream == ("CVE-2023-44487",)


class FakePost:
    """querybatch answers walked in order; an answer is an object (JSON) or an exception."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.sent: list[tuple[str, dict[str, object]]] = []

    def post_json(self, url: str, doc: dict[str, object]) -> bytes:
        self.sent.append((url, doc))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, bytes) else json.dumps(answer).encode()


def pv(ecosystem: str, name: str, version: str) -> PackageVersion:
    return PackageVersion(package=Package(ecosystem=ecosystem, name=name), version=Version(version))


def vulns(*ids: str, token: str | None = None) -> dict[str, object]:
    return {"vulns": [{"id": i} for i in ids], **({"next_page_token": token} if token else {})}


@pytest.mark.parametrize(
    ("ecosystem", "name", "version", "osv_eco", "sent"),
    [
        ("go", "golang.org/x/net", "v0.1.0", "Go", "0.1.0"),
        ("npm", "@scope/x", "v1.2.3", "npm", "v1.2.3"),
        ("pypi", "django", "4.2.0", "PyPI", "4.2.0"),
        ("maven", "org.apache:log4j", "2.14.1", "Maven", "2.14.1"),
        ("cargo", "serde", "1.0.0", "crates.io", "1.0.0"),
        ("ruby", "rails", "7.0.0", "RubyGems", "7.0.0"),
        ("nuget", "Newtonsoft.Json", "13.0.1", "NuGet", "13.0.1"),
        ("actions", "actions/checkout", "v4", "GitHub Actions", "v4"),
    ],
)
def test_each_package_version_is_asked_in_osvs_words(
    ecosystem: str, name: str, version: str, osv_eco: str, sent: str
) -> None:
    http = FakePost({"results": [{}]})
    lookup(http).affecting([pv(ecosystem, name, version)])  # type: ignore[arg-type]
    [(url, doc)] = http.sent
    assert url == "https://osv.test/v1/querybatch"
    assert doc == {"queries": [{"package": {"ecosystem": osv_eco, "name": name}, "version": sent}]}


@pytest.mark.parametrize("ecosystem", ["docker", "helm", "deb", "rpm", "apk"])
def test_ecosystems_osv_cant_answer_by_name_are_refused(ecosystem: str) -> None:
    assert Ecosystem(ecosystem) not in OsvAdvisoryLookup.ecosystems
    with pytest.raises(ValidationError, match="no by-name coverage"):
        lookup(FakePost()).affecting([pv(ecosystem, "x", "1")])  # type: ignore[arg-type]


def test_ids_line_up_with_the_queries_and_every_page_is_followed() -> None:
    http = FakePost(
        {"results": [vulns("GHSA-a", token="t1"), {}, vulns("MAL-b")]},
        vulns("GHSA-c", token="t2"),
        vulns("GHSA-d"),
    )
    queries = [pv("npm", "a", "1"), pv("npm", "b", "1"), pv("npm", "c", "1")]
    hits = lookup(http).affecting(queries).data  # type: ignore[arg-type]
    assert hits.ids == (("GHSA-a", "GHSA-c", "GHSA-d"), (), ("MAL-b",))
    assert hits.issues == {}
    assert [url for url, _ in http.sent[1:]] == ["https://osv.test/v1/query"] * 2
    assert http.sent[2][1]["page_token"] == "t2"


def test_a_partly_paged_answer_is_not_an_answer() -> None:
    http = FakePost(
        {"results": [vulns("GHSA-a", token="t1"), vulns("GHSA-b")]},
        ServiceError("osv: gave up", status=None),
    )
    hits = lookup(http).affecting([pv("npm", "a", "1"), pv("npm", "b", "1")]).data  # type: ignore[arg-type]
    assert hits.ids == (None, ("GHSA-b",))
    assert hits.issues == {"unreachable": 1}


@pytest.mark.parametrize(
    ("failure", "status"),
    [
        (ServiceError("gave up (HTTP 429)", status=429), "quota-deferred"),
        (ServiceError("gave up (timed out)"), "unreachable"),
        (ServiceError("HTTP 400", status=400), "error"),
        (b"not json", "error"),
        ({"results": []}, "error"),
        ({"results": "nope"}, "error"),
    ],
)
def test_a_failed_first_batch_counts_every_query_and_stops(failure: object, status: str) -> None:
    http = FakePost(failure)
    queries = [pv("npm", f"p{i}", "1") for i in range(3)]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("traust_core.v1.providers.osv.BATCH_SIZE", 2)
        hits = lookup(http).affecting(queries).data  # type: ignore[arg-type]
    assert hits.ids == (None, None, None)
    assert hits.issues == {status: 3}
    assert len(http.sent) == 1


def test_a_later_failed_batch_counts_only_its_own_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("traust_core.v1.providers.osv.BATCH_SIZE", 2)
    http = FakePost({"results": [vulns("GHSA-a"), {}]}, ServiceError("HTTP 500 gave up"))
    queries = [pv("npm", f"p{i}", "1") for i in range(3)]
    hits = lookup(http).affecting(queries).data  # type: ignore[arg-type]
    assert hits.ids == (("GHSA-a",), (), None)
    assert hits.issues == {"unreachable": 1}


@pytest.mark.parametrize(
    ("record", "malicious"),
    [
        ({"id": "MAL-2025-1"}, True),
        ({"id": "GHSA-x", "database_specific": {"type": "Malware"}}, True),
        ({"id": "GHSA-x", "affected": [{"ecosystem_specific": {"malicious": True}}]}, True),
        (
            {"id": "GHSA-x", "affected": [{"database_specific": {"type": "malicious-package"}}]},
            True,
        ),
        ({"id": "GHSA-x", "database_specific": {"severity": "CRITICAL"}}, False),
        ({"id": "GHSA-x", "affected": [{"ecosystem_specific": {"malicious": False}}]}, False),
    ],
)
def test_malware_is_named_narrowly(record: dict[str, object], malicious: bool) -> None:
    assert parse_osv(json.dumps(record).encode(), "s").malicious is malicious


@pytest.mark.parametrize(
    ("record", "severity", "display"),
    [
        ({"id": "MAL-2025-1"}, "critical", "MAL-2025-1"),
        ({"id": "GHSA-x", "aliases": ["GO-1", "CVE-2024-1"]}, "unrated", "CVE-2024-1"),
        ({"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}, "medium", "GHSA-x"),
        (
            {"id": "MAL-2", "aliases": ["CVE-2024-2"], "database_specific": {"severity": "LOW"}},
            "critical",
            "CVE-2024-2",
        ),
    ],
)
def test_malware_is_critical_and_a_cve_alias_names_the_advisory(
    record: dict[str, object], severity: str, display: str
) -> None:
    parsed = parse_osv(json.dumps(record).encode(), "s")
    assert (parsed.severity, parsed.display_id) == (severity, display)


def test_naming_asks_for_every_advisory_on_the_package_whatever_the_version() -> None:
    http = FakePost({"results": [vulns("GHSA-a", "GO-b")]})
    hits = lookup(http).naming([Package(ecosystem="go", name="example.com/lib")]).data  # type: ignore[arg-type]
    assert hits.ids == (("GHSA-a", "GO-b"),)
    [(_url, doc)] = http.sent
    assert doc == {"queries": [{"package": {"ecosystem": "Go", "name": "example.com/lib"}}]}


def nuget_lookup(http: FakePost, published: dict[str, str | None] | Exception) -> OsvAdvisoryLookup:
    def resolve(name: str) -> str | None:
        if isinstance(published, Exception):
            raise published
        return published.get(name)

    return OsvAdvisoryLookup(
        "https://osv.test/v1",
        http=http,
        clock=FixedClock(AT),
        nuget_ids=resolve,  # type: ignore[arg-type]
    )


def test_an_empty_nuget_answer_is_asked_again_in_published_casing() -> None:
    http = FakePost({"results": [{}, {}, vulns("GHSA-npm")]}, {"results": [vulns("GHSA-nuget")]})
    queries = [
        pv("nuget", "newtonsoft.json", "13.0.1"),
        pv("nuget", "Internal.Pkg", "1.0.0"),
        pv("npm", "lodash", "4.17.20"),
    ]
    published = {"newtonsoft.json": "Newtonsoft.Json", "Internal.Pkg": None}
    hits = nuget_lookup(http, published).affecting(queries).data  # type: ignore[arg-type]
    assert hits.ids == (("GHSA-nuget",), (), ("GHSA-npm",))
    retried = http.sent[1][1]["queries"]
    assert retried == [
        {"package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"}, "version": "13.0.1"}
    ]


def test_a_nuget_id_already_in_published_casing_is_not_asked_twice() -> None:
    http = FakePost({"results": [{}]})
    hits = nuget_lookup(http, {"Newtonsoft.Json": "Newtonsoft.Json"}).affecting(
        [pv("nuget", "Newtonsoft.Json", "13.0.1")]  # type: ignore[arg-type]
    )
    assert hits.data.ids == ((),) and len(http.sent) == 1


def test_nuget_org_unreachable_leaves_the_lookup_unanswered_not_empty() -> None:
    http = FakePost({"results": [{}]})
    hits = nuget_lookup(http, ServiceError("nuget.org: gave up")).affecting(
        [pv("nuget", "newtonsoft.json", "13.0.1")]  # type: ignore[arg-type]
    )
    assert (hits.data.ids, hits.data.issues) == ((None,), {"unreachable": 1})


def test_a_failed_retry_is_counted_not_read_as_empty() -> None:
    http = FakePost({"results": [{}]}, ServiceError("HTTP 503 gave up"))
    hits = nuget_lookup(http, {"newtonsoft.json": "Newtonsoft.Json"}).affecting(
        [pv("nuget", "newtonsoft.json", "13.0.1")]  # type: ignore[arg-type]
    )
    assert (hits.data.ids, hits.data.issues) == ((None,), {"unreachable": 1})
