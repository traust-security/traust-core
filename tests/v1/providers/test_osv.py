from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.dependencies import AdvisoryIdentifier, AffectedSpan, Version
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
