"""Advisory range rules, ported from traust-engine tests/test_osv_ranges.py and the
version tests of tests/test_run_impact_analysis.py (traust-engine main)."""

from __future__ import annotations

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.dependencies import (
    AffectedPackage,
    AffectedSpan,
    Version,
    parse_advisory_identifier,
    version_key,
)
from traust_core.v1.models.vocabulary import Ecosystem

GO, NPM, PYPI, MAVEN = Ecosystem.GO, Ecosystem.NPM, Ecosystem.PYPI, Ecosystem.MAVEN


def span(introduced: str, fixed: str | None = None, last: str | None = None) -> AffectedSpan:
    return AffectedSpan(
        introduced=Version(introduced),
        fixed=Version(fixed) if fixed else None,
        last_affected=Version(last) if last else None,
    )


def package(*spans: AffectedSpan, ecosystem: Ecosystem = GO, versions: tuple[str, ...] = ()):
    return AffectedPackage(
        ecosystem=ecosystem,
        name="example-lib",
        spans=spans,
        versions=tuple(Version(v) for v in versions),
    )


TWO_SPANS = package(span("0", "1.5.0"), span("2.0.0", "2.3.0"))


@pytest.mark.parametrize(
    ("version", "ecosystem", "same_as"),
    [
        ("v1.64.1", GO, "1.64.1"),
        ("v1.2.3-rc1", GO, "1.2.3"),
        ("v1.2.3", NPM, "1.2.3"),
        ("1.2.3.4", NPM, "1.2.3"),
        ("1.0.0.Final", MAVEN, "1"),
        ("5.3.2-RELEASE", MAVEN, "5.3.2"),
        ("1!2.3.4", PYPI, "2.3.4"),
        ("2.3.4rc1", PYPI, "2.3.4"),
        ("1.2.0", PYPI, "1.2"),
        ("13.0.1", Ecosystem.NUGET, "13.0.1"),
    ],
)
def test_version_key_normalises_per_ecosystem(version: str, ecosystem: Ecosystem, same_as: str):
    assert version_key(version, ecosystem) == version_key(same_as, ecosystem) is not None


@pytest.mark.parametrize("ecosystem", [GO, NPM, MAVEN, PYPI, Ecosystem.RUBY, Ecosystem.CARGO])
@pytest.mark.parametrize("version", ["latest", "", "  "])
def test_unorderable_versions_have_no_key(version: str, ecosystem: Ecosystem) -> None:
    assert version_key(version, ecosystem) is None


def test_go_needs_three_components_and_orders_numerically() -> None:
    assert version_key("1.64", GO) is None
    assert version_key("v1.10.0", GO) > version_key("1.9.3", GO)  # type: ignore[operator]


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("1.2.0", True),
        ("v1.4.9", True),
        ("1.5.0", False),
        ("1.9.0", False),
        ("2.0.0", True),
        ("2.3.0", False),
        ("latest", None),
    ],
)
def test_affects_every_span(version: str, affected: bool | None) -> None:
    assert TWO_SPANS.affects(Version(version)) is affected


def test_last_affected_is_inclusive() -> None:
    pkg = package(span("1.0.0", last="1.4.0"))
    assert pkg.affects(Version("1.4.0")) is True
    assert pkg.affects(Version("1.4.1")) is False
    assert pkg.affects(Version("0.9.0")) is False


def test_listed_versions_are_affected_even_without_a_span() -> None:
    pkg = package(versions=("1.0.0-custom",))
    assert pkg.affects(Version("1.0.0-custom")) is True
    assert pkg.affects(Version("1.0.0")) is False


def test_an_unorderable_bound_leaves_the_answer_undecided() -> None:
    assert package(span("0", "next")).affects(Version("1.0.0")) is None
    assert package(span("0", "next"), span("1.0.0", "1.2.0")).affects(Version("1.1.0")) is True


@pytest.mark.parametrize(
    ("installed", "fix"), [("1.2.0", "1.5.0"), ("2.1.0", "2.3.0"), ("v2.1.0", "2.3.0")]
)
def test_fix_is_the_one_for_the_installed_span(installed: str, fix: str) -> None:
    assert TWO_SPANS.fixed_in(Version(installed)) == fix


def test_last_affected_only_has_no_fix_and_a_later_span_supplies_one() -> None:
    assert package(span("1.0.0", last="1.4.0")).fixed_in(Version("1.2.0")) is None
    later = package(span("1.0.0", last="1.4.0"), span("2.0.0", "2.3.0"))
    assert later.fixed_in(Version("1.2.0")) == "2.3.0"


def test_a_fix_inside_another_span_is_skipped() -> None:
    pkg = package(span("0", "1.5.0"), span("1.4.0", "1.6.0"))
    assert pkg.fixed_in(Version("1.4.5")) == "1.6.0"


def test_overlapping_spans_take_the_covering_span_fix() -> None:
    pkg = package(span("3.6.5"), span("3.7.0", "3.7.14"))
    assert pkg.fixed_in(Version("3.7.11")) == "3.7.14"
    assert pkg.fixed_in(Version("3.6.6")) is None


def test_open_ended_span_above_every_fix_has_no_fix() -> None:
    assert package(span("0", "1.5.0"), span("3.0.0")).fixed_in(Version("3.1.0")) is None


def test_unorderable_installed_version_keeps_the_first_fix() -> None:
    assert TWO_SPANS.fixed_in(Version("latest")) == "1.5.0"
    assert TWO_SPANS.fixed_in(None) == "1.5.0"
    assert package(span("1.0.0", last="2.0.0")).fixed_in(None) is None


def test_pypi_fixes_follow_release_numbers() -> None:
    pkg = package(span("0", "2.20"), span("2.25.0", "2.32.0"), ecosystem=PYPI)
    assert pkg.fixed_in(Version("2.19.1")) == "2.20"
    assert pkg.fixed_in(Version("2.31.0")) == "2.32.0"


def test_vulnerable_range_states_each_span() -> None:
    pkg = package(span("0", "1.5.0"), span("2.0.0", last="2.2.0"), span("3.0.0"), span("0"))
    assert pkg.vulnerable_range == "<1.5.0 || >=2.0.0 <=2.2.0 || >=3.0.0 || *"
    assert package().vulnerable_range == ""


@pytest.mark.parametrize(
    "good",
    [
        "CVE-2026-1234",
        "GHSA-abcd-efgh-ijkl",
        "MAL-2025-0001",
        "PYSEC-2024-1",
        "GO-2024-1234",
        "RUSTSEC-2021-0001",
        "OSV-2023-1",
    ],
)
def test_advisory_identifiers_of_the_osv_family_parse(good: str) -> None:
    assert parse_advisory_identifier(good) == good


@pytest.mark.parametrize(
    "bad", ["foo; rm -rf", "../etc", "a b", "", "CVE_2026_1", "ghsa-lower", "CVE-2026-1/x"]
)
def test_injection_and_junk_are_not_advisory_identifiers(bad: str) -> None:
    with pytest.raises(ValidationError, match="not an advisory id"):
        parse_advisory_identifier(bad)
