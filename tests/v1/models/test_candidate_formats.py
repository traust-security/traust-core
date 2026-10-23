"""Scanner output as finding candidates, ported from traust's test_normalize_input.py (fabdb13)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.findings import CandidateFormat, FindingCandidate
from traust_core.v1.models.vocabulary import FindingOrigin

SCANNERS = Path(__file__).parents[2] / "fixtures" / "findings" / "scanners"
REPO = uuid4()
ORIGIN = FindingOrigin("vuln-scan")


def parse(raw: bytes, format: CandidateFormat) -> list[FindingCandidate]:
    return FindingCandidate.parse_many(raw, format, REPO, ORIGIN)


def sarif(mutate: Any = None) -> bytes:
    doc = json.loads((SCANNERS / "codeql.sarif").read_text())
    if mutate:
        mutate(doc)
    return json.dumps(doc).encode()


def test_sarif_maps_a_codeql_result_and_skips_suppressed() -> None:
    [c] = parse(sarif(), CandidateFormat.SARIF)
    assert c.label == "go/log-injection"
    assert c.rule == "go/log-injection"
    assert c.title == "Log injection"
    assert c.reported_severity == "high"
    assert c.cwes == ("CWE-117",)
    assert c.locations == (CodeSpan(path="pkg/api/handler.go", line=42),)
    assert c.confidence == 0.85
    assert c.description.splitlines() == [
        "Log entry from user input.",
        "User input written to log.",
        "Sanitize before logging.",
    ]
    assert (c.repository_id, c.origin, c.category) == (REPO, ORIGIN, None)


def test_sarif_level_decides_without_security_severity() -> None:
    def drop(doc: dict[str, Any]) -> None:
        del doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]

    assert parse(sarif(drop), CandidateFormat.SARIF)[0].reported_severity == "high"


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        ("9.9", "critical"),
        ("9.0", "critical"),
        ("7.0", "high"),
        ("4.5", "medium"),
        ("1.0", "low"),
        ("0.0", "informational"),
        ("not-a-number", "high"),
    ],
)
def test_sarif_security_severity_buckets(score: str, severity: str) -> None:
    def score_it(doc: dict[str, Any]) -> None:
        doc["runs"][0]["results"][0]["properties"] = {"security-severity": score}

    assert parse(sarif(score_it), CandidateFormat.SARIF)[0].reported_severity == severity


def test_sarif_logical_location_and_missing_rule() -> None:
    def logical(doc: dict[str, Any]) -> None:
        result = doc["runs"][0]["results"][0]
        result.update(ruleIndex=None, ruleId="unknown/rule", level="note")
        result["locations"] = [{"logicalLocations": [{"fullyQualifiedName": "pkg.Handler"}]}]

    [c] = parse(sarif(logical), CandidateFormat.SARIF)
    assert c.title == "unknown/rule"
    assert c.reported_severity == "informational"
    assert c.locations == (CodeSpan(path="pkg.Handler", line=None),)
    assert c.confidence is None


def test_sarif_labels_are_unique_within_a_document() -> None:
    def twice(doc: dict[str, Any]) -> None:
        results = doc["runs"][0]["results"]
        results[1] = dict(results[0])
        results.append({"message": {"text": "no rule, no guid"}})

    assert [c.label for c in parse(sarif(twice), CandidateFormat.SARIF)] == [
        "go/log-injection",
        "go/log-injection#2",
        "sarif-3",
    ]


def test_dependabot_maps_an_alert() -> None:
    [c] = parse((SCANNERS / "dependabot-alerts.json").read_bytes(), CandidateFormat.DEPENDABOT)
    assert c.label == "GHSA-xxxx-yyyy-zzzz"
    assert c.category == "supply-chain"
    assert c.reported_severity == "critical"
    assert c.locations == (CodeSpan(path="go.mod", line=None),)
    assert c.cwes == ("CWE-354",)
    assert "CVE-2026-1234" in c.description
    assert c.description.endswith("Upgrade to 0.17.0 or later.")


@pytest.mark.parametrize(
    ("given", "severity"), [("moderate", "medium"), ("", "unrated"), ("bogus", "unrated")]
)
def test_dependabot_severity(given: str, severity: str) -> None:
    alerts = json.loads((SCANNERS / "dependabot-alerts.json").read_text())
    alerts[0]["security_vulnerability"]["severity"] = given
    alerts[0]["security_advisory"]["severity"] = ""
    [c] = parse(json.dumps(alerts).encode(), CandidateFormat.DEPENDABOT)
    assert c.reported_severity == severity


def test_govulncheck_one_candidate_per_osv_with_called_symbol() -> None:
    [c] = parse((SCANNERS / "govulncheck.jsonl").read_bytes(), CandidateFormat.GOVULNCHECK)
    assert c.label == "GO-2026-0001"
    assert c.title == "GO-2026-0001: http2 rapid reset"
    assert c.locations == (CodeSpan(path="server.go", line=100),)
    assert c.reported_severity == "unrated"
    assert "Reachability: symbol_reachable" in c.description
    assert "CVE-2026-9999" in c.description
    assert c.description.endswith("Upgrade to v0.17.0 or later.")


def test_govulncheck_module_only_trace_is_module_present() -> None:
    records = [
        {"osv": {"id": "GO-2026-0002"}},
        {
            "finding": {
                "osv": "GO-2026-0002",
                "trace": [{"module": "example.com/m", "version": "v1"}],
            }
        },
    ]
    raw = "\n".join(json.dumps(r) for r in records).encode()
    [c] = parse(raw, CandidateFormat.GOVULNCHECK)
    assert "Reachability: module_present" in c.description
    assert c.locations == ()


@pytest.mark.parametrize(
    ("raw", "format", "message"),
    [
        (b"not json", CandidateFormat.SARIF, "not JSON"),
        (b'{"version": "1.0", "runs": []}', CandidateFormat.SARIF, "SARIF 2.x"),
        (b'[{"number": 1}]', CandidateFormat.DEPENDABOT, "security_advisory"),
        (b"", CandidateFormat.GOVULNCHECK, "record stream"),
        (b'{"foo": 1}', CandidateFormat.GOVULNCHECK, "record stream"),
        (b'{"config": {}} {"osv": ', CandidateFormat.GOVULNCHECK, "malformed record"),
        (b"\xff\xfe", CandidateFormat.GOVULNCHECK, "not text"),
    ],
)
def test_unreadable_input_raises(raw: bytes, format: CandidateFormat, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        parse(raw, format)


def test_empty_documents_give_no_candidates() -> None:
    assert parse(b'{"version": "2.1.0", "runs": []}', CandidateFormat.SARIF) == []
    assert parse(b"[]", CandidateFormat.DEPENDABOT) == []


@pytest.mark.parametrize(
    ("logical", "shared", "symbol"),
    [
        (
            [{"kind": "function", "fullyQualifiedName": "pkg.Handle", "name": "Handle"}],
            [],
            "pkg.Handle",
        ),
        ([{"kind": "method", "name": "Handle"}], [], "Handle"),
        ([{"index": -1, "kind": "function", "name": "Handle"}], [], "Handle"),
        ([{"index": 0}], [{"kind": "function", "fullyQualifiedName": "pkg.Handle"}], "pkg.Handle"),
        (
            [{"index": 0}],
            [{"kind": "parameter", "parentIndex": 1}, {"kind": "function", "name": "Handle"}],
            "Handle",
        ),
        (
            [{"kind": "namespace", "name": "pkg"}, {"kind": "function", "name": "Handle"}],
            [],
            "Handle",
        ),
        ([{"kind": "function", "name": "Handle"}] * 2, [], "Handle"),
        ([{"kind": "function", "name": "One"}, {"kind": "function", "name": "Two"}], [], None),
        (
            [{"kind": "function", "name": "One"}, {"kind": "function", "decoratedName": "_Z3Twov"}],
            [],
            None,
        ),
        ([{"kind": "namespace", "name": "pkg"}, {"kind": "type", "name": "Handler"}], [], None),
        ([{"kind": "namespace", "name": "pkg", "parentIndex": -1}], [], None),
        ([{"kind": "function"}], [], None),
        ([{"fullyQualifiedName": "pkg.UnknownKind"}], [], None),
        ([], [], None),
    ],
)
def test_sarif_preserves_only_an_unambiguous_enclosing_function(
    logical: list[dict[str, Any]], shared: list[dict[str, Any]], symbol: str | None
) -> None:
    def locate(doc: dict[str, Any]) -> None:
        run = doc["runs"][0]
        run["logicalLocations"] = shared
        run["results"][0]["locations"][0]["logicalLocations"] = logical

    [c] = parse(sarif(locate), CandidateFormat.SARIF)
    assert c.locations == (CodeSpan(path="pkg/api/handler.go", line=42, symbol=symbol),)


@pytest.mark.parametrize(
    ("logical", "shared", "message"),
    [
        ([{"index": -2}], [], "invalid logical location index"),
        ([{"index": -1.0}], [], "invalid logical location index"),
        ([{"index": 1}], [], "invalid logical location index"),
        ([{"index": True}], [{}], "invalid logical location index"),
        ([{"index": "0"}], [{}], "invalid logical location index"),
        ([{"index": 0}], ["not an object"], "invalid logical location index"),
        ([{"index": 0}], {}, "invalid logical location index"),
        ([{"kind": "parameter", "parentIndex": 5}], [], "invalid logical location index"),
        ([{"kind": "parameter", "parentIndex": -2}], [], "invalid logical location index"),
        ([{"kind": "parameter", "parentIndex": -1.0}], [], "invalid logical location index"),
        ([{"index": 0}], [{"parentIndex": 0}], "cyclic logical location parents"),
        (["not an object"], [], "logical location must be an object"),
        ({}, [], "logical locations must be an array"),
        (None, [], "logical locations must be an array"),
        ([{"kind": "function", "name": 42}], [], "invalid function name"),
        (
            [{"kind": "function", "fullyQualifiedName": " "}],
            [],
            "invalid function fullyQualifiedName",
        ),
    ],
)
def test_sarif_rejects_malformed_function_locations(
    logical: Any, shared: Any, message: str
) -> None:
    def locate(doc: dict[str, Any]) -> None:
        run = doc["runs"][0]
        run["logicalLocations"] = shared
        run["results"][0]["locations"][0]["logicalLocations"] = logical

    with pytest.raises(ValidationError, match=message):
        parse(sarif(locate), CandidateFormat.SARIF)


def test_sarif_does_not_take_a_symbol_from_another_physical_location() -> None:
    def another_location(doc: dict[str, Any]) -> None:
        doc["runs"][0]["results"][0]["locations"].append(
            {
                "physicalLocation": {"artifactLocation": {"uri": "other.go"}},
                "logicalLocations": [{"kind": "function", "name": "Other"}],
            }
        )

    [c] = parse(sarif(another_location), CandidateFormat.SARIF)
    assert c.locations == (CodeSpan(path="pkg/api/handler.go", line=42),)


def test_sarif_symbol_fixture_resolves_its_indexed_function() -> None:
    [c] = parse((SCANNERS / "codeql-symbols.sarif").read_bytes(), CandidateFormat.SARIF)
    assert c.locations == (
        CodeSpan(path="vendor/example.com/logger/handler.go", line=42, symbol="api.Handle"),
    )
