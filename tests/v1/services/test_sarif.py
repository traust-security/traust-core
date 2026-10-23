"""SarifExport: findings as SARIF 2.1.0, ported from traust-engine reporting/sarif.py at main."""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.models.findings import (
    Disposition,
    Finding,
    FindingLabel,
    FindingView,
    Location,
    Occurrence,
)
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.services.insight import SarifExport

REPO = "https://github.com/example/operator"


def view(
    severity: Severity | None = Severity.HIGH, *, category: str | None = "injection", **kw: Any
) -> FindingView:
    finding = Finding(
        id=uuid4(),
        repository_id=uuid4(),
        fingerprint_algo="v3",
        fingerprint="f" * 64,
        title="SQL injection in the reconcile handler",
    )
    labels = (
        (FindingLabel(finding_id=finding.id, taxonomy="category", label=category),)
        if category
        else ()
    )
    values: dict[str, Any] = {
        "finding": finding,
        "effective_severity": severity,
        "labels": labels,
        "locations": (
            Location(occurrence_id=uuid4(), path="controllers/db.go", line_start=12, line_end=14),
        ),
        "cwes": ("CWE-89",),
    }
    return FindingView(**{**values, **kw})


def disposition(**kw: Any) -> Disposition:
    return Disposition(finding_id=uuid4(), assurance=DispositionAssurance.HUMAN_REVIEWED, **kw)


def results(*views: FindingView) -> list[dict[str, Any]]:
    return SarifExport().document(list(views), REPO)["runs"][0]["results"]


def test_the_document_is_sarif_with_one_rule_per_category() -> None:
    doc = SarifExport().document([view(), view(category="crypto"), view()], REPO)
    assert (doc["version"], doc["$schema"]) == (
        "2.1.0",
        "https://json.schemastore.org/sarif-2.1.0.json",
    )
    (run,) = doc["runs"]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["injection", "crypto"]
    assert [r["ruleIndex"] for r in run["results"]] == [0, 1, 0]
    assert run["versionControlProvenance"] == [{"repositoryUri": REPO}]


def test_a_finding_without_a_category_is_uncategorized() -> None:
    (r,) = results(view(category=None))
    assert r["ruleId"] == "uncategorized"


@pytest.mark.parametrize(
    ("severity", "level", "security_severity"),
    [
        (Severity.CRITICAL, "error", "9.5"),
        (Severity.HIGH, "error", "8.0"),
        (Severity.MEDIUM, "warning", "5.0"),
        (Severity.LOW, "note", "2.0"),
        (Severity.INFORMATIONAL, "note", "0.5"),
    ],
)
def test_severity_maps_to_level_and_security_severity(
    severity: Severity, level: str, security_severity: str
) -> None:
    (r,) = results(view(severity))
    assert (r["level"], r["properties"]["security-severity"]) == (level, security_severity)


@pytest.mark.parametrize("reported", [False, True])
def test_an_unrated_finding_has_no_invented_security_severity(reported: bool) -> None:
    occurrence = (
        Occurrence(finding_id=uuid4(), assessment_id=uuid4(), severity="unrated")
        if reported
        else None
    )
    (result,) = results(view(None, occurrence=occurrence))
    assert result["level"] == "none"
    assert result["properties"]["traust/severity"] is None
    assert "security-severity" not in result["properties"]


def test_a_human_rating_of_an_unrated_report_is_exported() -> None:
    (result,) = results(
        view(
            Severity.LOW,
            occurrence=Occurrence(finding_id=uuid4(), assessment_id=uuid4(), severity="unrated"),
            disposition=disposition(severity="low"),
        )
    )
    assert result["level"] == "note"
    assert result["properties"]["traust/severity"] == "low"
    assert result["properties"]["security-severity"] == "2.0"


def test_a_result_carries_location_fingerprints_cwes_and_cvss() -> None:
    v = view(
        occurrence=Occurrence(
            finding_id=uuid4(),
            assessment_id=uuid4(),
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=Decimal("9.8"),
        )
    )
    (r,) = results(v)
    assert r["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "controllers/db.go"},
                "region": {"startLine": 12, "endLine": 14},
            }
        }
    ]
    assert r["partialFingerprints"] == {
        "traustFindingId/v1": str(v.finding.id),
        "traustFingerprint/v1": "f" * 64,
    }
    assert r["properties"]["tags"] == ["security", "CWE-89"]
    assert r["properties"]["traust/cvss"]["score"] == "9.8"
    assert r["properties"]["traust/validity"] == "not_verified"
    assert "suppressions" not in r and "baselineState" not in r


def test_a_package_or_image_path_is_a_logical_location() -> None:
    v = view(locations=(Location(occurrence_id=uuid4(), path="pkg:golang/x/net@0.1.0"),))
    (r,) = results(v)
    assert r["locations"] == [
        {"logicalLocations": [{"fullyQualifiedName": "pkg:golang/x/net@0.1.0"}]}
    ]


def test_a_one_line_region_has_no_end_line() -> None:
    v = view(locations=(Location(occurrence_id=uuid4(), path="a.go", line_start=5, line_end=5),))
    (r,) = results(v)
    assert r["locations"][0]["physicalLocation"]["region"] == {"startLine": 5}


@pytest.mark.parametrize(
    ("said", "justifications"),
    [
        ({"validity": "false_positive"}, ["traust disposition: validity=false_positive"]),
        ({"resolution": "risk_accepted"}, ["traust disposition: resolution=risk_accepted"]),
        (
            {"validity": "false_positive", "resolution": "risk_accepted"},
            [
                "traust disposition: validity=false_positive",
                "traust disposition: resolution=risk_accepted",
            ],
        ),
    ],
)
def test_false_positives_and_accepted_risks_are_suppressions(
    said: dict[str, str], justifications: list[str]
) -> None:
    (r,) = results(view(disposition=disposition(**said)))
    assert [s["justification"] for s in r["suppressions"]] == justifications
    assert all((s["kind"], s["status"]) == ("external", "accepted") for s in r["suppressions"])


def test_a_resolved_finding_is_absent() -> None:
    (r,) = results(view(disposition=disposition(resolution="resolved")))
    assert r["baselineState"] == "absent"
    assert r["properties"]["traust/disposition"]["resolution"] == "resolved"


def test_no_findings_is_an_empty_run() -> None:
    (run,) = SarifExport().document([], REPO)["runs"]
    assert (run["results"], run["tool"]["driver"]["rules"]) == ([], [])
