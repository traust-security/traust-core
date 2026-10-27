"""The compliance assertion engine and runner rules, ported from traust (fabdb13)
tests/test_compliance_phase1.py, test_compliance_fixtures.py and test_run_compliance_check.py."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ComplianceMappingArtifact, ComplianceScopeArtifact
from traust_core.v1.models.code_facts import CryptoFact, CryptoProbeId
from traust_core.v1.models.compliance import (
    Assertion,
    Check,
    ComplianceMapping,
    ComplianceScope,
    EvaluationRequest,
    InventorySnapshot,
    MappedControl,
    canonical_json,
    coverage,
    crypto_snapshot,
    evaluate_control,
    evidence_id,
    findings_snapshot,
    framework_of,
    select,
)
from traust_core.v1.models.findings import Disposition, Finding, FindingView
from traust_core.v1.models.vocabulary import (
    ComplianceFramework,
    DispositionAssurance,
    DispositionResolution,
    Severity,
    Validity,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "compliance"
MAPPING = ComplianceMapping.of(
    ComplianceMappingArtifact.parse((FIXTURES / "compliance-mapping.json").read_bytes())
)
PARAMS = {"allowed_data_regions": ["us-east-1", "eu-west-1"]}
SNAP: dict[str, Any] = {
    "resources": [
        {"region": "us-east-1", "encryption_at_rest": True, "rules": [{"verbs": ["get", "list"]}]},
        {"region": "eu-west-1", "encryption_at_rest": False, "rules": [{"verbs": ["*"]}]},
    ]
}


def assertion(path: str, operator: str, expected: Any = None) -> Assertion:
    return Assertion.model_validate({"path": path, "operator": operator, "expected": expected})


def check(**fields: Any) -> Check:
    return Check.model_validate({"id": "chk-x", "collector": "cloud_inventory", **fields})


def test_canonicalize_strips_volatile_and_sorts() -> None:
    a = {
        "b": 1,
        "a": 2,
        "resourceVersion": "9",
        "creationTimestamp": "t",
        "nested": [{"uid": "x", "z": 1, "y": 2}],
    }
    b = {"nested": [{"y": 2, "z": 1, "uid": "DIFFERENT"}], "a": 2, "b": 1, "resourceVersion": "42"}
    assert canonical_json(a) == canonical_json(b)
    assert evidence_id(a) == evidence_id(b)


@pytest.mark.parametrize(
    ("path", "selected"),
    [
        ("resources[*].region", ["us-east-1", "eu-west-1"]),
        ("resources[*].rules[*].verbs[*]", ["get", "list", "*"]),
        ("resources[*].missing", []),
        ("nope.deeper", []),
        ("bad]segment", []),
    ],
)
def test_select_fans_out_over_lists_and_nests(path: str, selected: list[str]) -> None:
    assert select(SNAP, path) == selected


@pytest.mark.parametrize(
    ("snapshot", "path", "operator", "expected", "outcome"),
    [
        ({"r": [{"e": True}, {"e": True}]}, "r[*].e", "equals", True, "pass"),
        (SNAP, "resources[*].encryption_at_rest", "equals", True, "fail"),  # one False ruins it
        (SNAP, "resources[*]", "exists", None, "pass"),
        ({}, "resources[*]", "absent", None, "pass"),
        (SNAP, "resources[*]", "absent", None, "fail"),
        ({}, "resources[*]", "exists", None, "fail"),
        ({"v": ["a", "b"]}, "v", "contains", "a", "pass"),
        ({"v": ["a", "b"]}, "v", "not_contains", "a", "fail"),
        ({"v": 3}, "v", "contains", "a", "not_assessed"),
        ({"v": "abc"}, "v", "regex", "^a", "pass"),
        ({"v": "abc"}, "v", "not_regex", "^a", "fail"),
        ({"v": None}, "v", "regex", "^a", "not_assessed"),
        ({"v": 2}, "v", "gte", 1, "pass"),
        ({"v": 2}, "v", "lte", 1, "fail"),
        ({"v": "x"}, "v", "gte", 1, "not_assessed"),
        ({"v": "a"}, "v", "in", ["a"], "pass"),
        ({"v": "a"}, "v", "not_in", ["a"], "fail"),
        ({"v": "a"}, "v", "not_equals", "b", "pass"),
    ],
)
def test_assertion_operators(
    snapshot: Any, path: str, operator: str, expected: Any, outcome: str
) -> None:
    assert assertion(path, operator, expected).evaluate(snapshot, {}).outcome == outcome


@pytest.mark.parametrize("operator", ["in", "not_in"])
def test_scalar_membership_expected_is_not_assessed(operator: str) -> None:
    result = assertion("v", operator, 0).evaluate({"v": 1}, {})
    assert result.outcome == "not_assessed"


def test_empty_selection_is_not_assessed_never_a_vacuous_pass() -> None:
    result = assertion("resources[*].region", "equals", "x").evaluate({}, {})
    assert (result.outcome, "no values" in result.reason) == ("not_assessed", True)


def test_param_indirection_and_undeclared_parameter() -> None:
    regions = assertion("resources[*].region", "in", "param:allowed_data_regions")
    assert regions.evaluate(SNAP, PARAMS).outcome == "pass"
    undeclared = regions.evaluate(SNAP, {})
    assert (undeclared.outcome, undeclared.reason) == (
        "not_assessed",
        "parameter undeclared: allowed_data_regions",
    )


def test_check_applicability_and_verdicts_cite_the_violating_resource() -> None:
    encryption = check(
        id="chk-encryption-at-rest",
        assertion={
            "path": "resources[*].encryption_at_rest",
            "operator": "equals",
            "expected": True,
        },
        applies_when={"path": "resources[*]", "operator": "exists"},
    )
    failed = encryption.evaluate(SNAP, {})
    assert failed.verdict == "not_satisfied"
    assert [(e.locator, e.value) for e in failed.evidence] == [
        ("cloud_inventory:resources[*]", SNAP["resources"][1])
    ]
    assert all(len(e.sha256) == 64 for e in failed.evidence)
    not_applicable = encryption.evaluate({"resources": []}, {})
    assert (not_applicable.verdict, not_applicable.reason) == (
        "not_applicable",
        "declared applicability condition not met",
    )


def test_undeterminable_applicability_is_not_assessed() -> None:
    gated = check(
        assertion={"path": "a", "operator": "exists"},
        applies_when={"path": "n", "operator": "gte", "expected": "param:missing"},
    )
    result = gated.evaluate({"a": 1}, {})
    assert (result.verdict, result.reason) == (
        "not_assessed",
        "applicability undeterminable: parameter undeclared: missing",
    )


def test_an_absence_cites_the_scanned_scope() -> None:
    absent = check(
        collector="findings_db", assertion={"path": "view.open[*]", "operator": "absent"}
    )
    result = absent.evaluate({"view": {"open": []}}, {})
    assert (result.verdict, [e.locator for e in result.evidence]) == (
        "satisfied",
        ["findings_db:view"],
    )
    root = check(assertion={"path": "missing", "operator": "absent"}).evaluate({}, {})
    assert [e.locator for e in root.evidence] == ["cloud_inventory:(snapshot root)"]


def test_a_failing_bare_value_cites_the_violating_values() -> None:
    result = check(assertion={"path": "v[*]", "operator": "equals", "expected": 1}).evaluate(
        {"v": [1, 2, 3]}, {}
    )
    assert [e.value for e in result.evidence] == [2, 3]


def test_sampling_rule_is_deterministic() -> None:
    snap = {"resources": [{"region": f"r{i}"} for i in range(20)]}
    sampled = check(
        sampling="sorted_first_5",
        assertion={"path": "resources[*].region", "operator": "regex", "expected": "^r"},
    )
    a, b = sampled.evaluate(snap, {}), sampled.evaluate(copy.deepcopy(snap), {})
    assert a == b and a.verdict == "satisfied" and len(a.evidence) == 5


@pytest.mark.parametrize("registered", MAPPING.checks, ids=lambda c: c.id)
def test_every_registry_check_calibrates_on_its_fixtures(registered: Check) -> None:
    fixtures = FIXTURES / "checks" / registered.id
    bad = registered.evaluate(json.loads((fixtures / "bad" / "snapshot.json").read_text()), PARAMS)
    good = registered.evaluate(
        json.loads((fixtures / "good" / "snapshot.json").read_text()), PARAMS
    )
    assert (bad.verdict, good.verdict) == ("not_satisfied", "satisfied")
    assert bad.evidence


def test_a_mapping_citing_an_unknown_check_is_refused() -> None:
    raw = json.loads((FIXTURES / "compliance-mapping.json").read_text())
    raw["controls"][0]["checks"] = ["chk-nope"]
    with pytest.raises(ValidationError, match="unknown checks: \\['chk-nope'\\]"):
        ComplianceMapping.of(ComplianceMappingArtifact.from_document(raw))


def control(classification: str, *checks: str, **kw: Any) -> MappedControl:
    return MappedControl.model_validate(
        {
            "framework": "nist-800-53-rev5",
            "control_id": "x-1",
            "classification": classification,
            "checks": checks,
            **kw,
        }
    )


SPINE = ComplianceFramework("nist-800-53-rev5")
GOOD_FINDINGS = {
    "open_critical_dependency_findings": [],
    "open_confirmed_hardcoded_credential_findings": [],
}


@pytest.mark.parametrize(
    ("ctl", "snapshots", "verdict", "reason", "check_id"),
    [
        (
            control("organizational"),
            {},
            "not_assessed",
            "organizational — out of technical scope",
            None,
        ),
        (
            control("evidence_review", evidence_request="TLS posture"),
            {},
            "not_assessed",
            "evidence_review — awaiting artifact: TLS posture",
            None,
        ),
        (
            control("deterministic", "chk-encryption-at-rest"),
            {},
            "not_assessed",
            "collector unavailable: cloud_inventory",
            None,
        ),
        (
            control("deterministic", "chk-no-open-critical-dependency-vulns"),
            {"findings_db": GOOD_FINDINGS},
            "satisfied",
            None,
            "chk-no-open-critical-dependency-vulns",
        ),
        (
            control(
                "deterministic",
                "chk-encryption-at-rest",
                "chk-no-confirmed-hardcoded-credentials",
            ),
            {
                "findings_db": {"open_confirmed_hardcoded_credential_findings": [{"id": "F-2"}]},
                "cloud_inventory": {"resources": []},
            },
            "not_satisfied",
            None,
            "chk-no-confirmed-hardcoded-credentials",
        ),
        (
            control("deterministic", "chk-encryption-at-rest"),
            {"cloud_inventory": {"resources": []}},
            "not_applicable",
            "declared applicability condition not met",
            None,
        ),
    ],
)
def test_a_control_verdict_is_every_check_passing_and_the_first_failure_wins(
    ctl: MappedControl, snapshots: Any, verdict: str, reason: str | None, check_id: str | None
) -> None:
    result = evaluate_control(ctl, SPINE, MAPPING, snapshots, {})
    assert (result.verdict, result.reason, result.check_id) == (verdict, reason, check_id)
    assert bool(result.evidence) == (verdict in ("satisfied", "not_satisfied"))
    assert result.verdict_source == "check"


def test_fedramp_rides_the_800_53_spine() -> None:
    assert framework_of(ComplianceFramework("fedramp-high")) == SPINE
    assert framework_of(ComplianceFramework("soc2-tsc")) == "soc2-tsc"


def test_coverage_counts_per_framework_never_blended() -> None:
    results = [
        {"framework": "a", "classification": "deterministic", "verdict": "satisfied"},
        {"framework": "a", "classification": "organizational", "verdict": "not_assessed"},
        {"framework": "b", "classification": "evidence_review", "verdict": "not_assessed"},
    ]
    blocks = coverage(results)
    assert blocks["a"] == {
        "total_in_scope": 2,
        "deterministic": 1,
        "evidence_review": 0,
        "organizational": 1,
        "satisfied": 1,
        "not_satisfied": 0,
        "not_applicable": 0,
        "not_assessed": 1,
    }
    assert blocks["b"]["total_in_scope"] == 1
    assert coverage([]) == {}


def request(**kw: Any) -> EvaluationRequest:
    return EvaluationRequest(scope_id=uuid4(), harness_version="t", **kw)


@pytest.mark.parametrize(
    ("framework", "kw", "reason"),
    [
        ("pci-dss-v4", {}, "skipped: no declared CDE boundary (--cde-boundary)"),
        ("pci-dss-v4", {"cde_boundary": "cde.md"}, None),
        (
            "gdpr-technical",
            {"target_kind": "environment"},
            "skipped: no declared personal-data stores (--personal-data-stores)",
        ),
        ("soc2-tsc", {}, "skipped: no declared trust-service categories (--trust-categories)"),
        ("soc2-tsc", {"trust_categories": ("security",)}, None),
        ("fedramp-high", {}, "skipped: requires a deployed-environment target (product-only run)"),
        ("fedramp-moderate", {"target_kind": "environment"}, None),
        ("nist-800-53-rev5", {}, None),
    ],
)
def test_a_framework_missing_its_declared_input_is_skipped_with_a_named_reason(
    framework: str, kw: Any, reason: str | None
) -> None:
    assert request(**kw).skip_reason(ComplianceFramework(framework)) == reason


def view(severity: str, cwes: tuple[str, ...], **disposition: Any) -> FindingView:
    finding = Finding(
        id=uuid4(), repository_id=uuid4(), fingerprint_algo="v3", fingerprint="f", title="t"
    )
    return FindingView(
        finding=finding,
        effective_severity=Severity(severity),
        cwes=cwes,
        disposition=Disposition(
            finding_id=finding.id,  # type: ignore[arg-type]
            assurance=DispositionAssurance.HUMAN_REVIEWED,
            **disposition,
        )
        if disposition
        else None,
    )


def test_findings_view_keeps_open_critical_dependency_and_confirmed_credential_findings() -> None:
    critical_dep = view("critical", ("CWE-1395",))
    high_dep = view("high", ("CWE-1395",))
    confirmed_cred = view("high", ("CWE-798",), validity=Validity("confirmed"))
    unconfirmed_cred = view("high", ("CWE-798",))
    resolved_dep = view("critical", ("CWE-1035",), resolution=DispositionResolution.RESOLVED)
    snap = findings_snapshot(
        ("org/a", v)
        for v in (critical_dep, high_dep, confirmed_cred, unconfirmed_cred, resolved_dep)
    )
    assert [r["id"] for r in snap["open_critical_dependency_findings"]] == [  # type: ignore[union-attr,index]
        str(critical_dep.finding.id)
    ]
    assert [r["id"] for r in snap["open_confirmed_hardcoded_credential_findings"]] == [  # type: ignore[union-attr,index]
        str(confirmed_cred.finding.id)
    ]
    assert findings_snapshot([]) == {
        "open_critical_dependency_findings": [],
        "open_confirmed_hardcoded_credential_findings": [],
    }


def test_crypto_census_feeds_the_killswitch_check() -> None:
    killswitch = CryptoFact(
        probe_id=CryptoProbeId("CRYPTO_GODEBUG_TLS_KILLSWITCH"), provider="go", detail="tlsmlkem=0"
    )
    toolchain = CryptoFact(
        probe_id=CryptoProbeId("CRYPTO_GO_TOOLCHAIN"), provider="go", detail="go"
    )
    registered = next(c for c in MAPPING.checks if c.id == "chk-no-pqc-tls-killswitch")
    assert (
        registered.evaluate(crypto_snapshot([toolchain, killswitch]), {}).verdict == "not_satisfied"
    )
    assert registered.evaluate(crypto_snapshot([toolchain]), {}).verdict == "satisfied"
    assert registered.evaluate(crypto_snapshot([]), {}).verdict == "not_applicable"


def test_inventory_snapshot_id_addresses_the_canonical_body() -> None:
    a = InventorySnapshot.of("aws", [{"id": "b", "etag": "1"}, {"id": "a"}], ["z", "y"])
    b = InventorySnapshot.of("aws", [{"id": "a"}, {"id": "b", "etag": "2"}], ["y", "z"])
    assert a.snapshot_id == b.snapshot_id
    assert [r["id"] for r in a.resources] == ["a", "b"]
    assert a.document()["metadata"] == {"collector": "aws", "snapshot_id": a.snapshot_id}


def scope_doc(**entry: Any) -> ComplianceScopeArtifact:
    base = {
        "frameworks": ["soc2-tsc"],
        "resolves_via": "explicit",
        "include": [{"repo": "org/a", "reason": "in"}],
        "declared_by": "alice",
        "declared_at": "2026-10-23",
    }
    return ComplianceScopeArtifact.from_document(
        {"version": 1, "updated": "2026-10-23", "boundaries": {"b1": {**base, **entry}}}
    )


def test_a_scope_is_one_boundary_and_draft_when_unsigned() -> None:
    assert not ComplianceScope.of(None, scope_doc()).draft
    assert ComplianceScope.of(None, scope_doc(declared_by="draft:alice")).draft
    two = json.loads(scope_doc().payload)
    two["boundaries"]["b2"] = two["boundaries"]["b1"]
    with pytest.raises(ValidationError, match="exactly one boundary"):
        ComplianceScope.of(None, ComplianceScopeArtifact.from_document(two))
