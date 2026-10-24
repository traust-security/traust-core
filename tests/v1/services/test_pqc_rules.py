"""The pqc-readiness rules ported from the legacy skill scripts, table-driven: the Layer-1
post-processing (`pqc_facts.py`), the readiness gate (`--validate-readiness`), the findings
vocabulary of remediations (`build_pqc_blockers.py`), the Layer-2 route (`l2_prepass.py`) and
the zero-hit verdict (`bulk_prescan.py`)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from tests.v1.providers.test_crypto import DEPENDENCY_PROBES
from tests.v1.providers.test_crypto import FIXTURE as CRYPTO
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    PqcFactsArtifact,
    PqcReadinessArtifact,
)
from traust_core.v1.models.code_facts import CryptoFact, CryptoProbeId
from traust_core.v1.models.common import CodeSpan, ToolRequest
from traust_core.v1.models.pqc import (
    PqcFact,
    PqcReadiness,
    PqcRemediation,
    PqcRoute,
    PqcScan,
    PqcScanFinding,
    PqcStamps,
)
from traust_core.v1.models.vocabulary import (
    PqcClassification,
    PqcPathClass,
    PqcReadinessBucket,
    PqcRemediationCategory,
    Severity,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.crypto import CryptoProbe, long_validity
from traust_core.v1.services.lint import LintContext
from traust_core.v1.services.pqc import facts as F
from traust_core.v1.services.pqc import readiness as R

P = CryptoProbeId
FIXTURE = Path(__file__).parents[2] / "fixtures/pqc"
AT = datetime(2026, 10, 24, tzinfo=UTC)
STAMPS = PqcStamps(adapter_version="1.4.0", pqc_scan_commit="be5c760", rules_sha256="ab" * 32)
URL = "https://github.com/acme/widget"
SHA = "f1b29843254b34f95ee1b36f1accca0380070962"
REPORT = json.loads((FIXTURE / "widget-pqc-readiness.json").read_text())


def scan(*findings: PqcScanFinding, rules: int = 150) -> PqcScan:
    return PqcScan(
        findings=findings, scanned_files=40, skipped_files=2, rules_in_pack=rules, stamps=STAMPS
    )


def hit(rule_id: str, file: str, line: int = 1, **kw: Any) -> PqcScanFinding:
    return PqcScanFinding(rule_id=rule_id, file=file, line=line, **kw)


def census(probe_id: CryptoProbeId, detail: str, path: str = "go.mod", **kw: Any) -> CryptoFact:
    return CryptoFact(
        probe_id=probe_id, provider=kw.pop("provider", "go"), detail=detail,
        location=CodeSpan(path=path, line=1), **kw,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("provider", "version", "capable"),
    [
        ("go", "1.24", True),
        ("go", "1.23.9", False),
        ("go", "go1.25.1", True),
        ("openssl", "3.5.0", True),
        ("openssl-libs", "1:3.2.2-6.el9", False),
        ("openssl-fips-provider", "3.5.1", True),
        ("node", "22.20.0", True),
        ("node", "22.19", False),
        ("node", "24", True),
        ("jdk", "24", False),  # TLS hybrid KEX defaults in JDK 27
        ("jdk", "27", True),
        ("rustls", "0.23.27", True),
        ("rustls", "0.23.26", False),
        ("nss", "3.105", True),
        ("gnutls", "3.7.9", False),
        ("python", "3.12", None),  # no capability row
        ("go", None, None),
        ("go", "devel", None),
        (None, "1.24", None),
    ],
)
def test_pqc_capable_reads_the_version_matrix(
    provider: str | None, version: str | None, capable: bool | None
) -> None:
    assert F.pqc_capable(provider, version) is capable


@pytest.mark.parametrize(
    ("rule_id", "evidence", "qclass", "usage", "prefix", "deprecated", "disallowed"),
    [
        (
            "API_GO_CRYPTO_RSA_GENKEY",
            "rsa.GenerateKey(r, 2048)",
            "shor_112bit",
            "sig",
            "API_GO_CRYPTO_RSA",
            2030,
            2035,
        ),
        (
            "API_GO_CRYPTO_RSA_GENKEY",
            "rsa.GenerateKey(r, 4096)",
            "shor_128bit_plus",
            "sig",
            "API_GO_CRYPTO_RSA",
            None,
            2035,
        ),
        ("TLS_CIPHER_3DES", "3DES suite", "shor_112bit", "tls", "TLS_", 2030, 2035),
        ("CERT_RSA_1024_SELF", "", "classically_broken", "pki", "CERT_RSA_1024", None, None),
        (
            "HP_GOV_PLATFORM_OCP_DIRECT",
            "",
            "quantum_resistant",
            "platform-delegation",
            "HP_GOV_PLATFORM_",
            None,
            None,
        ),
        (
            "HP_HASH_UNAUTH_CIPHER_MODE",
            "",
            "non_quantum_risk",
            "sym",
            "HP_HASH_UNAUTH_CIPHER_MODE",
            None,
            None,
        ),
        ("HP_CHAIN_GO_TOOLCHAIN", "", "grover_margin", "infra", "HP_CHAIN_", None, None),
    ],
)
def test_rules_map_to_ir8547_by_longest_prefix(
    rule_id: str,
    evidence: str,
    qclass: str,
    usage: str,
    prefix: str,
    deprecated: int | None,
    disallowed: int | None,
) -> None:
    mapped = F.map_rule(rule_id, evidence)
    assert (mapped.qclass, mapped.usage, mapped.matched_prefix) == (qclass, usage, prefix)
    assert mapped.clock is not None
    assert (mapped.clock.deprecated_after, mapped.clock.disallowed_after) == (
        deprecated,
        disallowed,
    )


def test_an_unmapped_rule_has_no_clock() -> None:
    assert F.map_rule("NOT_A_RULE") == F.Ir8547(qclass="unmapped")


@pytest.mark.parametrize(
    ("path", "cls", "hint_for_chain"),
    [
        ("pkg/server/tls.go", PqcPathClass.FIRST_PARTY, "provider-census"),
        ("vendor/github.com/x/y.go", PqcPathClass.VENDOR, "vendored"),
        ("web/node_modules/jose/index.js", PqcPathClass.VENDOR, "vendored"),
        ("pkg/server/tls_test.go", PqcPathClass.TEST_DOCS, "provider-census"),
        ("docs/tls.md", PqcPathClass.TEST_DOCS, "provider-census"),
        ("examples/client/main.go", PqcPathClass.TEST_DOCS, "provider-census"),
        (".coderabbit.yaml", PqcPathClass.TEST_DOCS, "provider-census"),
        ("", PqcPathClass.FIRST_PARTY, "provider-census"),
    ],
)
def test_paths_are_classified(path: str, cls: PqcPathClass, hint_for_chain: str) -> None:
    assert F.path_class(path) is cls
    assert F.provenance_hint("HP_CHAIN_GO_TOOLCHAIN", path) == hint_for_chain


@pytest.mark.parametrize(
    ("rule_id", "hint"),
    [
        ("HP_GOV_PLATFORM_OCP_DIRECT", "inherited-platform"),
        ("HP_GROUPS_GO_CURVE_PREFS", "inherited-constrained"),
        ("HP_POLICY_CRYPTO_POLICIES", "inherited-constrained"),
        ("HP_ENV_GODEBUG_KILLSWITCH", "inherited-constrained"),
        ("DEP_GO_JOSE", "delegated-dependency"),
        ("HP_FW_SPRING_TLS", "delegated-dependency"),
        ("JWT_LIB_JOSE", "delegated-dependency"),
        ("HP_PQC_MLKEM_GROUP", "adoption-signal"),
        ("API_GO_CRYPTO_RSA", "native-candidate"),
    ],
)
def test_provenance_hints_by_rule_family(rule_id: str, hint: str) -> None:
    assert F.provenance_hint(rule_id, "pkg/x.go") == hint


def legacy_census() -> list[dict[str, Any]]:
    return json.loads((FIXTURE / "legacy-census-facts.json").read_text())


def test_the_census_maps_to_the_legacy_chain_facts() -> None:
    """Parity: the probe's configured facts become the legacy adapter's facts field for field.
    The legacy manifest-parsed dependency facts come from dependency rows now (service tests)."""
    configured = [
        f
        for f in CryptoProbe(FixedClock(AT)).enumerate(ToolRequest(workspace=CRYPTO / "repo")).data
        if isinstance(f, CryptoFact)
    ]
    dependency_rules = {F._PROBE_RULES[p] for p in DEPENDENCY_PROBES}
    expected = [f for f in legacy_census() if f["rule_id"] not in dependency_rules]
    got = [F._fact_json(f) for f in F.source_facts(scan(), configured)]
    strip = lambda f: {k: v for k, v in f.items() if k != "fact_id"}  # noqa: E731
    assert [strip(f) for f in got] == [strip(f) for f in expected]
    assert len(got) == 27


def test_fips_mode_marks_every_census_fact_when_any_fips_signal_fired() -> None:
    plain = F.source_facts(scan(), [census(P.GO_TOOLCHAIN, "go 1.24", version="1.24")])
    assert plain[0].fips_mode is None and plain[0].pqc_capable is True
    for signal in (
        census(P.FIPS140_GODEBUG, "GODEBUG fips140=on", "hack/e2e.sh"),
        census(P.GO_FIPS_BACKEND, "golang-fips/openssl", "go.sum"),
        census(P.POLICY_SET, "update-crypto-policies --set FIPS", "Dockerfile"),
    ):
        facts = F.source_facts(scan(), [census(P.GO_TOOLCHAIN, "go 1.24"), signal])
        assert all(f.fips_mode for f in facts)
    policy = census(P.POLICY_SET, "update-crypto-policies --set DEFAULT:PQ", "Dockerfile")
    assert all(f.fips_mode is None for f in F.source_facts(scan(), [policy]))


def test_image_tier_facts_have_no_chain_rule() -> None:
    assert F.source_facts(scan(), [census(P.IMAGE_ENV, "GODEBUG=x", provider="image")]) == []


def test_vendored_governance_hits_are_dropped_and_ids_follow_path_order() -> None:
    """Regression (FIO miss): a vendored platform-API type is not profile consumption."""
    facts = F.source_facts(
        scan(
            hit("HP_TLS_LISTENER_GO", "pkg/controller/metrics/metrics.go", 225),
            hit("HP_GOV_PLATFORM_OCP_DIRECT", "vendor/github.com/openshift/api/types.go", 65),
            hit("HP_GOV_PLATFORM_OCP_DIRECT", "pkg/config/profile.go", 10),
            hit("HP_GOV_PLATFORM_OCP_DIRECT", "test/e2e/profile_test.go", 3),
        ),
        [],
    )
    assert [(f.fact_id, f.rule_id, f.file) for f in facts] == [
        ("F0000", "HP_GOV_PLATFORM_OCP_DIRECT", "pkg/config/profile.go"),
        ("F0001", "HP_TLS_LISTENER_GO", "pkg/controller/metrics/metrics.go"),
    ]


def test_long_fields_are_clipped_and_empty_match_is_absent() -> None:
    [fact] = F.source_facts(scan(hit("HP_EC_GO", "a.go", detail="d" * 300, match="m" * 300)), [])
    assert (len(fact.detail), len(fact.match or "")) == (200, 120)
    [bare] = F.source_facts(scan(hit("HP_EC_GO", "a.go")), [])
    assert bare.match is None and "match" not in F._fact_json(bare)


def test_the_facts_document_meets_its_contract_and_counts_by_family() -> None:
    facts = F.source_facts(
        scan(hit("API_GO_CRYPTO_RSA", "pkg/sign.go", match="2048"), hit("HP_EC_GO", "vendor/x.go")),
        [census(P.GO_TOOLCHAIN, "go 1.23", version="1.23")],
    )
    doc = F.facts_document(URL, STAMPS, facts, scan())
    body = json.loads(doc.payload)
    assert body["coverage"] == {
        "assessment_basis": "source", "scanned_files": 40, "skipped_files": 2, "rules_in_pack": 150,
    }  # fmt: skip
    assert body["summary"]["by_path_class"] == {"first_party": 2, "vendor": 1}
    assert body["summary"]["by_qclass"] == {
        "grover_margin": 1,
        "shor_112bit": 1,
        "shor_128bit_plus": 1,
    }
    assert body["facts"][0]["line"] == 1 and "clock" in body["facts"][0]["ir8547"]
    assert F.read_facts(doc) == facts
    assert F.read_stamps(doc) == STAMPS
    assert F.facts_document(URL, STAMPS, facts, scan()).payload == doc.payload  # deterministic


def test_zero_facts_carry_the_assertion_and_only_a_full_pack_is_a_verified_zero_hit() -> None:
    doc = F.facts_document(URL, STAMPS, [], scan())
    assert doc.coverage.no_crypto_detected_assertion == (
        "0 facts with 150 rules over 40 files scanned (2 skipped)"
    )
    assert R.zero_hit(doc)
    assert not R.zero_hit(F.facts_document(URL, STAMPS, [], scan(rules=120)))
    assert not R.zero_hit(
        F.facts_document(URL, STAMPS, F.source_facts(scan(hit("HP_EC_GO", "a.go")), []), scan())
    )


def test_sbom_only_facts_are_components_with_null_coverage() -> None:
    packages = [
        CryptoFact(probe_id=P.PYTHON_CRYPTO_DEP, provider="python", detail="cryptography==43.0.1"),
        CryptoFact(
            probe_id=P.SBOM_COMPONENT, provider="openssl", detail="openssl 3.5.1", version="3.5.1"
        ),
    ]
    facts = F.sbom_facts(packages)
    assert {(f.rule_id, f.pqc_capable) for f in facts} == {
        (F.SBOM_COMPONENT_RULE, None),
        (F.SBOM_COMPONENT_RULE, True),
    }
    doc = F.facts_document(URL, STAMPS, facts, None)
    assert json.loads(doc.payload)["coverage"] == {
        "assessment_basis": "sbom-only", "scanned_files": None, "skipped_files": None,
        "rules_in_pack": None,
    }  # fmt: skip
    assert not R.zero_hit(F.facts_document(URL, STAMPS, [], None))


def test_facts_from_a_newer_adapter_read_their_known_fields() -> None:
    body = json.loads(F.facts_document(URL, STAMPS, [], scan()).payload)
    body["stamps"]["new_stamp"] = "x"
    body["facts"] = [
        {
            "fact_id": "F0000", "rule_id": "HP_EC_GO", "file": "a.go", "line": None, "detail": "",
            "ir8547": {"qclass": "shor_128bit_plus", "usage": "ke", "clock": None, "new": 1},
            "provenance_hint": "native-candidate", "path_class": "first_party", "new_field": True,
        }
    ]  # fmt: skip
    doc = PqcFactsArtifact.from_document(body)
    assert F.read_facts(doc)[0].ir8547.clock is None
    assert F.read_stamps(doc) == STAMPS


def test_long_validity_finds_five_year_certificates(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "pkg/ca.go").write_text(
        "x\nnotAfter := now.AddDate(10, 0, 0)\ny := t.AddDate(1, 0, 0)\n"
    )
    (tmp_path / "gen.sh").write_text("openssl req -x509 -days 3650\nopenssl req -days 1000\n")
    (tmp_path / "mkcert").write_text("openssl x509 -days 1825\n")
    (tmp_path / "vendor/ca.go").write_text("t.AddDate(20, 0, 0)\n")
    (tmp_path / "notes.txt").write_text("-days 9999\n")
    assert [(f.file, f.line, f.detail) for f in long_validity(tmp_path)] == [
        ("gen.sh", 1, "-days 3650"),
        ("mkcert", 1, "-days 1825"),
        ("pkg/ca.go", 2, "AddDate years=10"),
    ]
    with pytest.raises(ValidationError, match="not a directory"):
        long_validity(tmp_path / "missing")


def readiness_doc(**changes: Any) -> PqcReadinessArtifact:
    body = json.loads(json.dumps(REPORT))
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    return PqcReadinessArtifact.from_document(body)


def violations(doc: PqcReadinessArtifact) -> list[tuple[str, str]]:
    return [(v.item, v.message) for v in R.ReadinessRules().check(doc, LintContext())]


def test_the_fixture_report_passes_the_gate() -> None:
    assert violations(readiness_doc()) == []


def rem(**kw: Any) -> dict[str, Any]:
    return {"id": "WIDGET-f1b2984-REM-009", "category": "fix-now", "action": "Do it.", **kw}


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"capabilities": None}, ("capabilities", "missing top-level key")),
        ({"status": "great"}, ("status", "bad status 'great'")),
        ({"quantum_ready": "maybe"}, ("quantum_ready", "bad quantum_ready 'maybe'")),
        ({"who_sets_tls": "someone"}, ("who_sets_tls", "bad who_sets_tls 'someone'")),
        (
            {
                "scores": {
                    **REPORT["scores"],
                    "AGIL": {
                        "score": 0,
                        "checks": [{"id": "AGIL-1", "result": "no", "fact_ids": []}],
                    },
                }
            },
            ("AGIL.checks[0]", "AGIL-1: a non-yes result cites fact_ids"),
        ),
        (
            {"metadata": {**REPORT["metadata"], "assessment_basis": "source+runtime"}},
            ("runtime_evidence", "assessment_basis source+runtime needs runtime_evidence.pqc_caps"),
        ),
        (
            {"remediations": [rem(), rem()]},
            ("remediations[1]", "duplicate id 'WIDGET-f1b2984-REM-009'"),
        ),
        ({"remediations": [rem(action="  ")]}, ("remediations[0]", "empty action")),
        (
            {"remediations": [rem(category="waiting-on-upstream")]},
            ("remediations[0]", "waiting-on-upstream needs blocked_on"),
        ),
        (
            {"remediations": [rem(category="deadline", deadline=2031)]},
            ("remediations[0]", "category deadline needs deadline 2030 or 2035, got 2031"),
        ),
        (
            {"remediations": [rem(fact_ids=["F0001"])]},
            ("remediations[0]", "fact_ids belong on scores/clock_items; owners use locations[]"),
        ),
        ({"do_next": ["fix it"]}, ("do_next[0]", "must be an object")),
        ({"do_next": [{"who": "platform", "do": ""}]}, ("do_next[0]", "empty do")),
        (
            {
                "do_next": [
                    {"who": "platform", "do": "x", "how": "see `remediation/tls-ke-client/go.md`"}
                ]
            },
            ("do_next[0].how", "cites a harness-local path; distill the playbook into prose"),
        ),
        (
            {"do_next": [{"who": "platform", "do": "fix F0003"}]},
            ("do_next[0].do", "contains a fact id; owners use locations[]"),
        ),
        (
            {"do_next": [{"who": "platform", "do": "x", "fact_ids": ["F1"]}]},
            ("do_next[0]", "fact_ids not allowed; use locations[]"),
        ),
        (
            {"do_next": [{"who": "app", "do": "x"}]},
            ("do_next[0]", "who=app needs locations[] (repo file:line anchors for the owner)"),
        ),
    ],
)
def test_the_gate_refuses(changes: dict[str, Any], expected: tuple[str, str]) -> None:
    assert violations(readiness_doc(**changes)) == [expected]


def test_a_missing_choice_is_also_a_bad_choice() -> None:
    assert violations(readiness_doc(status=None)) == [
        ("status", "missing top-level key"),
        ("status", "bad status None"),
    ]


def test_the_schema_refuses_what_it_covers() -> None:
    for changes in (
        {"readiness_bucket": "great"},
        {"remediations": [rem(id="REM-001")]},
        {
            "clock_items": [
                {
                    "fact_ids": [],
                    "primitive": "x",
                    "disallowed_after": None,
                    "remediation_effort": "easy",
                }
            ]
        },
        {"fips_interaction": {"verdict": "fine", "fact_ids": []}},
    ):
        with pytest.raises(ValidationError):
            readiness_doc(**changes)


def test_the_gate_checks_only_readiness_reports() -> None:
    with pytest.raises(ValidationError, match="checks pqc-readiness"):
        R.ReadinessRules().check(F.facts_document(URL, STAMPS, [], scan()), LintContext())


def found(doc: PqcReadinessArtifact) -> PqcReadiness:
    return R.readiness(doc, uuid4(), uuid4(), AT)


def test_the_report_reads_as_a_scorecard_with_remediations() -> None:
    r = found(readiness_doc())
    assert (r.bucket, r.overall, r.dominant, r.has_2030_clock_items) == (
        PqcReadinessBucket.PARTIAL, 57.5, "native-first-party", True,
    )  # fmt: skip
    assert [x.id for x in r.remediations] == [f"WIDGET-f1b2984-REM-00{i}" for i in (1, 2, 3)]
    assert r.is_blocked()
    assert not found(readiness_doc(remediations=[rem(locations=[])])).is_blocked()
    assert found(readiness_doc(readiness_bucket=None)).bucket is None


@pytest.mark.parametrize(
    ("category", "deadline", "severity", "classification"),
    [
        ("fix-now", None, Severity.HIGH, PqcClassification.PQC_BLOCKER_CONFIG),
        ("deadline", 2030, Severity.MEDIUM, PqcClassification.CLOCK_2030_PARAMETER),
        ("deadline", 2035, Severity.LOW, PqcClassification.PQC_BLOCKER_CONFIG),
        ("deadline", None, Severity.MEDIUM, PqcClassification.PQC_BLOCKER_CONFIG),
        ("upgrade", None, Severity.LOW, PqcClassification.PQC_ADOPTION),
        ("waiting-on-upstream", None, Severity.INFORMATIONAL, PqcClassification.PQC_BLOCKER_CONFIG),
    ],
)
def test_severity_and_classification_map(
    category: str, deadline: int | None, severity: Severity, classification: PqcClassification
) -> None:
    r = PqcRemediation(
        id="X-u000000-REM-001",
        category=PqcRemediationCategory(category),
        action="a",
        deadline=deadline,
    )
    assert (R.severity(r), R.classification(r)) == (severity, classification)


def test_blockers_carry_the_findings_vocabulary_and_who_is_patchable() -> None:
    r = found(readiness_doc())
    assert r.who_sets_tls == "this_app"
    assert [
        (b.remediation.id, b.severity, b.classification, b.patchable) for b in R.blockers(r)
    ] == [
        ("WIDGET-f1b2984-REM-001", Severity.HIGH, PqcClassification.PQC_BLOCKER_CONFIG, True),
        ("WIDGET-f1b2984-REM-002", Severity.MEDIUM, PqcClassification.CLOCK_2030_PARAMETER, True),
        (
            "WIDGET-f1b2984-REM-003",
            Severity.INFORMATIONAL,
            PqcClassification.PQC_BLOCKER_CONFIG,
            False,
        ),
    ]
    assert R.blockers(found(readiness_doc(remediations=None))) == []


def fact(
    rule_id: str = "API_GO_CRYPTO_RSA", path: PqcPathClass = PqcPathClass.FIRST_PARTY, **kw: Any
) -> PqcFact:
    return PqcFact(
        fact_id="F0000", rule_id=rule_id, file="a.go", ir8547=F.map_rule(rule_id),
        provenance_hint="native-candidate", path_class=path, **kw,
    )  # fmt: skip


def prior(bucket: str = "partial", clock: bool = False, hndl: bool = False) -> PqcReadiness:
    return PqcReadiness(
        assessment_id=uuid4(), repository_ref_id=uuid4(), assessed_at=AT,
        bucket=PqcReadinessBucket(bucket), overall=60, has_2030_clock_items=clock,
        hndl_priority=hndl, runtime_verification_required=True, dominant="none",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("facts", "previous", "expected"),
    [
        ([fact("HP_GOV_PLATFORM_OCP_LIBGO")], prior(), PqcRoute.FULL),
        ([fact("HP_DB_CLIENT_TLS")], prior(), PqcRoute.FULL),
        ([fact(fips_mode=True)], prior(), PqcRoute.FULL),
        ([fact()], prior(clock=True), PqcRoute.FULL),
        ([fact()], prior(hndl=True), PqcRoute.FULL),
        ([fact()], prior("not-ready"), PqcRoute.FULL),
        ([fact()], prior("blocked-external"), PqcRoute.FULL),
        ([fact()], prior(), PqcRoute.LIGHT),
        (
            [fact("HP_GOV_PLATFORM_OCP_DIRECT", PqcPathClass.VENDOR), fact()],
            prior(),
            PqcRoute.LIGHT,
        ),
        ([], prior("not-applicable"), PqcRoute.SKIP),
        ([fact(path=PqcPathClass.VENDOR)], prior(), PqcRoute.SKIP),
        ([fact(path=PqcPathClass.TEST_DOCS)], prior(clock=True), PqcRoute.SKIP),
        ([fact()], None, PqcRoute.UNSCORED),
    ],
)
def test_the_layer_2_route(
    facts: list[PqcFact], previous: PqcReadiness | None, expected: PqcRoute
) -> None:
    assert R.route(facts, previous) is expected


def test_a_zero_hit_is_not_applicable_with_nothing_to_do() -> None:
    ids = uuid4(), uuid4()
    r = R.zero_hit_readiness(*ids, AT)
    assert (r.assessment_id, r.repository_ref_id, r.assessed_at) == (*ids, AT)
    assert (r.bucket, r.overall, r.dominant, r.remediations, r.is_blocked()) == (
        PqcReadinessBucket.NOT_APPLICABLE, 100, "none", (), False,
    )  # fmt: skip
    assert (r.has_2030_clock_items, r.hndl_priority, r.runtime_verification_required) == (
        False, False, True,
    )  # fmt: skip


def test_stamps_compare_by_adapter_and_rules() -> None:
    assert STAMPS.same_pack(
        STAMPS.model_copy(update={"binary_sha256": "x", "pqc_scan_commit": "y"})
    )
    assert not STAMPS.same_pack(STAMPS.model_copy(update={"adapter_version": "1.5.0"}))
    assert not STAMPS.same_pack(STAMPS.model_copy(update={"rules_sha256": "cd" * 32}))
