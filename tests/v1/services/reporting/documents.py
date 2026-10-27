"""Report documents that pass every check, ported from traust-engine's and traust's reporting
tests; each test mutates a fresh copy."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

from traust_core.v1 import contracts

Doc = dict[str, Any]

SURFACES = contracts.enum_values("review-surface")
ORIGINAL_SHA = "abcdef0123456789abcdef0123456789abcdef01"
PATCHED_SHA = "1234567890abcdef1234567890abcdef12345678"
FIX_SHA = "feedfacefeedfacefeedfacefeedfacefeedface"
GENERATED_AT = "2026-07-28T23:19:00+00:00"
TODAY = date(2026, 10, 27)


def write(directory: Path, name: str, document: Any) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def valid_report() -> Doc:
    rep: Doc = {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-05-21",
            "scope": "First-party Go source (cmd/, pkg/), Kubernetes manifests, Dockerfiles",
            "repository": "https://github.com/example/widget-operator",
        },
        "executive_summary": {
            "prose": (
                "The Widget Operator manages resources in OpenShift clusters. "
                "This assessment identified 2 findings across the codebase."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {
                "level": "critical",
                "definition": "Remote attacker achieves node-root or cluster-admin without "
                "authentication.",
            },
            {
                "level": "high",
                "definition": "Authenticated user escalates privileges across namespace "
                "boundaries.",
            },
            {
                "level": "medium",
                "definition": "Requires elevated prerequisites or enables denial of service.",
            },
            {
                "level": "low",
                "definition": "Hardening gap or best-practice deviation with no direct "
                "exploitability.",
            },
        ],
        "findings": [
            {
                "id": "TEST-001",
                "title": "SSRF via Webhook Annotation",
                "severity": "high",
                "cwes": ["CWE-918"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "42-58"}],
                "description": (
                    "The admission webhook reads a destination URL from a pod annotation "
                    "and makes an HTTP POST without validating against an allow-list."
                ),
                "remediation": "Validate the callback URL against a configurable allow-list of "
                "permitted hosts.",
            },
            {
                "id": "TEST-002",
                "title": "Unbounded Request Body Read",
                "severity": "medium",
                "cwes": ["CWE-770"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "30-35"}],
                "description": (
                    "The admission webhook reads the entire request body with io.ReadAll "
                    "without setting a size limit, enabling memory exhaustion."
                ),
                "remediation": "Replace io.ReadAll with io.LimitReader(r.Body, maxBodySize).",
            },
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": ["TEST-001"]},
            {"severity": "medium", "count": 1, "finding_ids": ["TEST-002"]},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "P0",
                "action": "Implement URL allow-list validation for webhook callbacks",
                "addresses": ["TEST-001"],
            },
            {
                "priority": "P1",
                "action": "Add io.LimitReader to admission webhook body read",
                "addresses": ["TEST-002"],
            },
        ],
    }
    for f in rep["findings"]:
        f["fingerprint"] = hashlib.sha256(f["id"].encode()).hexdigest()
    return rep


def consistency_report() -> Doc:
    """`valid_report` at the 0.15.0 conventions (canonical ids, commit, harness_version)."""
    r = valid_report()
    r["metadata"]["commit"] = ORIGINAL_SHA
    r["metadata"]["additional"] = {"harness_version": "0.15.0-1234567"}
    text = json.dumps(r)
    text = text.replace("TEST-001", "TEST_WIDGET-abcdef0-001")
    text = text.replace("TEST-002", "TEST_WIDGET-abcdef0-002")
    r = json.loads(text)
    for f in r["findings"]:
        f["validation_status"] = "not_verified"
    r["peach_isolation_review"] = {
        "applicable": False,
        "rationale": "Single-tenant operator: one deployment serves exactly one cluster and "
        "trust domain.",
    }
    return r


def cumulative_report() -> Doc:
    """`consistency_report` as track-findings writes it: a disposition on every finding."""
    r = consistency_report()
    for f in r["findings"]:
        f["disposition"] = {
            "validity": f["validation_status"],
            "resolution": "open",
            "last_updated": "2026-07-10T12:00:00+00:00",
            "events": [],
        }
    r["disposition_summary"] = {
        "layer_ref": "test-widget-findings-layer.json",
        "generated_at": "2026-07-10T12:00:00+00:00",
        "by_resolution": {
            "open": 2,
            "fix_in_progress": 0,
            "resolved": 0,
            "partially_resolved": 0,
            "risk_accepted": 0,
            "regression_introduced": 0,
        },
        "by_validity": {"confirmed": 0, "corrected": 0, "false_positive": 0, "not_verified": 2},
        "conflicts": [],
        "needs_review_count": 0,
    }
    return r


def _commit(relevance: str) -> Doc:
    return {
        "sha": FIX_SHA,
        "short_sha": FIX_SHA[:7],
        "date": "2026-06-15T10:00:00+00:00",
        "author": "Jane Dev <jane@example.com>",
        "subject": "Validate webhook URL against allow-list (#42)",
        "pr_number": 42,
        "relevance": relevance,
    }


def valid_verification_report() -> Doc:
    return {
        "title": "example-app Remediation Verification",
        "metadata": {
            "date": "2026-07-10",
            "harness_version": "0.17.0-1234567",
            "original_report": "findings/example-operator/example-app/"
            "example-app-security-audit.json",
            "original_commit": ORIGINAL_SHA,
            "patched_commit": PATCHED_SHA,
            "patched_ref": "pull/42/head",
            "repository": "https://github.com/example-org/example-app",
        },
        "summary": {
            "total_findings": 2,
            "by_verdict": {
                "resolved": 1,
                "partially_resolved": 1,
                "unresolved": 0,
                "new_approach": 0,
                "regression": 0,
                "false_positive": 0,
                "risk_accepted": 0,
            },
            "regressions": 1,
        },
        "verified_findings": [
            {
                "original_id": "EXAMPLE_APP-abcdef0-001",
                "original_title": "SSRF via Webhook Annotation",
                "original_severity": "high",
                "verdict": "resolved",
                "remediation_commits": [_commit("direct")],
                "unattributed": False,
                "evidence": {
                    "original_code": "http.Post(url, ct, body)",
                    "patched_code": "if !allowlist.Match(url) { return errDenied }",
                    "explanation": (
                        "Webhook callback URLs are now validated against a "
                        "configurable allow-list before any request is made."
                    ),
                    "framework_reference": "CWE-918",
                },
                "disposition_rationale": None,
                "residual_risk": None,
                "residual_severity": None,
            },
            {
                "original_id": "EXAMPLE_APP-abcdef0-002",
                "original_title": "Unbounded Request Body Read",
                "original_severity": "medium",
                "verdict": "partially_resolved",
                "remediation_commits": [_commit("partial")],
                "unattributed": False,
                "evidence": {
                    "original_code": "body, _ := io.ReadAll(r.Body)",
                    "patched_code": "body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))",
                    "explanation": (
                        "The admission path now bounds the body read, but the "
                        "metrics path still calls io.ReadAll unbounded."
                    ),
                    "framework_reference": "CWE-770",
                },
                "disposition_rationale": None,
                "residual_risk": "Metrics endpoint body read remains unbounded.",
                "residual_severity": "low",
            },
        ],
        "regressions": [
            {
                "id": "EXAMPLE_APP-1234567-REG-001",
                "title": "Allow-list bypass via URL userinfo",
                "severity": "medium",
                "cwes": ["CWE-918"],
                "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "60-72"}],
                "description": (
                    "The new allow-list matcher compares the raw authority "
                    "before stripping userinfo, so https://allowed@evil.example "
                    "bypasses the check."
                ),
                "remediation": "Parse the URL and compare url.Hostname() only.",
                "evidence": [{"code": "if allowlist.Match(u.Host) {", "language": "go"}],
                "introduced_by": FIX_SHA,
            }
        ],
        "commit_timeline": [
            {
                "sha": FIX_SHA[:7],
                "full_sha": FIX_SHA,
                "date": "2026-06-15T10:00:00+00:00",
                "author": "Jane Dev <jane@example.com>",
                "subject": "Validate webhook URL against allow-list (#42)",
                "pr_number": 42,
                "addresses": ["EXAMPLE_APP-abcdef0-001", "EXAMPLE_APP-abcdef0-002"],
            }
        ],
        "recommendations": [
            "Bound the metrics endpoint body read to close EXAMPLE_APP-abcdef0-002."
        ],
    }


def valid_live_validation_report() -> Doc:
    return {
        "title": "Live validation of a synthetic application",
        "metadata": {
            "date": "2026-10-23",
            "harness_version": "0.175.0",
            "scope_binding_mode": "explicit",
            "target_fingerprint": [],
        },
        "source_reports": [{"kind": "security-audit", "path": "source-audit.json"}],
        "summary": {
            "by_verdict": {
                "confirmed": 0,
                "refuted": 0,
                "inconclusive": 0,
                "blocked_by_scope": 0,
                "not_attempted": 0,
            },
            "by_technique": {},
        },
        "validated_findings": [],
        "attack_chains": [],
        "novel_findings": [],
        "execution_log_ref": "validation-audit.jsonl",
    }


def valid_readiness_report() -> Doc:
    return {
        "title": "Synthetic PQC readiness assessment",
        "metadata": {
            "repository": "https://github.com/example/widget",
            "assessment_basis": "source",
            "tool": {"pqc_scan_commit": "fixture", "rules_sha256": "a" * 64},
        },
        "summary": {"by_rule": {}},
        "status": "ready",
        "who_sets_tls": "this_app",
        "quantum_ready": "yes_by_default",
        "why_not": [],
        "do_next": [],
        "capabilities": {},
        "scores": {
            **{domain: {"score": 0, "checks": []} for domain in ("VULN", "AGIL", "PQCA", "HNDL")},
            "overall": 0,
        },
        "flags": {
            "has_2030_clock_items": False,
            "hndl_priority": False,
            "runtime_verification_required": True,
        },
        "provenance_summary": {"counts": {}, "dominant": "none"},
        "readiness_bucket": "ready",
    }


def _triage_finding(**kw: Any) -> Doc:
    base: Doc = {
        "id": "f001",
        "orig_id": "TEST_REPO-abc1234-001",
        "title": "Cross-tenant token theft via scope gap",
        "file": "pkg/rbac/scope.go",
        "line": 37,
        "category": "authorization",
        "claimed_severity": "critical",
        "verdict": "true_positive",
        "verify_verdict": "exploitable",
        "confidence": 9.0,
        "severity": "critical",
        "rationale": "reachable at handler.go:73; no ownership check",
        "vote_breakdown": {
            "true_positive": 3,
            "hardening": 0,
            "false_positive": 0,
            "cannot_verify": 0,
        },
        "refute_reasons": [],
        "exclusion_rule": None,
        "first_links": ["plugins/credentials/plugin.go:73"],
        "duplicate_of": None,
        "owner_hint": "@maintainers (CODEOWNERS)",
    }
    return base | kw


def valid_triage() -> Doc:
    return {
        "triage_completed": "2026-07-09",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant internet-facing platform",
            "votes_per_finding": 3,
            "repo": "/tmp/clone",
            "harness_version": "0.24.0-e240e87",
        },
        "summary": {
            "input_count": 3,
            "true_positives": 1,
            "hardening": 1,
            "false_positives": 1,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            _triage_finding(),
            _triage_finding(
                id="f002",
                orig_id="TEST_REPO-abc1234-002",
                title="CORS wildcard on public API",
                verdict="hardening",
                verify_verdict="hardening",
                severity=None,
                exclusion_rule="13",
                confidence=8.0,
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 3,
                    "false_positive": 0,
                    "cannot_verify": 0,
                },
            ),
            _triage_finding(
                id="f003",
                orig_id="TEST_REPO-abc1234-003",
                title="Dev-overlay default credentials",
                verdict="false_positive",
                verify_verdict="refuted",
                severity=None,
                exclusion_rule="2",
                confidence=8.0,
                refute_reasons=["intentional_behavior"],
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 0,
                    "false_positive": 3,
                    "cannot_verify": 0,
                },
                owner_hint=None,
            ),
        ],
    }


def valid_vuln_findings() -> Doc:
    return {
        "target": "targets/example-repo",
        "scanned_at": "2026-07-12T20:00:00Z",
        "focus_areas": ["HTTP handlers (pkg/server) — render, upload"],
        "metadata": {
            "repo": "example-repo",
            "repo_slug": "EXAMPLE_REPO",
            "scanned_ref": "abc1234",
            "harness_version": "0.38.0-de5a090",
            "baseline": "findings/example-repo/example-repo-security-audit.json",
            "baseline_findings": 12,
        },
        "findings": [
            {
                "id": "EXAMPLE_REPO-abc1234-001",
                "scanner_ref": "F-01-01",
                "file": "pkg/server/handler.go",
                "line": 73,
                "category": "command-injection",
                "cwe": "CWE-78",
                "severity": "high",
                "confidence": 0.9,
                "title": "Command injection via unsanitized template value",
                "description": (
                    "The handler passes the request's template parameter into "
                    "exec.Command without sanitization; untrusted input reaches the "
                    "shell at handler.go:73."
                ),
                "exploit_scenario": "POST a template containing $(id) to /render.",
                "recommendation": "Use exec.Command with a fixed argv; never a shell string.",
                "confidence_reason": "Direct data flow from request to sink.",
            }
        ],
        "known_findings": [
            {
                "title": "Path traversal in upload handler",
                "matches_baseline_id": "EXAMPLE_REPO-9cb7556-004",
            }
        ],
        "summary": {
            "total": 1,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "known": 1,
            "low_confidence": 0,
        },
    }


def _cloud_finding(n: int, check: str, severity: str, status: str, rationale: str) -> Doc:
    return {
        "id": f"CCA-widget-00{n}",
        "fact_ids": [f"cca-d0055ddb7a4{n}"],
        "framework": "terraform",
        "provider": "aws",
        "check_id": check,
        "title": "S3 bucket lacks server-side encryption",
        "severity": severity,
        "scanner_severity": "unrated",
        "status": status,
        "rationale": rationale,
        "locations": [
            {
                "file_path": "/main.tf",
                "resource": "aws_s3_bucket.artifacts",
                "file_line_range": [10, 24],
            }
        ],
        "cwe": "CWE-311",
        "control_refs": [],
        "remediation": "Enable SSE-S3 on the bucket.",
        "disposition": {
            "validity": "not_verified",
            "resolution": "open",
            "assurance": "claimed",
            "last_updated": GENERATED_AT,
            "events": [],
        },
        "validation_status": "not_verified",
        "effective_severity": severity,
    }


def valid_cloud_config_current() -> Doc:
    """What build_cumulative emits over a cloud-config-audit baseline."""
    return {
        "title": "Cloud config audit — widget (declared layer) — Cumulative Findings Status",
        "metadata": {
            "target": "widget",
            "assessment_mode": "declared",
            "target_head": "6cb81ba1a4077a2b812d6c8403d9f4f871a3d9f3",
            "ref": "main",
            "ref_kind": "default",
            "repository": "https://github.com/example/widget",
            "harness_version": "0.202.0",
            "checkov_version": "3.3.6",
            "facts_ref": "analysis-results/cloud-config/widget/widget-cloud-facts.json",
            "facts_snapshot_id": "b50717124734aae7",
            "generated_at": "2026-07-28T20:52:36Z",
            "frameworks": ["terraform"],
            "deterministic_steps": [
                {
                    "tool": "checkov (via run_checkov.py)",
                    "invocation": "python3 run_checkov.py --target-dir .",
                    "version": "3.3.6",
                }
            ],
            "additional": {
                "cumulative": {
                    "source_audit": "widget-cloud-config-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": None,
                    "generated_at": GENERATED_AT,
                }
            },
            "date": "2026-07-28",
        },
        "summary": {
            "facts_total": 2,
            "confirmed": 1,
            "suppressed": 1,
            "needs_review": 0,
            "gaps": 0,
            "by_severity": {"low": 1, "informational": 1},
            "by_provider": {"aws": 2},
        },
        "findings": [
            _cloud_finding(1, "CKV_AWS_1", "low", "confirmed", "Rubric row R4: hygiene gap."),
            _cloud_finding(
                2, "CKV_AWS_2", "informational", "suppressed", "Handled by the backup pipeline."
            ),
        ],
        "gaps": [],
        "disposition_summary": {
            "layer_ref": "widget-findings-layer.json",
            "generated_at": GENERATED_AT,
            "by_resolution": {
                "open": 2,
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {
                "confirmed": 0,
                "corrected": 0,
                "false_positive": 0,
                "not_verified": 2,
                "hardening": 0,
            },
            "severity_overrides": [],
            "conflicts": [],
            "needs_review_count": 0,
        },
    }


def code_audit_current() -> Doc:
    """A code-audit cumulative stub: its stamp names a security-audit baseline."""
    return {
        "title": "Security Assessment — Widget — Cumulative Findings Status",
        "metadata": {
            "date": "2026-07-28",
            "scope": "First-party Go source under cmd/ and pkg/.",
            "additional": {
                "cumulative": {
                    "source_audit": "widget-security-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": "2026-07-01",
                    "generated_at": GENERATED_AT,
                }
            },
        },
    }
