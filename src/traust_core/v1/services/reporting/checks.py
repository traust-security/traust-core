"""Content checks on a report document past its schema: counts against findings, canonical ids,
review-surface records, version-gated conventions, and the strict-mode warnings."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import PurePath
from typing import Any
from urllib.parse import urlparse

from traust_core.v1 import contracts
from traust_core.v1.providers.report_files import ReportFiles
from traust_core.v1.services.artifact_publishing import RedactionPolicy

Report = dict[str, Any]

MANDATORY_SEVERITY_LEVELS = {"critical", "high", "medium", "low"}

CANONICAL_FINDING_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,23}-[a-f0-9]{7}-\d{3}$")

# traust reset its version to 0.1.0 on this date; pre- and post-reset versions overlap, so a gate
# reads the audit date to pick the numbering first (`_gate`). Thresholds are pre-reset unless
# named REVIEW_SURFACE_*.
VERSION_RESET_DATE = "2026-09-10"
CANONICAL_ID_MIN_VERSION = (0, 12, 0)
CONSISTENCY_MIN_VERSION = (0, 15, 0)
REVIEW_SURFACE_MIN_VERSION = (0, 20, 0)
REVIEW_SURFACE_EXTENDED_MIN_VERSION = (0, 21, 0)
DETERMINISTIC_STEPS_MIN_VERSION = (0, 60, 1)

RECOMMENDED_CATEGORIES = {
    "injection",
    "authentication",
    "authorization",
    "secrets-management",
    "supply-chain",
    "insecure-workload-config",
    "network-exposure",
    "cryptography",
    "input-validation",
    "path-traversal",
    "cross-site-scripting",
    "ssrf",
    "resource-management",
    "logging-monitoring",
    "data-exposure",
    "tenant-isolation",
}

# Copied CIS/STIG recommendation titles are a content-license violation; cite bare section ids.
CIS_CONTROL_TEXT_RE = re.compile(
    r"[Ee]nsure that the [^\n]{0,80}?(argument|parameter|plugin) is set"
)

# build_org_index's parse_org_repo() acceptance rules: a value it can't parse hides the report.
_REPO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_REPO_HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_REPO_URL_RE = re.compile(r"^https://[a-z0-9.-]+/[^/]+/.+$", re.I)

_BANDS = (("critical", 9.0), ("high", 7.0), ("medium", 4.0), ("low", 0.1))
_BAND_ORDER = ["informational", "low", "medium", "high", "critical"]
_DOWNGRADE_RATIONALE = re.compile(
    r"deployment context|contextual|downgrad|base score|CVSS base|"
    r"advisory (score|CVSS)|rated (low|medium|informational)|"
    r"not attacker.reachable|reachab",
    re.IGNORECASE,
)

# Families with their own schema whose findings carry no authored audit-report identity.
_NON_AUDIT = (
    "validation",
    "remediation",
    "verification",
    "layer",
    "triage",
    "vuln-findings",
    "cloud-config-findings-current",
    "cloud-config-audit",
    "threat-model",
    "refuted-register",
    "operator-priv-profile",
    "pqc-readiness",
    "adapter-result",
)
_SCHEMA_ONLY = ("refuted-register", "operator-priv-profile", "pqc-readiness", "adapter-result")


@dataclass
class ReportValidation:
    """One report file's errors and warnings; it passes with no errors."""

    file_path: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @property
    def passed(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class CheckContext:
    """What the checks read beyond the document: today, the secret scan, sibling files."""

    today: date
    redaction: RedactionPolicy
    files: ReportFiles


def _normalize_category(value: str) -> str:
    return re.sub(r"[\s_]+", "-", value.strip().lower())


def _parse_harness_version(meta: dict[str, Any]) -> tuple[int, int, int] | None:
    hv = (meta.get("additional") or {}).get("harness_version")
    if not hv:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(hv))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _audit_date(meta: dict[str, Any]) -> str:
    # A cumulative report re-stamps metadata.date but keeps the audit's harness_version.
    cumulative = (meta.get("additional") or {}).get("cumulative") or {}
    return str(cumulative.get("original_report_date") or meta.get("date") or "")


def _post_reset(meta: dict[str, Any]) -> bool:
    audited = _audit_date(meta)
    return bool(re.match(r"^\d{4}-\d{2}-\d{2}", audited)) and audited[:10] >= VERSION_RESET_DATE


def _gate(
    meta: dict[str, Any],
    *,
    legacy: tuple[int, int, int] | None = None,
    current: tuple[int, int, int] | None = None,
) -> bool:
    """Whether a version-gated rule applies: `legacy` is a pre-reset threshold every post-reset
    release meets, `current` a post-reset one; no parseable harness_version is never gated."""
    hv = _parse_harness_version(meta)
    if hv is None:
        return False
    if _post_reset(meta):
        return current is None or hv >= current
    return legacy is not None and hv >= legacy


def format_path(path: tuple[str | int, ...]) -> str:
    """A schema error's path as `a.b[0].c`; `(root)` when empty."""
    parts: list[str] = []
    for p in path:
        if isinstance(p, int):
            parts.append(f"[{p}]")
        else:
            parts.append(f".{p}" if parts else str(p))
    return "".join(parts) or "(root)"


def cross_validate(report: Report, result: ReportValidation) -> None:
    findings = report.get("findings", [])
    finding_ids = [f["id"] for f in findings]
    finding_id_set = set(finding_ids)

    for fid in [fid for fid, cnt in Counter(finding_ids).items() if cnt > 1]:
        result.error(f"Duplicate finding ID: {fid}")

    defined_levels = {c["level"] for c in report.get("severity_criteria", [])}
    for level in sorted(MANDATORY_SEVERITY_LEVELS - defined_levels):
        result.error(f"Severity criteria missing mandatory level: {level}")

    actual_counts = Counter(f["severity"] for f in findings)
    for entry in report.get("findings_summary", []):
        sev = entry["severity"]
        expected = actual_counts.get(sev, 0)
        declared = entry["count"]
        if declared != expected:
            result.error(
                f"findings_summary[{sev}]: count is {declared}, "
                f"but {expected} finding(s) have severity '{sev}'"
            )
        if len(entry["finding_ids"]) != declared:
            result.error(
                f"findings_summary[{sev}]: count is {declared}, "
                f"but finding_ids has {len(entry['finding_ids'])} entries"
            )

    all_summary_ids = set()
    for entry in report.get("findings_summary", []):
        for fid in entry["finding_ids"]:
            if fid not in finding_id_set:
                result.error(f"findings_summary references unknown finding ID: {fid}")
            all_summary_ids.add(fid)
    missing = finding_id_set - all_summary_ids
    if missing:
        result.error(f"Findings not listed in any findings_summary entry: {sorted(missing)}")

    for item in report.get("remediation_roadmap", []):
        for fid in item.get("addresses", []):
            if fid not in finding_id_set:
                result.error(f"remediation_roadmap references unknown finding ID: {fid}")

    es_counts = report.get("executive_summary", {}).get("severity_counts", {})
    for sev, declared in es_counts.items():
        expected = actual_counts.get(sev, 0)
        if declared != expected:
            result.error(
                f"executive_summary.severity_counts[{sev}]: declared {declared}, "
                f"but {expected} finding(s) have severity '{sev}'"
            )

    peach = report.get("peach_isolation_review")
    if peach is not None:
        if not peach.get("applicable"):
            if peach.get("interfaces"):
                result.error(
                    "peach_isolation_review.applicable is false but interfaces[] is non-empty"
                )
            for i, f in enumerate(findings):
                if f.get("peach_references"):
                    result.error(
                        f"findings[{i}] ({f.get('id')}): peach_references set but "
                        f"peach_isolation_review.applicable is false"
                    )
        for iface in peach.get("interfaces") or []:
            for fid in iface.get("finding_ids") or []:
                if fid not in finding_id_set:
                    result.error(
                        f"peach_isolation_review.interfaces[{iface.get('name')}] "
                        f"references unknown finding ID: {fid}"
                    )

    lb = report.get("metadata", {}).get("loc_breakdown")
    if lb and lb.get("by_language"):
        lang_sum = sum(lb["by_language"].values())
        if lang_sum != lb.get("total"):
            result.warn(
                f"metadata.loc_breakdown: by_language sums to {lang_sum} "
                f"but total is {lb.get('total')}"
            )

    # A warning, not an error, so historical reports keep validating.
    repo_raw = str((report.get("metadata") or {}).get("repository") or "")
    if repo_raw:
        if repo_raw.startswith("<") or repo_raw.rstrip().endswith(">"):
            result.warn(
                "metadata.repository is wrapped in angle brackets "
                f"({repo_raw!r}) — strip the markdown autolink wrapper"
            )
        elif re.search(r"[;\s]", repo_raw.strip()):
            result.warn(
                "metadata.repository contains whitespace/multiple URLs "
                f"({repo_raw[:80]!r}) — use exactly one repository URL"
            )
        elif not re.match(r"^(https?://|git@)", repo_raw.strip()):
            result.warn(
                f"metadata.repository ({repo_raw[:80]!r}) is not a URL — "
                "use the full https:// (or git@) repository URL"
            )

    meta = report.get("metadata", {})
    hv = _parse_harness_version(meta)
    enforce = _gate(meta, legacy=CANONICAL_ID_MIN_VERSION)
    commit = meta.get("commit", "")
    shortsha = re.match(r"^[a-f0-9]{7}", str(commit).lower())
    for i, f in enumerate(findings):
        fid = f.get("id", "")
        if CANONICAL_FINDING_ID.match(fid):
            if shortsha and f"-{shortsha.group(0)}-" not in fid:
                result.warn(
                    f"findings[{i}] ({fid}): SHORTSHA segment does not match "
                    f"metadata.commit ({shortsha.group(0)})"
                )
            continue
        msg = (
            f"findings[{i}] ({fid}): non-canonical finding ID — expected "
            f"{{REPO_SLUG}}-{{SHORTSHA}}-{{NNN}} "
            f"(e.g. EXAMPLE_PROXY-abc1234-001)"
        )
        if enforce:
            assert hv is not None
            result.error(
                msg + f" [canonical IDs required: harness_version {'.'.join(map(str, hv))}]"
            )
        else:
            result.warn(msg + " [legacy report — re-audit to migrate]")
    if enforce and not commit:
        result.error(
            "metadata.commit is required once canonical IDs apply "
            "(SHORTSHA component of canonical finding IDs)"
        )

    if _gate(meta, legacy=CONSISTENCY_MIN_VERSION):
        if "peach_isolation_review" not in report:
            result.error(
                "peach_isolation_review is required for harness >= 0.15.0 — "
                "record {applicable: false, rationale: <why>} for "
                "single-tenant components"
            )
        for i, f in enumerate(findings):
            if "validation_status" not in f:
                result.error(
                    f"findings[{i}] ({f.get('id', '?')}): validation_status is "
                    "required for harness >= 0.15.0 — audit-stage findings "
                    "default to 'not_verified'"
                )

    _cross_validate_dispositions(report, result)
    _cross_validate_review_surfaces(report, result)


def check_metadata_repository(report: Report, result: ReportValidation) -> None:
    """`metadata.repository` is the first field of the cross-scan fingerprint, so a malformed
    value silently yields a wrong identity: an error."""
    repo = (report.get("metadata") or {}).get("repository")
    if repo is None or not str(repo).strip():
        result.error(
            "metadata.repository is absent — it is the first field of the "
            "cross-scan fingerprint, so an empty value silently produces a "
            "wrong identity. Set it from the caller, not from the model."
        )
        return
    s = str(repo).strip()
    if s.startswith("<") and s.endswith(">"):
        result.error(
            f"metadata.repository is wrapped in markdown autolink brackets "
            f"({s[:60]}) — the brackets are hashed into the fingerprint. "
            "Strip them."
        )
        return
    if not _REPO_URL_RE.match(s):
        result.error(
            f"metadata.repository {s[:60]!r} does not look like a "
            f"<scheme>://<host>/<org>/<repo> URL — it is the first field of "
            f"the cross-scan fingerprint, so a malformed value yields a wrong "
            f"identity."
        )


def _cross_validate_review_surfaces(report: Report, result: ReportValidation) -> None:
    """review_surface_coverage is required from REVIEW_SURFACE_MIN_VERSION on, and each entry
    must point at something in the report: a finding, a negative result, a coverage gap."""
    meta = report.get("metadata", {}) or {}
    record = report.get("review_surface_coverage")
    if record is None:
        profile = meta.get("audit_profile")
        since = {
            "code": REVIEW_SURFACE_MIN_VERSION,
            "rpm": REVIEW_SURFACE_EXTENDED_MIN_VERSION,
        }.get(profile)
        if since and _gate(meta, current=since):
            result.error(
                f"review_surface_coverage is required for {profile}-profile audits from "
                f"traust {'.'.join(map(str, since))} — record finding / negative / "
                "not_applicable / not_assessed / out_of_scope for each review surface"
            )
        return
    if not isinstance(record, dict):
        return
    finding_ids = {f.get("id") for f in report.get("findings", []) if isinstance(f, dict)}
    areas = [
        str(n.get("area", ""))
        for n in report.get("negative_results", []) or []
        if isinstance(n, dict)
    ]
    gaps = {
        (g.get("tool"), g.get("system"))
        for g in (meta.get("additional") or {}).get("coverage_gaps", []) or []
        if isinstance(g, dict)
    }
    for surface in contracts.enum_values("review-surface"):
        entry = record.get(surface)
        if not isinstance(entry, dict):
            continue
        status = entry.get("status")
        where = f"review_surface_coverage.{surface}"
        if status == "finding":
            for fid in entry.get("finding_ids") or []:
                if fid not in finding_ids:
                    result.error(f"{where}: finding_ids names {fid!r}, which is not in findings")
        elif status == "negative":
            if not any(a == surface or a.startswith(surface + " ") for a in areas):
                result.error(
                    f"{where}: status negative but no negative_results entry has "
                    f"area {surface!r} — record what was examined"
                )
        elif status == "not_assessed" and ("review-surfaces", surface) not in gaps:
            result.error(
                f"{where}: status not_assessed but metadata.additional.coverage_gaps "
                f"has no {{tool: review-surfaces, system: {surface}}} entry"
            )


def _cross_validate_scan_review_surfaces(
    record: Any,
    result: ReportValidation,
    *,
    kind: str,
    harness_version: Any,
    date: Any,
    ids: set[Any],
    diff_scoped: bool | None = None,
) -> None:
    """review_surface_coverage on a vuln-findings or verification report: each finding_id names
    one of `ids`; out_of_scope only on a diff-scoped scan (`diff_scoped` None: always is)."""
    gate_meta = {"date": date or "", "additional": {"harness_version": harness_version}}
    if record is None:
        if _gate(gate_meta, current=REVIEW_SURFACE_EXTENDED_MIN_VERSION):
            result.error(
                f"review_surface_coverage is required for {kind} reports from traust "
                f"{'.'.join(map(str, REVIEW_SURFACE_EXTENDED_MIN_VERSION))} — record "
                "finding / negative / not_applicable / not_assessed / out_of_scope "
                "for each review surface"
            )
        return
    if not isinstance(record, dict):
        return
    for surface in contracts.enum_values("review-surface"):
        entry = record.get(surface)
        if not isinstance(entry, dict):
            continue
        if entry.get("status") == "out_of_scope" and diff_scoped is False:
            result.error(
                f"review_surface_coverage.{surface}: out_of_scope on a full scan — "
                "out_of_scope is only for a diff-scoped scan "
                "(metadata.additional.coverage_diff); record what the full scan found"
            )
        if entry.get("status") != "finding":
            continue
        for fid in entry.get("finding_ids") or []:
            if fid not in ids:
                result.error(
                    f"review_surface_coverage.{surface}: finding_ids names {fid!r}, "
                    f"which is not a finding of this {kind} report"
                )


def _cross_validate_dispositions(report: Report, result: ReportValidation) -> None:
    """Disposition blocks of a cumulative report; none on an audit-stage report."""
    findings = report.get("findings", [])
    ds = report.get("disposition_summary")
    with_disposition = [f for f in findings if "disposition" in f]

    if ds is None and not with_disposition:
        return
    if ds is not None and len(with_disposition) != len(findings):
        result.error(
            "disposition_summary present but "
            f"{len(findings) - len(with_disposition)} finding(s) have no "
            "disposition block — cumulative reports must disposition every finding"
        )
    if ds is None:
        result.warn("findings carry disposition blocks but disposition_summary is absent")

    for i, f in enumerate(findings):
        disp = f.get("disposition")
        if disp and disp.get("validity") != f.get("validation_status"):
            result.error(
                f"findings[{i}] ({f.get('id', '?')}): validation_status "
                f"'{f.get('validation_status')}' does not equal "
                f"disposition.validity '{disp.get('validity')}'"
            )

    if ds is None:
        return

    res_counts = Counter(f["disposition"].get("resolution") for f in with_disposition)
    for key, declared in (ds.get("by_resolution") or {}).items():
        if res_counts.get(key, 0) != declared:
            result.error(
                f"disposition_summary.by_resolution[{key}]: declared {declared}, "
                f"but {res_counts.get(key, 0)} finding(s) have that resolution"
            )
    val_counts = Counter(f["disposition"].get("validity") for f in with_disposition)
    for key, declared in (ds.get("by_validity") or {}).items():
        if val_counts.get(key, 0) != declared:
            result.error(
                f"disposition_summary.by_validity[{key}]: declared {declared}, "
                f"but {val_counts.get(key, 0)} finding(s) have that validity"
            )

    flagged = {f["id"] for f in with_disposition if f["disposition"].get("conflict")}
    listed = set(ds.get("conflicts") or [])
    for fid in sorted(flagged - listed):
        result.error(
            f"finding {fid} has disposition.conflict but is not in disposition_summary.conflicts"
        )
    for fid in sorted(listed - flagged):
        result.error(
            f"disposition_summary.conflicts lists {fid} but that "
            f"finding's disposition.conflict is not true"
        )


def cross_validate_cloud_config_current(report: Report, result: ReportValidation) -> None:
    """A cloud-config cumulative: errors only for what build_cumulative guarantees; summary
    counts copied from the audit drifted across vintages, so they warn."""
    findings = report.get("findings", [])

    for fid, cnt in Counter(f.get("id") for f in findings).items():
        if cnt > 1:
            result.error(f"Duplicate finding ID: {fid}")

    for i, f in enumerate(findings):
        ov = (f.get("disposition") or {}).get("severity_override")
        expected = ov["severity"] if ov else f.get("severity")
        if f.get("effective_severity") != expected:
            result.error(
                f"findings[{i}] ({f.get('id', '?')}): effective_severity "
                f"'{f.get('effective_severity')}' does not equal the "
                f"{'severity_override' if ov else 'original severity'} "
                f"'{expected}'"
            )

    summary = report.get("summary") or {}
    status_counts = Counter(f.get("status") for f in findings)
    for key in ("confirmed", "suppressed", "needs_review"):
        declared = summary.get(key)
        actual = status_counts.get(key, 0)
        if declared is not None and declared != actual:
            result.warn(
                f"summary.{key}: declared {declared}, but {actual} finding(s) have status '{key}'"
            )
    if "gaps" in summary and summary.get("gaps") != len(report.get("gaps", [])):
        result.warn(
            f"summary.gaps: declared {summary.get('gaps')}, but gaps[] has "
            f"{len(report.get('gaps', []))} entries"
        )

    _cross_validate_dispositions(report, result)


def cross_validate_remediation(
    report: Report, result: ReportValidation, files: ReportFiles
) -> None:
    findings = report.get("source_findings", [])
    patch = report.get("patch", {})
    checks = report.get("checks", [])
    summary = report.get("summary", {})

    declared = summary.get("findings_addressed")
    if declared is not None and declared != len(findings):
        result.error(
            f"summary.findings_addressed: declared {declared}, "
            f"but source_findings has {len(findings)} entries"
        )

    passed = sum(1 for c in checks if c.get("outcome") == "pass")
    if summary.get("checks_passed") != passed:
        result.error(
            f"summary.checks_passed: declared {summary.get('checks_passed')}, "
            f"but {passed} check(s) have outcome 'pass'"
        )
    if summary.get("checks_total") != len(checks):
        result.error(
            f"summary.checks_total: declared {summary.get('checks_total')}, "
            f"but checks[] has {len(checks)} entries"
        )

    fc = patch.get("files_changed", [])
    ds = patch.get("diffstat", {})
    if ds.get("files") != len(fc):
        result.error(
            f"patch.diffstat.files: declared {ds.get('files')}, "
            f"but files_changed has {len(fc)} entries"
        )

    changed_paths = {f["path"] for f in fc}
    for sf in findings:
        for loc in sf.get("locations", []):
            if loc.get("path") not in changed_paths:
                result.warn(
                    f"source_findings[{sf['finding_ref']}] location "
                    f"'{loc.get('path')}' is not in patch.files_changed — "
                    f"verify the fix actually addresses this site"
                )

    # skip means the tool was unavailable, so only an actual fail contradicts checks_passed
    failed = sum(1 for c in checks if c.get("outcome") == "fail")
    status = summary.get("status")
    if status == "checks_passed" and failed > 0:
        result.error("summary.status is 'checks_passed' but not all checks passed")
    if status == "checks_failed" and failed == 0:
        result.error("summary.status is 'checks_failed' but all checks passed")
    rev = report.get("revalidation", {})
    if status == "revalidated_fixed" and not rev.get("fixed"):
        result.error("summary.status is 'revalidated_fixed' but revalidation.fixed is not true")
    if status in ("pr_opened", "merged") and "pull_request" not in report:
        result.error(f"summary.status is '{status}' but no pull_request block present")

    fork = report.get("fork", {})
    meta = report.get("metadata", {})
    upstream = fork.get("upstream_remote")
    if (
        upstream
        and meta.get("repository")
        and upstream.rstrip("/").removesuffix(".git")
        != meta["repository"].rstrip("/").removesuffix(".git")
    ):
        result.warn(
            f"fork.upstream_remote ({upstream}) does not match "
            f"metadata.repository ({meta['repository']})"
        )

    pr = report.get("pull_request", {})
    if pr.get("target") == "upstream":
        result.warn(
            "pull_request.target is 'upstream' — automated remediation should open "
            "PRs against private-fork or downstream only; upstream disclosure is a "
            "separate human-driven step"
        )

    dp = patch.get("diff_path")
    if dp:
        rp = PurePath(result.file_path).parent / dp
        if not files.exists(rp):
            result.warn(f"patch.diff_path '{dp}' not found at {rp}")


def cross_validate_validation(report: Report, result: ReportValidation, files: ReportFiles) -> None:
    actual = Counter(f["verdict"] for f in report.get("validated_findings", []))
    declared = report.get("summary", {}).get("by_verdict", {})
    for v, n in declared.items():
        if actual.get(v, 0) != n:
            result.error(
                f"summary.by_verdict[{v}]: declared {n}, "
                f"but {actual.get(v, 0)} validated_findings have verdict '{v}'"
            )
    known = {f["source_id"] for f in report.get("validated_findings", [])}
    for c in report.get("attack_chains", []):
        for s in c.get("steps", []):
            ref = s.get("finding_ref")
            if ref and ref not in known:
                result.warn(
                    f"attack_chains[{c['chain_id']}] step references unknown finding '{ref}'"
                )
    for nf in report.get("novel_findings", []):
        if nf["id"] in known:
            result.error(f"novel_findings[{nf['id']}] collides with source finding ID")
    log_ref = report.get("execution_log_ref")
    if log_ref:
        rp = PurePath(result.file_path).parent / log_ref
        if not files.exists(rp):
            result.warn(f"execution_log_ref '{log_ref}' not found at {rp}")


def cross_validate_triage(report: Report, result: ReportValidation) -> None:
    """The verdict taxonomy: hardening and undetermined are never false positives, a false
    positive carries evidence of wrongness, and the summary counts reconcile."""
    findings = report.get("findings", [])
    summary = report.get("summary", {})

    ids = [f.get("id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate triage finding ID: {fid}")
    id_set = set(ids)

    verdicts = Counter(f.get("verdict") for f in findings)
    declared = {
        "input_count": len(findings),
        "true_positives": verdicts.get("true_positive", 0),
        "hardening": verdicts.get("hardening", 0),
        "false_positives": verdicts.get("false_positive", 0),
        "undetermined": verdicts.get("undetermined", 0),
        "duplicates": verdicts.get("duplicate", 0),
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but findings show {actual}")

    sev_actual = Counter(
        str(f.get("severity", "")).lower()
        for f in findings
        if f.get("verdict") == "true_positive" and f.get("severity")
    )
    for level, n in (summary.get("by_severity") or {}).items():
        if sev_actual.get(level, 0) != n:
            result.error(
                f"summary.by_severity[{level}]: declared {n}, but "
                f"{sev_actual.get(level, 0)} true positives have that severity"
            )

    for i, f in enumerate(findings):
        fid = f.get("id", f"findings[{i}]")
        verdict = f.get("verdict")
        rule = f.get("exclusion_rule")
        rule_s = str(rule) if rule is not None else None

        if verdict == "hardening" and rule_s != "13":
            result.error(
                f"{fid}: verdict 'hardening' requires exclusion_rule 13 "
                f"(got {rule_s!r}) — hardening is defined by rule 13"
            )
        if verdict == "false_positive" and rule_s == "13":
            result.error(
                f"{fid}: verdict 'false_positive' with exclusion_rule 13 — "
                "rule-13 (missing-hardening-only) findings must be verdict "
                "'hardening', never false positives"
            )

        if verdict == "false_positive" and not f.get("refute_reasons"):
            result.error(
                f"{fid}: verdict 'false_positive' with empty refute_reasons — "
                "refutation requires evidence"
            )

        if verdict == "undetermined":
            conf = f.get("confidence")
            if conf not in (None, 0, 0.0) and f.get("verify_verdict") != "needs_manual_test":
                result.error(
                    f"{fid}: verdict 'undetermined' with confidence {conf} and "
                    "verify_verdict != needs_manual_test — undetermined findings "
                    "carry no confident conclusion"
                )

        if verdict != "true_positive" and f.get("severity") is not None:
            result.error(
                f"{fid}: severity {f['severity']!r} set on verdict "
                f"'{verdict}' — derived severity applies to true positives only"
            )

        if verdict == "duplicate":
            target = f.get("duplicate_of")
            if not target:
                result.error(f"{fid}: verdict 'duplicate' without duplicate_of")
            elif target not in id_set:
                result.error(f"{fid}: duplicate_of '{target}' is not a known finding id")
            else:
                canon = next(x for x in findings if x.get("id") == target)
                if canon.get("verdict") == "duplicate":
                    result.error(f"{fid}: duplicate_of '{target}' is itself a duplicate")

        # a warning: noise-tolerance policies may legitimately override a split vote
        vb = f.get("vote_breakdown")
        if isinstance(vb, dict) and verdict in ("true_positive", "hardening", "false_positive"):
            countable = {k: vb.get(k, 0) for k in ("true_positive", "hardening", "false_positive")}
            total = sum(countable.values())
            if total:
                top_verdict, top_votes = max(countable.items(), key=lambda kv: kv[1])
                if top_votes * 2 > total and top_verdict != verdict:
                    result.warn(
                        f"{fid}: verdict '{verdict}' contradicts strict vote "
                        f"majority '{top_verdict}' ({countable}) — confirm a "
                        "noise-tolerance policy justified the override"
                    )

    # mostly canonical orig_ids: the stragglers are probably transcription errors
    orig_ids = [f.get("orig_id") for f in findings if f.get("orig_id")]
    canonical = [o for o in orig_ids if CANONICAL_FINDING_ID.match(str(o))]
    if orig_ids and len(canonical) >= len(orig_ids) / 2:
        for o in orig_ids:
            if not CANONICAL_FINDING_ID.match(str(o)):
                result.warn(
                    f"orig_id '{o}' is not canonical while most of the batch is "
                    "— check for a transcription error"
                )


def cross_validate_impact_analysis(report: Report, result: ReportValidation) -> None:
    repos = report.get("repos", [])
    summary = report.get("summary", {})

    class_counts = Counter(r.get("classification") for r in repos)
    declared = {
        key: class_counts.get(key, 0)
        for key in (
            "affected",
            "likely_affected",
            "not_observed",
            "version_not_in_range",
            "not_imported",
            "inconclusive",
        )
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but repos show {actual}")

    if summary.get("repos_in_blast_radius") != len(repos):
        result.error(
            f"summary.repos_in_blast_radius: declared "
            f"{summary.get('repos_in_blast_radius')}, but repos[] has "
            f"{len(repos)} entries"
        )

    in_range = sum(
        1
        for r in repos
        if r.get("classification") != "version_not_in_range"
        and r.get("classification") != "not_imported"
    )
    if summary.get("version_in_range") != in_range:
        result.warn(
            f"summary.version_in_range: declared "
            f"{summary.get('version_in_range')}, expected {in_range} "
            f"(repos - version_not_in_range - not_imported)"
        )

    for rid, cnt in Counter(r.get("repo") for r in repos).items():
        if cnt > 1:
            result.error(f"Duplicate repo entry: {rid}")

    for i, r in enumerate(repos):
        rid = r.get("repo", f"repos[{i}]")
        cls = r.get("classification")
        ev = r.get("evidence", {})
        if cls == "affected" and not (
            ev.get("govulncheck") == "symbol_reachable"
            or (ev.get("feature_pattern_matches") or 0) > 0
        ):
            result.warn(
                f"{rid}: classification 'affected' without "
                "govulncheck symbol_reachable or feature_pattern_matches > 0"
            )
        if cls == "version_not_in_range" and ev.get("l1_version_in_range") is True:
            result.error(
                f"{rid}: classification 'version_not_in_range' but l1_version_in_range is true"
            )


def cross_validate_vuln_findings(report: Report, result: ReportValidation) -> None:
    """Unique ids derived from this scan's repo_slug/scanned_ref, reconciled summary counts and
    consistent baseline bookkeeping."""
    findings = report.get("findings", [])
    known = report.get("known_findings", []) or []
    summary = report.get("summary", {})
    meta = report.get("metadata", {})

    _cross_validate_scan_review_surfaces(
        report.get("review_surface_coverage"),
        result,
        kind="vuln-findings",
        harness_version=meta.get("harness_version"),
        date=report.get("scanned_at"),
        ids={f.get("id") for f in findings if isinstance(f, dict)},
        diff_scoped=isinstance((meta.get("additional") or {}).get("coverage_diff"), dict),
    )

    ids = [f.get("id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate finding ID: {fid}")

    slug = meta.get("repo_slug")
    ref = str(meta.get("scanned_ref", ""))[:7]
    if slug and ref:
        prefix = f"{slug}-{ref}-"
        for fid in ids:
            if fid and not str(fid).startswith(prefix):
                result.error(
                    f"{fid}: id does not start with '{prefix}' — finding IDs "
                    "must derive from metadata.repo_slug + scanned_ref"
                )

    sev_actual = Counter(str(f.get("severity", "")).lower() for f in findings)
    declared = {
        "total": len(findings),
        **{
            level: sev_actual.get(level, 0)
            for level in ("critical", "high", "medium", "low", "informational")
        },
        "known": len(known),
        "low_confidence": sum(
            1
            for f in findings
            if isinstance(f.get("confidence"), (int, float)) and f["confidence"] < 0.4
        ),
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but findings show {actual}")

    core_baseline = (meta.get("additional") or {}).get("baseline_assessment_id")
    if meta.get("baseline") is None and core_baseline is None:
        if known:
            result.error(
                f"{len(known)} known_findings recorded but metadata.baseline "
                "is null — known findings must match a baseline audit"
            )
        if meta.get("baseline_findings"):
            result.error("metadata.baseline_findings > 0 but metadata.baseline is null")


def cross_validate_verification(report: Report, result: ReportValidation) -> None:
    """The verify-remediation consistency checklist: verdict counts, coverage, commit
    attribution, timeline order and regression id hygiene."""
    findings = report.get("verified_findings", [])
    regressions = report.get("regressions", [])
    timeline = report.get("commit_timeline", [])
    summary = report.get("summary", {})
    meta = report.get("metadata", {})

    # its own findings are its regressions; a re-checked original is named by original_id
    _cross_validate_scan_review_surfaces(
        report.get("review_surface_coverage"),
        result,
        kind="verification",
        harness_version=meta.get("harness_version"),
        date=meta.get("date"),
        ids={r.get("id") for r in regressions if isinstance(r, dict)}
        | {f.get("original_id") for f in findings if isinstance(f, dict)},
    )

    ids = [f.get("original_id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate verified_findings original_id: {fid}")
    known_ids = set(ids)

    # an upstream fix the repo has not consumed cannot resolve the finding
    for f in findings:
        cr = f.get("cross_repo")
        if not cr:
            continue
        if cr.get("propagation") == "pending" and f.get("verdict") == "resolved":
            result.error(
                f"{f.get('original_id')}: verdict 'resolved' with "
                f"cross_repo.propagation 'pending' — the fix in "
                f"{cr.get('fix_repo')} is not consumed by this repo; use "
                f"'partially_resolved' (ledger maps it to fix_in_progress)"
            )
        if (
            cr.get("fix_repo")
            and meta.get("repository")
            and cr["fix_repo"].rstrip("/").lower() == str(meta["repository"]).rstrip("/").lower()
        ):
            result.error(
                f"{f.get('original_id')}: cross_repo.fix_repo equals "
                f"metadata.repository — cross_repo is for fixes in a "
                f"DIFFERENT repo; drop the block for same-repo fixes"
            )

    declared_total = summary.get("total_findings")
    if declared_total is not None and declared_total != len(findings):
        result.error(
            f"summary.total_findings: declared {declared_total}, "
            f"but verified_findings has {len(findings)} entries"
        )

    actual = Counter(f.get("verdict") for f in findings)
    for v, n in (summary.get("by_verdict") or {}).items():
        if actual.get(v, 0) != n:
            result.error(
                f"summary.by_verdict[{v}]: declared {n}, "
                f"but {actual.get(v, 0)} verified_findings have verdict '{v}'"
            )

    declared_reg = summary.get("regressions")
    if declared_reg is not None and declared_reg != len(regressions):
        result.error(
            f"summary.regressions: declared {declared_reg}, "
            f"but regressions[] has {len(regressions)} entries"
        )

    for i, f in enumerate(findings):
        fid = f.get("original_id", "?")
        verdict = f.get("verdict")
        commits = f.get("remediation_commits") or []
        unattributed = f.get("unattributed")
        if commits and unattributed:
            result.error(
                f"verified_findings[{i}] ({fid}): unattributed is true but "
                f"remediation_commits is non-empty"
            )
        if (
            not commits
            and not unattributed
            and verdict in ("resolved", "partially_resolved", "new_approach", "regression")
        ):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict '{verdict}' requires "
                f"remediation_commits, or unattributed: true with an explanation"
            )
        if verdict in ("false_positive", "risk_accepted") and not f.get("disposition_rationale"):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict '{verdict}' requires "
                f"disposition_rationale (who made the determination and why)"
            )
        if verdict == "partially_resolved" and not f.get("residual_risk"):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict 'partially_resolved' "
                f"requires residual_risk"
            )
        if verdict == "new_approach" and not f.get("residual_risk"):
            result.warn(
                f"verified_findings[{i}] ({fid}): verdict 'new_approach' should "
                f"describe residual_risk (or state there is none)"
            )
        for c in commits:
            if not str(c.get("sha", "")).startswith(str(c.get("short_sha", ""))):
                result.error(
                    f"verified_findings[{i}] ({fid}): remediation commit "
                    f"short_sha '{c.get('short_sha')}' is not a prefix of "
                    f"sha '{c.get('sha')}'"
                )

    prev_dt = None
    for i, t in enumerate(timeline):
        if not str(t.get("full_sha", "")).startswith(str(t.get("sha", ""))):
            result.error(
                f"commit_timeline[{i}]: sha '{t.get('sha')}' is not a prefix "
                f"of full_sha '{t.get('full_sha')}'"
            )
        for fid in t.get("addresses") or []:
            if fid not in known_ids:
                result.error(f"commit_timeline[{i}] references unknown finding ID: {fid}")
        try:
            dt = datetime.fromisoformat(str(t.get("date", "")))
        except ValueError:
            dt = None  # the schema rejects a malformed date
        if dt is not None and prev_dt is not None and dt < prev_dt:
            result.error(
                f"commit_timeline[{i}] ({t.get('sha')}): entries are not in chronological order"
            )
        if dt is not None:
            prev_dt = dt

    # a warning: the timeline aggregates the per-finding attributions
    attributed_shas = {c.get("sha") for f in findings for c in (f.get("remediation_commits") or [])}
    timeline_shas = {t.get("full_sha") for t in timeline}
    for sha in sorted(attributed_shas - timeline_shas):
        result.warn(f"remediation commit {sha} is not in commit_timeline")
    for sha in sorted(timeline_shas - attributed_shas):
        result.warn(
            f"commit_timeline entry {sha} does not appear in any finding's remediation_commits"
        )

    patched = str(meta.get("patched_commit", ""))[:7]
    for i, r in enumerate(regressions):
        rid = r.get("id", "")
        if patched and f"-{patched}-REG-" not in rid:
            result.warn(
                f"regressions[{i}] ({rid}): SHORTSHA segment does not match "
                f"metadata.patched_commit ({patched})"
            )

    # a routed campaign finding is minted at the patched sha; routing is one-to-one
    routed_seen = Counter(r.get("routed_id") for r in regressions if r.get("routed_id"))
    for rid, cnt in routed_seen.items():
        if cnt > 1:
            result.error(
                f"regressions: routed_id {rid} assigned to "
                f"{cnt} regressions — routing must be one-to-one"
            )
    for i, r in enumerate(regressions):
        routed = r.get("routed_id")
        if routed and patched and f"-{patched}-" not in routed:
            result.warn(
                f"regressions[{i}] ({r.get('id')}): routed_id {routed} "
                f"SHORTSHA segment does not match metadata.patched_commit "
                f"({patched})"
            )

    if meta.get("original_commit") and meta.get("original_commit") == meta.get("patched_commit"):
        result.warn(
            "metadata.original_commit equals patched_commit — the 'patched' "
            "code is identical to what was audited"
        )


def _repository_parses(url: str) -> bool:
    url = url.strip().strip("<>")
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return False
    parts = [p for p in parsed.path.split("/") if p]
    return (
        len(parts) >= 2
        and _REPO_HOST_RE.match((parsed.hostname or "").lower()) is not None
        and all(_REPO_SEGMENT_RE.match(p) and any(c.isalnum() for c in p) for p in parts)
    )


def _band_of(score: float) -> str:
    for name, floor in _BANDS:
        if score >= floor:
            return name
    return "informational"


def strict_checks(report: Report, result: ReportValidation, context: CheckContext) -> None:
    # Evidence may quote target code, but an unredacted live secret in a report is an incident.
    for hit in context.redaction.scan(json.dumps(report, ensure_ascii=False)):
        msg = (
            f"Strict: unredacted secret-shaped value in report "
            f"(class={hit.category}, prefix={hit.match_prefix!r})"
            " — redact at write time (traust_engine._util.redact)"
        )
        if hit.high_confidence:
            result.error(msg)
        else:
            result.warn(msg)
    if "dependency_audit" not in report:
        result.warn("Strict: missing recommended section 'dependency_audit'")
    repo_url = (report.get("metadata", {}).get("repository") or "").strip()
    if not repo_url:
        result.warn(
            "Strict: metadata.repository missing — org-index and repo-graph "
            "cannot attribute this report to a repository"
        )
    elif not _repository_parses(repo_url):
        result.warn(
            f"Strict: metadata.repository {repo_url!r} does not parse as "
            "https://<host>/<org>/<repo> — build_org_index.py skips such "
            "reports; use the concrete repository URL (org-only URLs are "
            "valid only for org-URL stub reports)"
        )
    meta = report.get("metadata", {})
    if (
        meta.get("audit_profile") == "code"
        and _gate(meta, legacy=DETERMINISTIC_STEPS_MIN_VERSION)
        and "deterministic_steps" not in (meta.get("additional") or {})
    ):
        result.warn(
            "Strict: code profile missing "
            "metadata.additional.deterministic_steps — record ran/skipped "
            "for k8s-hardening, opengrep, sbom-grype so a skipped scanner "
            "is not read as a quiet one (docs/report-structure.md)"
        )
    findings = report.get("findings", [])
    for i, f in enumerate(findings):
        for text_field in ("description", "remediation"):
            if CIS_CONTROL_TEXT_RE.search(f.get(text_field) or ""):
                result.warn(
                    f"Strict: findings[{i}] ({f.get('id', '?')}) {text_field} "
                    "matches CIS/STIG recommendation-title phrasing — cite "
                    "bare section IDs with original prose; do not copy "
                    "benchmark text (docs/external-dependencies.md)"
                )
    if "negative_results" not in report:
        result.warn("Strict: missing recommended section 'negative_results'")
    if "footer" not in report:
        result.warn("Strict: missing 'footer'")
    if "positive_observations" not in report.get("executive_summary", {}):
        result.warn("Strict: missing 'executive_summary.positive_observations'")
    # A container profile measures an image, not source: no LoC by design.
    if meta.get("audit_profile") == "container":
        if "sbom_packages" not in (meta.get("additional") or {}):
            result.warn("Strict: container profile missing 'metadata.additional.sbom_packages'")
    elif "loc_reviewed" not in meta and "loc_breakdown" not in meta:
        result.warn("Strict: metadata missing 'loc_reviewed' / 'loc_breakdown'")
    elif _gate(meta, legacy=CONSISTENCY_MIN_VERSION) and "loc_breakdown" not in meta:
        result.warn(
            "Strict: metadata missing 'loc_breakdown' — per-language LoC "
            "counts feed the campaign dashboards"
        )
    if "peach_isolation_review" not in report:
        result.warn(
            "Strict: missing 'peach_isolation_review' (record applicable:false "
            "with rationale if the component is single-tenant)"
        )
    else:
        pr = report["peach_isolation_review"]
        rationale = str(pr.get("rationale") or "")
        if pr.get("applicable") is False and len(rationale) < 40:
            result.warn(
                "Strict: peach_isolation_review.applicable is false with a "
                f"{len(rationale)}-char rationale — justify against the "
                "multi-tenant triggers in the secure-code-audit skill"
            )
    # Validation runs right after the audit, so a date more than a day off is almost always a
    # commit or CVE date pasted into the wrong field.
    date_s = str(meta.get("date", ""))
    if date_s:
        try:
            report_date = date.fromisoformat(date_s)
        except ValueError:
            report_date = None  # the schema rejects a malformed date
        if report_date is not None and abs(report_date - context.today) > timedelta(days=1):
            result.warn(
                f"Strict: metadata.date '{date_s}' was not generated "
                "within the last day — this must be the audit execution "
                "date, not a commit/CVE date"
            )
    for i, f in enumerate(findings):
        sev = str(f.get("severity", "")).lower()
        if "cvss" not in f and sev != "informational":
            result.warn(f"Strict: findings[{i}] ({f.get('id', '?')}): missing CVSS scoring")
        score = (f.get("cvss") or {}).get("score")
        if score is not None:
            if sev == "informational":
                msg = (
                    f"findings[{i}] ({f.get('id', '?')}): 'informational' "
                    f"finding carries CVSS {score} — informational findings "
                    "are never scored; set the severity the score implies "
                    f"('{_band_of(float(score))}') or drop the cvss block"
                )
                # >= 7 is the proven data-corruption class; lower legacy scores only warn
                if float(score) >= 7.0:
                    result.error(msg)
                elif float(score) > 0.0:
                    result.warn("Strict: " + msg)
            elif sev in _BAND_ORDER:
                gap = _BAND_ORDER.index(_band_of(float(score))) - _BAND_ORDER.index(sev)
                if gap >= 2 and not _DOWNGRADE_RATIONALE.search(f.get("description", "")):
                    result.warn(
                        f"Strict: findings[{i}] ({f.get('id', '?')}): severity "
                        f"'{sev}' is {gap} bands below the CVSS {score} band "
                        f"('{_band_of(float(score))}') with no stated rationale — "
                        "when an upstream advisory score is contextually "
                        "downgraded, the description must say so and why"
                    )
        if sev in ("critical", "high") and not f.get("attack_pattern"):
            result.warn(
                f"Strict: findings[{i}] ({f.get('id', '?')}): {sev} finding "
                "missing 'attack_pattern' (concrete attack scenario)"
            )
    # Static analysis can't confirm: confirmation needs execution evidence or a human triage.
    statuses = [f.get("validation_status") for f in findings]
    if len(findings) >= 5 and statuses and all(s == "confirmed" for s in statuses):
        result.warn(
            "Strict: every finding is validation_status 'confirmed' — "
            "audit-stage findings default to 'not_verified'; reserve "
            "'confirmed' for findings verified by execution (fuzz crash, "
            "PoC, failing test), a validations-pipeline report, or a "
            "human reviewer's triage"
        )
    if _gate(meta, legacy=CONSISTENCY_MIN_VERSION):
        off_vocab = sorted(
            {
                f["category"]
                for f in findings
                if f.get("category")
                and _normalize_category(f["category"]) not in RECOMMENDED_CATEGORIES
            }
        )
        if off_vocab:
            result.warn(
                "Strict: finding categories outside the recommended "
                f"vocabulary: {off_vocab} — use one of "
                f"{sorted(RECOMMENDED_CATEGORIES)}"
            )


def cross_validate_threat_model(report: Report, result: ReportValidation) -> None:
    """Each OWASP risk_rating's derived values must follow from its factors."""
    for i, threat in enumerate(report.get("threats") or []):
        rating = threat.get("risk_rating")
        if rating:
            for problem in contracts.risk_rating.problems(rating):
                result.error(f"threats[{i}] ({threat.get('id', '?')}) risk_rating: {problem}")


def _report_shaped(report: Any) -> bool:
    if not isinstance(report, dict):
        return False
    if not isinstance(report.get("metadata", {}), dict):
        return False
    findings = report.get("findings", [])
    return isinstance(findings, list) and all(isinstance(f, dict) for f in findings)


def validate_report(
    file_path: str, text: str, schema: str, context: CheckContext, *, strict: bool = False
) -> ReportValidation:
    """A report file's text against the named contract schema, then its family's content
    checks; `strict` adds the audit-report warnings."""
    result = ReportValidation(file_path=file_path)
    try:
        report = json.loads(text)
    except json.JSONDecodeError as e:
        result.error(f"Invalid JSON: {e}")
        return result

    for path, message in contracts.schema_errors(schema, report):
        result.error(f"{format_path(path)}: {message}")

    sid = contracts.schema(schema).get("$id", "")
    if result.passed:
        if "verification" in sid:
            cross_validate_verification(report, result)
        elif "remediation" in sid:
            cross_validate_remediation(report, result, context.files)
        elif "triage" in sid:
            cross_validate_triage(report, result)
        elif "vuln-findings" in sid:
            cross_validate_vuln_findings(report, result)
        elif "impact-analysis" in sid:
            cross_validate_impact_analysis(report, result)
        elif "cloud-config-findings-current" in sid:
            cross_validate_cloud_config_current(report, result)
        elif "cloud-config-audit" in sid:
            pass  # run_checkov.py --validate-report is that family's content gate
        elif "validation" in sid:
            cross_validate_validation(report, result, context.files)
        elif "threat-model" in sid:
            cross_validate_threat_model(report, result)
        elif any(family in sid for family in _SCHEMA_ONLY):
            pass
        else:
            cross_validate(report, result)

    # these read findings and metadata directly; a malformed shape already has schema errors
    if not any(k in sid for k in _NON_AUDIT) and _report_shaped(report):
        check_metadata_repository(report, result)
        if strict:
            strict_checks(report, result, context)
    return result


def detect_schema(path: PurePath, text: str, files: ReportFiles) -> str:
    """The contract schema a report file's name says it holds; `report` when the name says
    nothing. A *-findings-current.json peeks at its content for the cloud-config variant."""
    name = path.name
    if name == "TRIAGE.json" or name.endswith("-triage.json"):
        return "triage"
    if name == "validation.json" or name.endswith("-validation.json"):
        return "validation"
    if name == "pqc-readiness.json" or name.endswith("-pqc-readiness.json"):
        return "pqc-readiness"
    if name.endswith("-findings-layer.json"):
        return "layer"
    if name.endswith("-vuln-findings.json"):
        # legacy VULN-FINDINGS.json predates the contract and is deliberately not detected
        return "vuln-findings"
    if name.endswith("-threat-model.json"):
        return "threat-model"
    if name.endswith("-impact-analysis.json"):
        return "impact-analysis"
    if name == "verification.json" or name.endswith("-verification.json"):
        return "verification"
    if name.endswith("-refuted-register.json"):
        return "refuted-register"
    if name.endswith("-priv-profile.json"):
        return "operator-priv-profile"
    if name.endswith("-cloud-config-audit.json"):
        return "cloud-config-audit"
    if name.endswith("-findings-current.json") and _is_cloud_config_current(text, files, path):
        return "cloud-config-findings-current"
    return "report"


def _is_cloud_config_current(text: str, files: ReportFiles, path: PurePath) -> bool:
    """build_cumulative stamps the baseline audit's filename as cumulative.source_audit; without
    it, a sibling <base>-cloud-config-audit.json says so."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if isinstance(doc, dict):
        meta = doc.get("metadata")
        additional = meta.get("additional") if isinstance(meta, dict) else None
        cumulative = additional.get("cumulative") if isinstance(additional, dict) else None
        source_audit = cumulative.get("source_audit") if isinstance(cumulative, dict) else None
        if source_audit:
            return str(source_audit).endswith("-cloud-config-audit.json")
    base = path.name[: -len("-findings-current.json")]
    return files.is_file(path.parent / f"{base}-cloud-config-audit.json")
