"""The readiness report's rules past its schema (`pqc_facts --validate-readiness`), its
projection into pqc-blockers (`build_pqc_blockers`), the Layer-2 route (`l2_prepass`) and the
templated zero-hit report (`bulk_prescan`)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    PqcBlockersArtifact,
    PqcFactsArtifact,
    PqcReadinessArtifact,
)
from traust_core.v1.models.pqc import (
    PqcBlocker,
    PqcFact,
    PqcReadiness,
    PqcRemediation,
    PqcRoute,
    PqcStamps,
)
from traust_core.v1.models.vocabulary import (
    PqcClassification,
    PqcPathClass,
    PqcReadinessBucket,
    PqcRemediationCategory,
    Severity,
)
from traust_core.v1.services.lint import LintAction, LintContext, LintRuleId, Violation

C = PqcRemediationCategory

_REQUIRED = (
    "summary", "status", "who_sets_tls", "quantum_ready", "why_not", "do_next", "capabilities",
    "readiness_bucket",
)  # fmt: skip
_CHOICES = {
    "status": ("ready", "needs_work", "blocked", "not_applicable"),
    "quantum_ready": (
        "yes_by_default", "yes_if_configured", "no", "only_with_fips_curves", "unknown",
    ),
    "who_sets_tls": (
        "this_app", "language_defaults", "platform", "mesh_or_ingress", "external_server",
        "unknown",
    ),
}  # fmt: skip
_DOMAINS = ("VULN", "AGIL", "PQCA", "HNDL")
_HARNESS_PATH = re.compile(
    r"(?:^|[\s`])(?:harnessing/|remediation/|notes/(?:capabilities|reference|schemas)/)"
)
_FACT_ID = re.compile(r"\bF\d{4}\b")
_GOVERNANCE = ("HP_GOV_", "HP_DB_")
# The templated zero-hit report needs a full pack: a rules-loading failure must not pass.
ZERO_HIT_MIN_RULES = 120

_SEVERITY = {
    C.FIX_NOW: Severity.HIGH,
    C.UPGRADE: Severity.LOW,
    C.WAITING_ON_UPSTREAM: Severity.INFORMATIONAL,
}
_DEADLINE_SEVERITY = {2030: Severity.MEDIUM, 2035: Severity.LOW}
_CLASSIFICATION = {
    C.FIX_NOW: PqcClassification.PQC_BLOCKER_CONFIG,
    C.UPGRADE: PqcClassification.PQC_ADOPTION,
    C.WAITING_ON_UPSTREAM: PqcClassification.PQC_BLOCKER_CONFIG,
}
_DEADLINE_CLASSIFICATION = {2030: PqcClassification.CLOCK_2030_PARAMETER}
_SEVERITY_CRITERIA = (
    (
        "critical",
        "Not used by this projection — PQC transition items are schedule risks, not live "
        "exploits.",
    ),
    (
        "high",
        "fix-now: quantum-vulnerable crypto the repo owner can remove today (pin, kill-switch, "
        "or hardcoded algorithm blocking PQC negotiation).",
    ),
    ("medium", "NIST IR 8547 deprecated-after-2030 clock item in first-party code or config."),
    (
        "low",
        "Disallowed-after-2035 clock item, or an upgrade that unlocks PQC when the toolchain "
        "allows.",
    ),
    ("informational", "Waiting on an upstream provider/vendor; no repo-local action yet."),
)  # fmt: skip
_ROADMAP_PRIORITY = {
    "fix-now": "immediate",
    "deadline": "scheduled (NIST IR 8547 clock)",
    "upgrade": "next toolchain bump",
    "waiting-on-upstream": "track upstream",
}


def _body(doc: ArtifactDocument) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(doc.payload)
    return body


class ReadinessRules:
    """The readiness report's gate past its schema; `record` refuses a report that fails."""

    id = LintRuleId("pqc.readiness")

    def check(self, subject: ArtifactDocument, context: LintContext) -> list[Violation]:
        if not isinstance(subject, PqcReadinessArtifact):
            raise ValidationError(f"{self.id} checks pqc-readiness, not {type(subject).__name__}")
        return [
            Violation(rule=self.id, item=item, message=message, action=LintAction.REVIEW)
            for item, message in _defects(_body(subject))
        ]


def _defects(doc: Mapping[str, Any]) -> Iterator[tuple[str, str]]:
    yield from ((k, "missing top-level key") for k in _REQUIRED if k not in doc)
    yield from (
        (k, f"bad {k} {doc.get(k)!r}")
        for k, allowed in _CHOICES.items()
        if doc.get(k) not in allowed
    )
    for domain in _DOMAINS:
        for i, check in enumerate(doc["scores"][domain]["checks"]):
            if check["result"] in ("partial", "no") and not check.get("fact_ids"):
                yield f"{domain}.checks[{i}]", f"{check['id']}: a non-yes result cites fact_ids"
    meta = doc["metadata"]
    if meta["assessment_basis"] == "source+runtime" and not (doc.get("runtime_evidence") or {}).get(
        "pqc_caps"
    ):
        yield "runtime_evidence", "assessment_basis source+runtime needs runtime_evidence.pqc_caps"
    seen: set[str] = set()
    for i, r in enumerate(doc.get("remediations") or ()):
        item = f"remediations[{i}]"
        if r["id"] in seen:
            yield item, f"duplicate id {r['id']!r}"
        seen.add(r["id"])
        if not r["action"].strip():
            yield item, "empty action"
        if r["category"] == "waiting-on-upstream" and not r.get("blocked_on"):
            yield item, "waiting-on-upstream needs blocked_on"
        if r["category"] == "deadline" and r.get("deadline") not in (2030, 2035):
            yield item, f"category deadline needs deadline 2030 or 2035, got {r.get('deadline')!r}"
        if r.get("fact_ids"):
            yield item, "fact_ids belong on scores/clock_items; owners use locations[]"
    for i, step in enumerate(doc.get("do_next") or ()):
        item = f"do_next[{i}]"
        if not isinstance(step, Mapping):
            yield item, "must be an object"
            continue
        if not str(step.get("do") or "").strip():
            yield item, "empty do"
        if _HARNESS_PATH.search(str(step.get("how") or "")):
            yield f"{item}.how", "cites a harness-local path; distill the playbook into prose"
        for name in ("do", "how"):
            if _FACT_ID.search(str(step.get(name) or "")):
                yield f"{item}.{name}", "contains a fact id; owners use locations[]"
        if step.get("fact_ids"):
            yield item, "fact_ids not allowed; use locations[]"
        if step.get("who") == "app" and not step.get("locations"):
            yield item, "who=app needs locations[] (repo file:line anchors for the owner)"


def remediations(doc: PqcReadinessArtifact) -> tuple[PqcRemediation, ...]:
    fields = PqcRemediation.model_fields
    return tuple(
        PqcRemediation.model_validate({k: v for k, v in r.items() if k in fields and v is not None})
        for r in _body(doc).get("remediations") or ()
    )


def readiness(
    doc: PqcReadinessArtifact, assessment_id: UUID, repository_ref_id: UUID, assessed_at: datetime
) -> PqcReadiness:
    body = _body(doc)
    flags = body["flags"]
    bucket = body.get("readiness_bucket")
    return PqcReadiness(
        assessment_id=assessment_id,
        repository_ref_id=repository_ref_id,
        assessed_at=assessed_at,
        bucket=None if bucket is None else PqcReadinessBucket(bucket),
        overall=body["scores"]["overall"],
        has_2030_clock_items=flags["has_2030_clock_items"],
        hndl_priority=flags["hndl_priority"],
        runtime_verification_required=flags["runtime_verification_required"],
        dominant=body["provenance_summary"]["dominant"],
        remediations=remediations(doc),
    )


def severity(r: PqcRemediation) -> Severity:
    if r.category == C.DEADLINE:
        return _DEADLINE_SEVERITY.get(r.deadline or 0, Severity.MEDIUM)
    return _SEVERITY[r.category]


def classification(r: PqcRemediation) -> PqcClassification:
    if r.category == C.DEADLINE:
        return _DEADLINE_CLASSIFICATION.get(r.deadline or 0, PqcClassification.PQC_BLOCKER_CONFIG)
    return _CLASSIFICATION[r.category]


def blockers(found: PqcReadiness) -> list[PqcBlocker]:
    return [
        PqcBlocker(
            repository_ref_id=found.repository_ref_id,
            assessment_id=found.assessment_id,
            remediation=r,
            severity=severity(r),
            classification=classification(r),
        )
        for r in found.remediations
    ]


def _title(action: str) -> str:
    head = re.split(r"\s+[\u2014\u2013]\s+|(?<=[.;])\s", action.strip(), maxsplit=1)[0]
    if len(head) > 90:
        head = head[:87].rsplit(" ", 1)[0] + "…"
    return f"PQC finding: {head}"


def _locations(r: PqcRemediation) -> list[dict[str, str]]:
    found = []
    for loc in r.locations:
        path, _, line = loc.rpartition(":")
        found.append({"path": path, "lines": line} if path and line.isdigit() else {"path": loc})
    return found


def _finding(b: PqcBlocker, who: str) -> dict[str, Any]:
    r = b.remediation
    description = [r.action]
    if r.deadline:
        description.append(f"NIST IR 8547 clock: disallowed/deprecated after {r.deadline}.")
    if r.blast_radius:
        description.append(f"Blast radius: {r.blast_radius}.")
    description.append(f"TLS decision owner (who_sets_tls): {who}.")
    remediation = r.target or r.action
    if r.blocked_on:
        remediation += f" (blocked on: {r.blocked_on})"
    finding: dict[str, Any] = {
        "id": r.id,
        "title": _title(r.action),
        "severity": b.severity.value,
        "cwes": ["CWE-327"],
        "locations": _locations(r),
        "description": " ".join(p for p in description if p),
        "remediation": remediation,
        "category": "cryptography",
        "validation_status": "not_verified",
        "pqc_classification": b.classification.value,
    }
    if r.remediation_effort:
        finding["remediation_effort"] = r.remediation_effort.value
    return finding


def blockers_document(
    doc: PqcReadinessArtifact, found: PqcReadiness, source: str
) -> PqcBlockersArtifact | None:
    """The report's location-anchored remediations as pqc-blockers, for /patch; the rest are
    listed as excluded, never dropped silently. None when nothing is anchored."""
    body = _body(doc)
    meta, who = body["metadata"], body.get("who_sets_tls", "unknown")
    eligible = [b for b in blockers(found) if b.patchable]
    if not eligible:
        return None
    findings = [_finding(b, who) for b in eligible]
    by_severity = {
        level: [f["id"] for f in findings if f["severity"] == level]
        for level, _ in _SEVERITY_CRITERIA
    }
    by_category: dict[str, list[str]] = {}
    for b in eligible:
        by_category.setdefault(b.remediation.category.value, []).append(b.remediation.id)
    repo = meta["repository"]
    status = body.get("status", "unknown")
    return PqcBlockersArtifact.from_document(
        {
            "artifact": "pqc-blockers",
            "title": f"PQC readiness findings — {repo.rstrip('/').rsplit('/', 1)[-1]}",
            "metadata": {
                "date": meta.get("assessed_at") or "",
                "scope": "Post-quantum readiness remediations projected from "
                f"{source} (deterministic, no new analysis)",
                "repository": repo,
                "commit": meta.get("commit"),
                "framework": "NIST IR 8547",
                "methodology": "Deterministic projection of pqc-readiness remediations[] into "
                "the findings vocabulary by traust-core PqcService",
                "additional": {
                    "harness_version": meta.get("harness_version", ""),
                    "source_artifact": source,
                    "adapter_version": meta["tool"].get("adapter_version", ""),
                    "who_sets_tls": who,
                    "readiness_status": body.get("status", ""),
                    "excluded_remediations": [r.id for r in found.remediations if not r.locations],
                },
            },
            "executive_summary": {
                "prose": f"{len(findings)} PQC transition finding(s) projected from the readiness "
                f"report (status: {status}, TLS decision owner: {who}). These are schedule-risk "
                "items on the NIST IR 8547 clock, not live exploits.",
                "severity_counts": {level: len(ids) for level, ids in by_severity.items()},
            },
            "severity_criteria": [{"level": lv, "definition": d} for lv, d in _SEVERITY_CRITERIA],
            "findings": findings,
            "findings_summary": [
                {"severity": level, "count": len(ids), "finding_ids": ids}
                for level, ids in by_severity.items()
            ],
            "remediation_roadmap": [
                {
                    "priority": _ROADMAP_PRIORITY[category],
                    "action": f"Work the {len(ids)} `{category}` PQC remediation(s) — "
                    "details per finding.",
                    "addresses": ids,
                }
                for category, ids in sorted(by_category.items())
            ],
        }
    )


def route(facts: Sequence[PqcFact], prior: PqcReadiness | None) -> PqcRoute:
    """How much Layer-2 work the facts need against the prior report; routes, never scores."""
    if prior is None:
        return PqcRoute.UNSCORED
    first_party = [f for f in facts if f.path_class is PqcPathClass.FIRST_PARTY]
    if not first_party:
        return PqcRoute.SKIP  # zero-hit, or every fact vendor/test_docs (score-excluded)
    governance = any(f.rule_id.startswith(_GOVERNANCE) for f in first_party)
    stakes = (
        prior.has_2030_clock_items
        or prior.hndl_priority
        or prior.bucket in (PqcReadinessBucket.NOT_READY, PqcReadinessBucket.BLOCKED_EXTERNAL)
    )
    return (
        PqcRoute.FULL if governance or any(f.fips_mode for f in facts) or stakes else PqcRoute.LIGHT
    )


def zero_hit(facts_doc: PqcFactsArtifact) -> bool:
    """A verified zero-hit: no facts, the scan's own assertion, and a full rules pack."""
    body = _body(facts_doc)
    coverage = body["coverage"]
    return (
        not body["facts"]
        and bool(coverage.get("no_crypto_detected_assertion"))
        and (coverage.get("rules_in_pack") or 0) > ZERO_HIT_MIN_RULES
    )


def zero_hit_report(
    name: str, repository_url: str, sha: str, stamps: PqcStamps, assertion: str
) -> PqcReadinessArtifact:
    """The templated not-applicable report: a pure function of the scan's assertion."""

    def domain(*ids: str) -> dict[str, Any]:
        checks = [{"id": i, "result": "na", "rationale": "zero-hit: no crypto facts"} for i in ids]
        return {"score": 100, "assessable_checks": 0, "checks": checks}

    return PqcReadinessArtifact.from_document(
        {
            "title": f"PQC readiness — {name} (verified zero-hit)",
            "metadata": {
                "repository": repository_url,
                "commit": sha,
                "assessment_basis": "source",
                "tool": stamps.model_dump(exclude_none=True),
            },
            "summary": "Verified zero-hit: the pinned scanner found no crypto usage in this "
            "repository, so PQC readiness is not applicable.",
            "status": "not_applicable",
            "who_sets_tls": "unknown",
            "quantum_ready": "unknown",
            "why_not": [],
            "do_next": [],
            "capabilities": [],
            "scores": {
                "VULN": domain("VULN-1", "VULN-2", "VULN-3", "VULN-4"),
                "AGIL": domain("AGIL-1", "AGIL-2", "AGIL-3", "AGIL-4", "AGIL-5", "AGIL-6"),
                "PQCA": domain("PQCA-1", "PQCA-2", "PQCA-3", "PQCA-4"),
                "HNDL": domain("HNDL-1", "HNDL-2", "HNDL-3"),
                "overall": 100,
            },
            "flags": {
                "has_2030_clock_items": False,
                "hndl_priority": False,
                "runtime_verification_required": True,
            },
            "provenance_summary": {"counts": {}, "dominant": "none"},
            "clock_items": [],
            "readiness_bucket": "not-applicable",
            "notes": f"TEMPLATED zero-hit report (split-layer protocol): {assertion}",
        }
    )
