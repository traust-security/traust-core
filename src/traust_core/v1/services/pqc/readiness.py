"""The readiness report's rules past its schema (`pqc_facts --validate-readiness`), its
remediations in the findings vocabulary (`build_pqc_blockers`), the Layer-2 route
(`l2_prepass`) and the zero-hit verdict (`bulk_prescan`)."""

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
    PqcFactsArtifact,
    PqcReadinessArtifact,
)
from traust_core.v1.models.pqc import (
    PqcBlocker,
    PqcFact,
    PqcReadiness,
    PqcRemediation,
    PqcRoute,
)
from traust_core.v1.models.vocabulary import (
    PqcClassification,
    PqcDominantProvenance,
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
        who_sets_tls=body.get("who_sets_tls"),
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


def zero_hit_readiness(
    assessment_id: UUID, repository_ref_id: UUID, assessed_at: datetime
) -> PqcReadiness:
    """A verified zero-hit's readiness, derived from its facts: not applicable, nothing to do."""
    return PqcReadiness(
        assessment_id=assessment_id,
        repository_ref_id=repository_ref_id,
        assessed_at=assessed_at,
        bucket=PqcReadinessBucket.NOT_APPLICABLE,
        overall=100,
        has_2030_clock_items=False,
        hndl_priority=False,
        runtime_verification_required=True,
        dominant=PqcDominantProvenance.NONE,
        who_sets_tls="unknown",
    )
