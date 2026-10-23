from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

import pydantic
from pydantic import JsonValue

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import (
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
)
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.code_facts import CryptoFact
from traust_core.v1.models.common import ArtifactRef, Sha256
from traust_core.v1.models.findings import FindingView
from traust_core.v1.models.vocabulary import (
    AdrDeclaredStatus,
    ComplianceAssertionOperator,
    ComplianceControlClassification,
    ComplianceEvidenceKind,
    ComplianceFramework,
    ComplianceTargetKind,
    ComplianceTargetResolvesVia,
    ComplianceVerdict,
    ComplianceVerdictSource,
    DocVarianceDisposition,
    DocVarianceKind,
    Severity,
    Validity,
)

TargetRef = NewType("TargetRef", str)
Collector = NewType("Collector", str)
JsonObject = dict[str, JsonValue]

FINDINGS_DB = Collector("findings_db")
CLOUD_INVENTORY = Collector("cloud_inventory")
CRYPTO_AUDIT = Collector("crypto_audit")

# Fields volatile by construction, never load-bearing for a verdict: two runs over the same
# environment must produce byte-identical evidence.
VOLATILE_FIELDS = frozenset(
    {
        "resourceVersion",
        "uid",
        "creationTimestamp",
        "generation",
        "managedFields",
        "observedGeneration",
        "generated_at",
        "retrieved_at",
        "request_id",
        "etag",
    }
)
EXCERPT_LIMIT = 2000
EVIDENCE_PER_CHECK = 10
SPINE = ComplianceFramework("nist-800-53-rev5")
SPINE_PROFILE = {
    ComplianceFramework("fedramp-high"): "profile-800-53b-high.json",
    ComplianceFramework("fedramp-moderate"): "profile-800-53b-moderate.json",
}
ENVIRONMENT_ONLY = frozenset(
    ComplianceFramework(f) for f in ("fedramp-high", "fedramp-moderate", "gdpr-technical")
)
CAVEATS = {
    ComplianceFramework("soc2-tsc"): (
        "point-in-time technical evidence; a SOC 2 Type 2 examination attests controls over a "
        "period — this is audit input, never an attestation"
    ),
    ComplianceFramework("fedramp-high"): (
        "interim posture: assessed against the NIST 800-53B High selections; FedRAMP-specific "
        "overlays pending an authoritative source"
    ),
    ComplianceFramework("fedramp-moderate"): (
        "interim posture: assessed against the NIST 800-53B Moderate selections; "
        "FedRAMP-specific overlays pending an authoritative source"
    ),
}
DEPENDENCY_CWES = frozenset({"CWE-1035", "CWE-937", "CWE-1104", "CWE-1395"})
CREDENTIAL_CWES = frozenset({"CWE-798", "CWE-321", "CWE-259", "CWE-540"})
COVERAGE_KEYS = (
    "total_in_scope",
    "deterministic",
    "evidence_review",
    "organizational",
    "satisfied",
    "not_satisfied",
    "not_applicable",
    "not_assessed",
)
_SEGMENT = re.compile(r"^([^\[\]]*)((?:\[\*\])*)$")
_LEAF = re.compile(r"^(.+)\.([A-Za-z0-9_-]+)$")


def canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {k: canonicalize(v) for k, v in sorted(value.items()) if k not in VOLATILE_FIELDS}
    if isinstance(value, list):
        return [canonicalize(v) for v in value]
    return value


def canonical_json(value: JsonValue) -> str:
    return json.dumps(
        canonicalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def evidence_id(value: JsonValue) -> Sha256:
    """The content address of a value: sha256 of its canonical JSON."""
    return Sha256(hashlib.sha256(canonical_json(value).encode()).hexdigest())


def select(snapshot: JsonValue, path: str) -> list[JsonValue]:
    """Dot path into the snapshot; `[*]` fans out over lists."""
    current = [snapshot]
    for segment in path.split("."):
        if not (m := _SEGMENT.match(segment)):
            return []
        key, stars = m.group(1), m.group(2).count("[*]")
        if key:
            current = [n[key] for n in current if isinstance(n, dict) and key in n]
        for _ in range(stars):
            current = [v for n in current if isinstance(n, list) for v in n]
    return current


def _number(value: JsonValue) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _holds(
    value: JsonValue, operator: ComplianceAssertionOperator, expected: JsonValue
) -> bool | None:
    """Whether the value meets the operator, or None when the comparison is impossible."""
    match str(operator):
        case "equals":
            return value == expected
        case "not_equals":
            return value != expected
        case "contains" | "not_contains":
            try:
                found = expected in value  # type: ignore[operator]
            except TypeError:
                return None
            return found if operator == "contains" else not found
        case "regex" | "not_regex":
            if value is None:
                return None
            found = re.search(str(expected), str(value)) is not None
            return found if operator == "regex" else not found
        case "gte" | "lte":
            a, b = _number(value), _number(expected)
            if a is None or b is None:
                return None
            return a >= b if operator == "gte" else a <= b
        case "in":
            return value in (expected or [])  # type: ignore[operator]
        case "not_in":
            return value not in (expected or [])  # type: ignore[operator]
    return None


class AssertionOutcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"


class AssertionResult(Model):
    outcome: AssertionOutcome
    values: tuple[JsonValue, ...] = ()
    reason: str = ""


class Assertion(Model):
    """A declarative check over a snapshot: every selected value must hold (no vacuous pass)."""

    path: str
    operator: ComplianceAssertionOperator
    expected: JsonValue = None

    def resolved(self, parameters: Mapping[str, JsonValue]) -> tuple[JsonValue, str]:
        """`param:<id>` reads an org parameter; an undeclared one is a signal, never a default."""
        if isinstance(self.expected, str) and self.expected.startswith("param:"):
            name = self.expected.removeprefix("param:")
            if name not in parameters:
                return None, f"parameter undeclared: {name}"
            return parameters[name], ""
        return self.expected, ""

    def evaluate(
        self,
        snapshot: JsonValue,
        parameters: Mapping[str, JsonValue],
        sampling: str | None = None,
    ) -> AssertionResult:
        expected, missing = self.resolved(parameters)
        if missing:
            return AssertionResult(outcome=AssertionOutcome.NOT_ASSESSED, reason=missing)
        values = select(snapshot, self.path)
        if self.operator in ("exists", "absent"):
            present = AssertionOutcome.PASS if self.operator == "exists" else AssertionOutcome.FAIL
            absent = AssertionOutcome.FAIL if self.operator == "exists" else AssertionOutcome.PASS
            return AssertionResult(outcome=present if values else absent, values=tuple(values))
        if not values:
            return AssertionResult(
                outcome=AssertionOutcome.NOT_ASSESSED,
                reason=f"path selected no values: {self.path}",
            )
        if sampling:
            values = sorted(values, key=canonical_json)[: int(sampling.rsplit("_", 1)[1])]
        for value in values:
            held = _holds(value, self.operator, expected)
            if held is None:
                return AssertionResult(
                    outcome=AssertionOutcome.NOT_ASSESSED,
                    values=tuple(values),
                    reason=f"operator {self.operator} not applicable to selected value type",
                )
            if not held:
                return AssertionResult(outcome=AssertionOutcome.FAIL, values=tuple(values))
        return AssertionResult(outcome=AssertionOutcome.PASS, values=tuple(values))


class ComplianceEvidence(Model):
    """One cited piece of evidence; `value` is the bundle material its sha256 addresses."""

    sha256: Sha256
    kind: ComplianceEvidenceKind
    locator: str
    excerpt: str | None = None
    value: JsonValue = pydantic.Field(default=None, exclude=True)

    @classmethod
    def identify(
        cls, kind: ComplianceEvidenceKind, locator: str, value: JsonValue
    ) -> ComplianceEvidence:
        return cls(
            sha256=evidence_id(value),
            kind=kind,
            locator=locator,
            excerpt=canonical_json(value)[:EXCERPT_LIMIT],
            value=value,
        )


class CheckResult(Model):
    check_id: str
    verdict: ComplianceVerdict
    reason: str | None = None
    evidence: tuple[ComplianceEvidence, ...] = ()


class Check(Dto):
    """A registry check: one assertion over one collector's snapshot, code-computed."""

    id: str
    collector: Collector
    assertion: Assertion
    applies_when: Assertion | None = None
    sampling: str | None = None

    def evaluate(self, snapshot: JsonValue, parameters: Mapping[str, JsonValue]) -> CheckResult:
        if self.applies_when is not None:
            applies = self.applies_when.evaluate(snapshot, parameters)
            if applies.outcome == AssertionOutcome.NOT_ASSESSED:
                return self._result(
                    "not_assessed", f"applicability undeterminable: {applies.reason}"
                )
            if applies.outcome == AssertionOutcome.FAIL:
                return self._result("not_applicable", "declared applicability condition not met")
        result = self.assertion.evaluate(snapshot, parameters, self.sampling)
        if result.outcome == AssertionOutcome.NOT_ASSESSED:
            return self._result("not_assessed", result.reason)
        path, values = self._cited(snapshot, parameters, result)
        evidence = tuple(
            ComplianceEvidence.identify(
                ComplianceEvidenceKind("inventory_snapshot_excerpt"),
                f"{self.collector}:{path}",
                v,
            )
            for v in values[:EVIDENCE_PER_CHECK]
        )
        verdict = "satisfied" if result.outcome == AssertionOutcome.PASS else "not_satisfied"
        return CheckResult(check_id=self.id, verdict=ComplianceVerdict(verdict), evidence=evidence)

    def _result(self, verdict: str, reason: str) -> CheckResult:
        return CheckResult(check_id=self.id, verdict=ComplianceVerdict(verdict), reason=reason)

    def _cited(
        self, snapshot: JsonValue, parameters: Mapping[str, JsonValue], result: AssertionResult
    ) -> tuple[str, list[JsonValue]]:
        """A failure cites the violating values (their parent objects when the path ends in a
        field: a resource with its id beats a bare `false`); an absence cites the scanned scope."""
        path, values = self.assertion.path, list(result.values)
        op = self.assertion.operator
        if result.outcome == AssertionOutcome.FAIL and values and op not in ("exists", "absent"):
            expected, _ = self.assertion.resolved(parameters)
            leaf = _LEAF.match(path)
            parents = [
                p
                for p in (select(snapshot, leaf.group(1)) if leaf else [])
                if isinstance(p, dict)
                and leaf is not None
                and leaf.group(2) in p
                and _holds(p[leaf.group(2)], op, expected) is False
            ]
            if parents and leaf:
                path, values = leaf.group(1), parents
            else:
                values = [v for v in values if _holds(v, op, expected) is False] or values
        if not values:
            parent = re.sub(r"(\[\*\])+$", "", path)
            parent = parent.rsplit(".", 1)[0] if "." in parent else ""
            values = select(snapshot, parent) if parent else [snapshot]
            path = parent or "(snapshot root)"
        return path, values


class MappedControl(Dto):
    framework: ComplianceFramework
    control_id: str
    classification: ComplianceControlClassification
    checks: tuple[str, ...] = ()
    evidence_request: str | None = None


class ComplianceMapping(Dto):
    """The control-to-check registry (policy data): what each control is and how it's checked."""

    version: int
    controls: tuple[MappedControl, ...]
    checks: tuple[Check, ...]

    @classmethod
    def of(cls, artifact: ComplianceMappingArtifact) -> ComplianceMapping:
        mapping = cls.model_validate(json.loads(artifact.payload))
        known = {c.id for c in mapping.checks}
        if missing := sorted({c for ctl in mapping.controls for c in ctl.checks} - known):
            raise ValidationError(f"compliance mapping cites unknown checks: {missing}")
        return mapping

    def check(self, check_id: str) -> Check:
        return next(c for c in self.checks if c.id == check_id)


class ControlResult(Model):
    """One control's verdict in a compliance assessment (`results[]` of the document)."""

    framework: ComplianceFramework
    control_id: str
    classification: ComplianceControlClassification
    verdict: ComplianceVerdict
    verdict_source: ComplianceVerdictSource = ComplianceVerdictSource("check")
    check_id: str | None = None
    title: str | None = None
    reason: str | None = None
    narrative: str | None = None
    evidence: tuple[ComplianceEvidence, ...] = ()
    override: JsonObject | None = None
    n_pass_agreement: JsonObject | None = None


def framework_of(framework: ComplianceFramework) -> ComplianceFramework:
    """The registry framework a selection is assessed through (FedRAMP rides the 800-53 spine)."""
    return SPINE if framework in SPINE_PROFILE else framework


def evaluate_control(
    control: MappedControl,
    framework: ComplianceFramework,
    mapping: ComplianceMapping,
    snapshots: Mapping[Collector, JsonValue],
    parameters: Mapping[str, JsonValue],
) -> ControlResult:
    """Code-computed verdict: every check must pass; the first failure decides."""
    base = ControlResult(
        framework=framework,
        control_id=control.control_id,
        classification=control.classification,
        verdict=ComplianceVerdict("not_assessed"),
    )
    if control.classification == "organizational":
        return base.model_copy(update={"reason": "organizational — out of technical scope"})
    if control.classification == "evidence_review":
        return base.model_copy(
            update={
                "reason": f"evidence_review — awaiting artifact: {control.evidence_request or ''}"
            }
        )
    verdict, evidence, reasons, cited = "satisfied", (), [], None
    for check_id in control.checks:
        check = mapping.check(check_id)
        if check.collector not in snapshots:
            verdict = "not_assessed"
            reasons.append(f"collector unavailable: {check.collector}")
            continue
        result = check.evaluate(snapshots[check.collector], parameters)
        if result.verdict == "not_satisfied":
            verdict, evidence, cited = "not_satisfied", result.evidence, check_id
            break
        if result.verdict in ("not_assessed", "not_applicable") and verdict == "satisfied":
            verdict = result.verdict
            reasons.append(result.reason or "")
        if result.verdict == "satisfied" and not evidence:
            evidence, cited = result.evidence, cited or check_id
    concluded = verdict in ("satisfied", "not_satisfied")
    return base.model_copy(
        update={
            "verdict": ComplianceVerdict(verdict),
            "check_id": cited,
            "evidence": evidence if concluded else (),
            "reason": None if concluded else "; ".join(r for r in reasons if r) or "undetermined",
        }
    )


def coverage(results: Iterable[Mapping[str, JsonValue]]) -> dict[str, dict[str, int]]:
    """Per-framework counts; no blended percentage exists anywhere."""
    counts: dict[str, Counter[str]] = {}
    for r in results:
        c = counts.setdefault(str(r.get("framework", "?")), Counter())
        c["total_in_scope"] += 1
        c[str(r.get("classification", "?"))] += 1
        c[str(r.get("verdict", "?"))] += 1
    return {fw: {k: c.get(k, 0) for k in COVERAGE_KEYS} for fw, c in counts.items()}


def findings_snapshot(views: Iterable[tuple[str, FindingView]]) -> JsonObject:
    """The findings-db collector over the scope's open findings, as (repository url, view):
    critical dependency-class and triage-confirmed credential-class findings."""

    def row(repo: str, v: FindingView) -> JsonObject:
        return {
            "id": str(v.finding.id),
            "severity": str(v.effective_severity),
            "cwes": sorted(v.cwes),
            "repository": repo,
        }

    open_views = sorted(
        ((repo, v) for repo, v in views if v.is_open()),
        key=lambda rv: (rv[0], str(rv[1].finding.id)),
    )
    confirmed = Validity("confirmed")
    return {
        "open_critical_dependency_findings": [
            row(repo, v)
            for repo, v in open_views
            if v.effective_severity == Severity("critical") and DEPENDENCY_CWES & set(v.cwes)
        ],
        "open_confirmed_hardcoded_credential_findings": [
            row(repo, v)
            for repo, v in open_views
            if v.disposition is not None
            and v.disposition.validity == confirmed
            and CREDENTIAL_CWES & set(v.cwes)
        ],
    }


def crypto_snapshot(facts: Sequence[CryptoFact]) -> JsonObject:
    """The crypto_audit collector over the core crypto census (CodeFactsService.crypto)."""
    return {
        "schema": "crypto-audit/v1",
        "facts": [f.model_dump(mode="json", exclude_none=True) for f in facts],
    }


class ComplianceTarget(Model):
    kind: ComplianceTargetKind
    ref: TargetRef
    resolves_via: ComplianceTargetResolvesVia


class ScopeEdge(Model):
    repo: str
    reason: str


class ComplianceScope(Model):
    """One declared compliance boundary, as recorded (`scope_id` is its declaration document)."""

    scope_id: UUID | None = None
    boundary: str
    frameworks: tuple[ComplianceFramework, ...]
    resolves_via: ComplianceTargetResolvesVia
    product: str | None = None
    include: tuple[ScopeEdge, ...] = ()
    exclude: tuple[ScopeEdge, ...] = ()
    declared_by: str
    declared_at: str
    notes: str | None = None

    @property
    def draft(self) -> bool:
        """An unsigned declaration: every consumer labels its output DRAFT."""
        return self.declared_by.startswith("draft:")

    @classmethod
    def of(cls, scope_id: UUID | None, doc: ComplianceScopeArtifact) -> ComplianceScope:
        (boundary, entry), *rest = boundaries(doc).items()
        if rest:
            raise ValidationError("a compliance-scope declaration holds exactly one boundary")
        return cls.model_validate({"scope_id": scope_id, "boundary": boundary, **entry})


def boundaries(doc: ComplianceScopeArtifact) -> dict[str, JsonObject]:
    return dict(json.loads(doc.payload)["boundaries"])


class ScopeMember(Model):
    repository_id: UUID
    repository_ref_id: UUID
    repo: str


class ResolvedScope(Model):
    """A boundary's membership now: the graph resolves scope, the declaration never stores it."""

    scope: ComplianceScope
    members: tuple[ScopeMember, ...]

    @property
    def repos(self) -> tuple[str, ...]:
        return tuple(m.repo for m in self.members)


class InventorySnapshot(Model):
    """A read-only environment snapshot; `snapshot_id` addresses its canonical body."""

    collector: str
    resources: tuple[JsonObject, ...] = ()
    gaps: tuple[str, ...] = ()
    snapshot_id: Sha256

    @classmethod
    def of(
        cls, collector: str, resources: Iterable[JsonObject], gaps: Iterable[str]
    ) -> InventorySnapshot:
        body: JsonObject = {
            "resources": sorted(resources, key=lambda r: str(r.get("id"))),  # type: ignore[dict-item]
            "gaps": sorted(gaps),  # type: ignore[dict-item]
        }
        return cls(
            collector=collector,
            resources=tuple(body["resources"]),  # type: ignore[arg-type]
            gaps=tuple(body["gaps"]),  # type: ignore[arg-type]
            snapshot_id=evidence_id(body),
        )

    def document(self) -> JsonObject:
        return {
            "metadata": {"collector": self.collector, "snapshot_id": self.snapshot_id},
            "resources": list(self.resources),  # type: ignore[dict-item]
            "gaps": list(self.gaps),  # type: ignore[dict-item]
        }


class EvaluationRequest(Model):
    """One run of the deterministic runner over a declared boundary.

    `snapshots` are collector outputs the caller ran (e.g. `scan_k8s_hardening`); the findings
    view, the crypto census (`crypto`) and the inventory (`inventory`) are built here."""

    scope_id: UUID
    harness_version: str
    frameworks: tuple[ComplianceFramework, ...] = ()
    target_kind: ComplianceTargetKind = ComplianceTargetKind("product")
    environment: str | None = None
    cde_boundary: str | None = None
    personal_data_stores: tuple[str, ...] = ()
    trust_categories: tuple[str, ...] = ()
    snapshots: Mapping[Collector, JsonObject] = pydantic.Field(default_factory=dict)
    crypto: tuple[CryptoFact, ...] | None = None
    inventory: InventorySnapshot | None = None

    def skip_reason(self, framework: ComplianceFramework) -> str | None:
        """A framework missing its declared input is skipped with a named reason, never run."""
        if framework == "pci-dss-v4" and not self.cde_boundary:
            return "skipped: no declared CDE boundary (--cde-boundary)"
        if framework == "gdpr-technical" and not self.personal_data_stores:
            return "skipped: no declared personal-data stores (--personal-data-stores)"
        if framework == "soc2-tsc" and not self.trust_categories:
            return "skipped: no declared trust-service categories (--trust-categories)"
        if self.target_kind == "product" and framework in ENVIRONMENT_ONLY:
            return "skipped: requires a deployed-environment target (product-only run)"
        return None


class EvaluationRun(Model):
    """The runner's draft assessment (check verdicts, evidence) and its citation-gate result."""

    model_config = pydantic.ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    scope: ResolvedScope
    document: ComplianceAssessmentArtifact
    evidence: tuple[Sha256, ...] = ()
    failures: tuple[str, ...] = ()


class AwaitingReview(Model):
    framework: ComplianceFramework
    control_id: str
    evidence_request: str


class ComplianceInput(Model):
    """The agent pass: the draft assessment and the evidence_review controls it may judge."""

    scope: ResolvedScope
    assessment: JsonObject
    awaiting: tuple[AwaitingReview, ...]
    prepared_at: datetime


class ComplianceAssessment(Model):
    """A recorded compliance assessment: one document, attached to each in-scope ref."""

    scope_id: UUID
    frameworks: tuple[ComplianceFramework, ...]
    assessed_at: datetime
    results: tuple[ControlResult, ...] = ()
    artifact: ArtifactRef
    assessment_ids: tuple[UUID, ...] = ()

    @classmethod
    def of(
        cls,
        doc: ComplianceAssessmentArtifact,
        artifact: ArtifactRef,
        assessed_at: datetime,
        assessment_ids: Sequence[UUID],
    ) -> ComplianceAssessment:
        body = json.loads(doc.payload)
        return cls(
            scope_id=scope_id_of(doc),
            frameworks=tuple(f["id"] for f in body["metadata"]["frameworks"]),
            assessed_at=assessed_at,
            results=tuple(ControlResult.model_validate(r) for r in body["results"]),
            artifact=artifact,
            assessment_ids=tuple(assessment_ids),
        )


def scope_id_of(doc: ComplianceAssessmentArtifact) -> UUID:
    raw = json.loads(doc.payload)["metadata"].get("scope_id")
    if raw is None:
        raise ValidationError("compliance assessment names no scope_id: run it through evaluate")
    return UUID(str(raw))


# Shapes land with their implementation slice.
class CompliancePosture(Model): ...


class ScopeFilter(Model): ...


class ComplianceFilter(Model): ...


class ComplianceDimension(Model): ...


class ComplianceRollup(Model): ...


class DocVarianceFilter(Model): ...


class Adr(Model):
    product_id: UUID
    number: int
    title: str
    status: AdrDeclaredStatus
    artifact: ArtifactRef


class DocVariance(Model):
    product_id: UUID
    kind: DocVarianceKind
    disposition: DocVarianceDisposition
    artifact: ArtifactRef
