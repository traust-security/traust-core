from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID, uuid5

import pydantic
from pydantic import JsonValue

from traust_core.v1.errors import ConflictError, ValidationError
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


class EfficacyFailureClass(StrEnum):
    """Worst first: a verdict on an honesty probe means the assessor invented evidence."""

    GUESSING = "guessing"
    WRONG_VERDICT = "wrong_verdict"
    MISSING = "missing"
    INCOHERENCE = "incoherence"


class EfficacyFailure(Model):
    kind: EfficacyFailureClass
    control: str  # framework:control, or "a <> b" for a crosswalk pair
    expected: str
    got: str


class EfficacyKey(Model):
    """A seeded target's answer key: verdicts true by construction of its snapshots, never
    bootstrapped from a run; honesty probes must stay not_assessed; crosswalk pairs must agree."""

    # NEED(contracts: compliance-efficacy answer key schema): no artifact type holds the key, so
    # the caller supplies it per run; it can't be recorded or versioned as benchmark-target is.
    expected: Mapping[ComplianceFramework, Mapping[str, ComplianceVerdict]]
    honesty_probes: tuple[str, ...] = ()
    crosswalk_coherence: tuple[tuple[str, str], ...] = ()

    def score(self, doc: ComplianceAssessmentArtifact) -> tuple[EfficacyFailure, ...]:
        """Every way the assessment misses the key, worst class first."""
        got = {f"{r['framework']}:{r['control_id']}": r["verdict"] for r in _results(doc)}
        failures = []
        for framework, controls in self.expected.items():
            for control, want in controls.items():
                ref = f"{framework}:{control}"
                if (actual := got.get(ref)) is None:
                    kind, actual = EfficacyFailureClass.MISSING, "(no result emitted)"
                elif actual == want:
                    continue
                elif ref in self.honesty_probes:
                    kind = EfficacyFailureClass.GUESSING
                else:
                    kind = EfficacyFailureClass.WRONG_VERDICT
                failures.append(EfficacyFailure(kind=kind, control=ref, expected=want, got=actual))
        failures += [
            EfficacyFailure(
                kind=EfficacyFailureClass.INCOHERENCE,
                control=f"{a} <> {b}",
                expected="agreement",
                got=f"{got.get(a)} vs {got.get(b)}",
            )
            for a, b in self.crosswalk_coherence
            if got.get(a) != got.get(b)
        ]
        order = list(EfficacyFailureClass)
        return tuple(sorted(failures, key=lambda f: order.index(f.kind)))


class RunCalibration(Model):
    """The run-twice idempotence gate over one evaluation and, given a key, its efficacy."""

    controls: int
    divergences: tuple[str, ...] = ()  # empty: byte-identical runs
    efficacy: tuple[EfficacyFailure, ...] | None = None  # None: no answer key given

    @property
    def passed(self) -> bool:
        return not self.divergences and not self.efficacy


def divergences(first: EvaluationRun, second: EvaluationRun) -> tuple[str, ...]:
    """How two runs over the same inputs differ, `generated_at` aside: per control, then the
    coverage blocks, then the gate."""
    a, b = (_comparable(r.document) for r in (first, second))
    out = []
    if a != b:
        ra, rb = ({(r["framework"], r["control_id"]): r for r in d["results"]} for d in (a, b))
        for key in sorted(ra.keys() | rb.keys()):
            va, vb = ra.get(key), rb.get(key)
            if va is None or vb is None:
                out.append(f"{key[0]}:{key[1]} present in only one run")
            elif canonical_json(va) != canonical_json(vb):
                same = va["verdict"] == vb["verdict"]
                out.append(
                    f"{key[0]}:{key[1]} differs: run1={va['verdict']} run2={vb['verdict']}"
                    + (" (same verdict, differing evidence/fields)" if same else "")
                )
        if a["coverage"] != b["coverage"]:
            out.append("coverage blocks differ")
        if not out:
            out.append("(difference outside the result set)")
    if first.failures != second.failures:
        out.append(f"gate outcomes differ: {list(first.failures)} vs {list(second.failures)}")
    return tuple(out)


def _results(doc: ComplianceAssessmentArtifact) -> list[dict[str, JsonValue]]:
    return json.loads(doc.payload)["results"]


def _comparable(doc: ComplianceAssessmentArtifact) -> dict[str, JsonValue]:
    body = json.loads(doc.payload)
    body["metadata"].pop("generated_at", None)
    return body


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
    skipped: dict[str, str] = pydantic.Field(default_factory=dict)
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
            skipped=body["metadata"].get("skipped_frameworks") or {},
            artifact=artifact,
            assessment_ids=tuple(assessment_ids),
        )

    def posture(self) -> CompliancePosture:
        """Per-framework coverage, unsatisfied controls, skips and caveats; never one number."""
        return CompliancePosture(
            scope_id=self.scope_id,
            assessed_at=self.assessed_at,
            coverage=coverage(r.model_dump(mode="json") for r in self.results),
            not_satisfied=tuple(r for r in self.results if r.verdict == "not_satisfied"),
            skipped=self.skipped,
            caveats={str(fw): CAVEATS[fw] for fw in self.frameworks if fw in CAVEATS},
        )


def scope_id_of(doc: ComplianceAssessmentArtifact) -> UUID:
    raw = json.loads(doc.payload)["metadata"].get("scope_id")
    if raw is None:
        raise ValidationError("compliance assessment names no scope_id: run it through evaluate")
    return UUID(str(raw))


class CompliancePosture(Model):
    """One assessment as the dashboard shows it: per-framework coverage with transparency rows."""

    scope_id: UUID
    assessed_at: datetime
    coverage: dict[str, dict[str, int]]
    not_satisfied: tuple[ControlResult, ...] = ()
    skipped: dict[str, str] = pydantic.Field(default_factory=dict)
    caveats: dict[str, str] = pydantic.Field(default_factory=dict)


class ScopeFilter(Model):
    framework: ComplianceFramework | None = None
    product: str | None = None
    draft: bool | None = None

    def admits(self, scope: ComplianceScope) -> bool:
        return (
            (self.framework is None or self.framework in scope.frameworks)
            and (self.product is None or scope.product == self.product)
            and (self.draft is None or scope.draft == self.draft)
        )


class ComplianceFilter(Model):
    scope_id: UUID | None = None
    framework: ComplianceFramework | None = None


class ComplianceDimension(StrEnum):
    FRAMEWORK = "framework"
    SCOPE = "scope"


class ComplianceRollup(Model):
    """One group's declared (boundary, framework) pairs, how many are assessed, and the summed
    coverage of their newest assessments, kept per framework (never blended)."""

    key: str
    pairs: int
    assessed: int
    coverage: dict[str, dict[str, int]]


class AdrStatus(StrEnum):
    ACCEPTED = "accepted"
    PROPOSED = "proposed"
    SUPERSEDED = "superseded"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"
    ARCHIVED = "archived"
    UNKNOWN = "unknown"


NON_CITABLE_ADR = frozenset(
    {AdrStatus.SUPERSEDED, AdrStatus.DEPRECATED, AdrStatus.ARCHIVED, AdrStatus.REJECTED}
)
ADR_LOCATOR = "adr:"
_ADR_EXTENSIONS = (".md", ".adoc")
_ADR_SKIP = ("template", "readme", "guideline", "index")
_ADR_STATUS = re.compile(
    r"(?im)^\s*(?:[-*#>\s]*status\s*[:*]*\s*)[\"'`\[\s]*"
    r"(accepted|proposed|superseded|deprecated|rejected|approved|draft)"
)
_ADR_TITLE = re.compile(r"(?m)^#\s+(.{3,120})$")


class Adr(Model):
    """A decision record of a pinned register, cited as `adr:<register>/<decision>`."""

    register_name: str
    decision: str
    title: str
    status: AdrStatus
    declared: bool = False
    path: str
    url: str
    artifact: ArtifactRef

    @property
    def key(self) -> str:
        return f"{self.register_name}/{self.decision}"


def is_decision_record(path: str, paths: Sequence[str]) -> bool:
    """A record under one of the register's paths, not a template/readme/index."""
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    return (
        path.lower().endswith(_ADR_EXTENSIONS)
        and any(path.startswith(base.rstrip("/") + "/") for base in paths)
        and not any(s in stem for s in _ADR_SKIP)
    )


def parse_adr(
    register: Mapping[str, JsonValue], path: str, text: str, url: str, artifact: ArtifactRef
) -> Adr:
    """Status from the MADR status line (`unknown` when absent, never guessed); an archives/
    path is archived; a register-level declared status overrides both."""
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    found = _ADR_STATUS.search(text)
    status = {"approved": "accepted", "draft": "proposed"}.get(
        raw := found.group(1).lower() if found else "unknown", raw
    )
    if "/archives/" in path or path.split("/")[-2:-1] == ["archives"]:
        status = "archived"
    declared = register.get("declared_status")
    title = _ADR_TITLE.search(text)
    return Adr(
        register_name=str(register["name"]),
        decision=stem,
        title=title.group(1).strip() if title else stem,
        status=AdrStatus(str(declared or status)),
        declared=bool(declared),
        path=path,
        url=url,
        artifact=artifact,
    )


def adr_citations(body: Mapping[str, JsonValue]) -> list[tuple[int, int, str]]:
    """(result, evidence, decision key) of each ADR a satisfied verdict cites."""
    return [
        (i, j, str(ev["locator"]).removeprefix(ADR_LOCATOR))
        for i, r in enumerate(body["results"])  # type: ignore[arg-type]
        if r["verdict"] == "satisfied"
        for j, ev in enumerate(r.get("evidence") or [])
        if str(ev.get("locator", "")).startswith(ADR_LOCATOR)
    ]


class DocVarianceFilter(Model):
    repository_id: UUID | None = None
    product_slug: str | None = None
    disposition: DocVarianceDisposition | None = None
    kind: DocVarianceKind | None = None


class DocVariance(Model):
    """One official-docs claim that code evidence contradicts (a doc-variance register record)."""

    repository_id: UUID
    record: str
    kind: DocVarianceKind | None = None
    disposition: DocVarianceDisposition
    product_slug: str
    version: str
    claim: str
    verified_at: datetime
    artifact: ArtifactRef

    @classmethod
    def of(cls, repository_id: UUID, record: JsonObject, artifact: ArtifactRef) -> DocVariance:
        source: JsonObject = record["source"]  # type: ignore[assignment]
        return cls(
            repository_id=repository_id,
            record=str(record["id"]),
            kind=record.get("variance"),  # type: ignore[arg-type]
            disposition=record["disposition"],  # type: ignore[arg-type]
            product_slug=str(source["product_slug"]),
            version=str(source["version"]),
            claim=str(record["claim"]),
            verified_at=record["verified_at"],  # type: ignore[arg-type]
            artifact=artifact,
        )

    @property
    def position(self) -> tuple[datetime, UUID]:
        """Oldest first; ties break on a stable id derived from (repository, record)."""
        return self.verified_at, uuid5(self.repository_id, self.record)

    def admitted_by(self, f: DocVarianceFilter) -> bool:
        return (
            (f.repository_id is None or f.repository_id == self.repository_id)
            and (f.product_slug is None or f.product_slug == self.product_slug)
            and (f.disposition is None or f.disposition == self.disposition)
            and (f.kind is None or f.kind == self.kind)
        )


def merge_variances(
    prior: Mapping[str, JsonValue] | None,
    incoming: Mapping[str, JsonValue],
    now: str,
    *,
    update: bool,
) -> JsonObject | None:
    """The register with `incoming`'s records appended, None when nothing changed. A changed
    record is never rewritten: with `update` it is kept as superseded and the new one appended."""
    if not incoming["records"]:
        raise ValidationError("no doc-variance records: nothing to record is an error")
    base = prior or {"metadata": incoming["metadata"], "records": []}
    records: list[JsonObject] = list(base["records"])  # type: ignore[arg-type]
    at = {str(r["id"]): i for i, r in enumerate(records)}
    changed = False
    for rec in incoming["records"]:  # type: ignore[union-attr]
        rid = str(rec["id"])  # type: ignore[index]
        if rid not in at:
            at[rid] = len(records)
            records.append(rec)  # type: ignore[arg-type]
        elif records[at[rid]] == rec:
            continue
        elif not update:
            raise ConflictError(
                f"doc-variance record {rid} exists with different content — pass update to "
                "supersede it (silent rewrite refused)"
            )
        else:
            successor = f"{rid}-r{len(records)}"
            records[at[rid]] = {
                **records[at[rid]],
                "disposition": "superseded",
                "disposition_note": f"superseded {now} by {successor}",
            }
            records.append({**rec, "id": successor})  # type: ignore[dict-item]
        changed = True
    if not changed:
        return None
    return {"metadata": {**base["metadata"], "updated": now}, "records": records}  # type: ignore[dict-item]


OFFICIAL_DOCS = "https://docs.redhat.com/"
_TAG = re.compile(r"<[^>]+>")
_HEADING = re.compile(r"<h([1-4])([^>]*)>(.*?)</h\1>", re.S)
_ID = re.compile(r'id="([^"]*)"')
_ANCHOR = re.compile(r'href="#([^"]+)"')
_COPY_LINK = re.compile(r"Copy link(Link copied to clipboard!?)?\s*$")
_CHROME = re.compile(r"<(script|style|nav|header|footer)\b.*?</\1>", re.S | re.I)


def doc_text(page: str, url: str) -> str:
    """Plain text with each heading as `## <title> [<url>#<anchor>]`, so a claim can cite its
    canonical section URL."""
    src = _CHROME.sub("", page)
    out, pos = [], 0
    for m in _HEADING.finditer(src):
        out.append(html.unescape(_TAG.sub(" ", src[pos : m.start()])))
        title = _COPY_LINK.sub("", html.unescape(_TAG.sub("", m.group(3))).strip()).strip()
        # docs.redhat.com puts ids on wrappers; every heading embeds its own copy-link anchor
        anchor = _ID.search(m.group(2)) or _ANCHOR.search(m.group(3))
        out.append(f"\n\n## {title} [{f'{url}#{anchor.group(1)}' if anchor else url}]\n")
        pos = m.end()
    out.append(html.unescape(_TAG.sub(" ", src[pos:])))
    text = "\n".join(re.sub(r"[ \t]+", " ", ln).strip() for ln in "".join(out).splitlines())
    return re.sub(r"\n{3,}", "\n\n", text).strip()


class DocGuide(Model):
    """One official guide as plain text for claim extraction; never stored (CC-BY-SA: variance
    records persist, doc mirrors don't)."""

    product_slug: str
    version: str
    guide: str
    url: str
    text: str
