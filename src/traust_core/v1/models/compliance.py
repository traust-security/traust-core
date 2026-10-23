from __future__ import annotations

from datetime import datetime
from typing import NewType
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.common import ArtifactRef, Sha256
from traust_core.v1.models.findings import SkillInput
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import (
    AdrDeclaredStatus,
    ComplianceAssertionOperator,
    ComplianceEvidenceKind,
    ComplianceFramework,
    ComplianceTargetKind,
    ComplianceTargetResolvesVia,
    ComplianceVerdict,
    ComplianceVerdictSource,
    DocVarianceDisposition,
    DocVarianceKind,
    ScopeBindingMode,
)

EvidenceId = NewType("EvidenceId", str)
TargetRef = NewType("TargetRef", str)


# Shapes land with their implementation slice.
class ControlRef(Model): ...


class AssertionResult(Model): ...


class CompliancePosture(Model): ...


class InventorySnapshot(Model): ...


class EvaluationRun(Model): ...


class ScopeFilter(Model): ...


class ComplianceFilter(Model): ...


class ComplianceDimension(Model): ...


class ComplianceRollup(Model): ...


class DocVarianceFilter(Model): ...


class ComplianceInput(SkillInput): ...


class ComplianceTarget(Model):
    kind: ComplianceTargetKind
    ref: TargetRef
    resolves_via: ComplianceTargetResolvesVia


class ComplianceEvidence(Model):
    id: EvidenceId
    kind: ComplianceEvidenceKind
    digest: Sha256
    artifact: ArtifactRef

    @classmethod
    def identify(cls, kind: ComplianceEvidenceKind, payload: bytes) -> ComplianceEvidence:
        raise NotImplementedError("stub: replaces compliance_assert.evidence_id")


class Assertion(Model):
    control: ControlRef
    selector: str
    operator: ComplianceAssertionOperator
    expected: object

    def evaluate(self, evidence: ComplianceEvidence) -> AssertionResult:
        raise NotImplementedError("stub: replaces compliance_assert.eval_assertion")


class ComplianceScope(Model):
    product_id: UUID
    frameworks: tuple[ComplianceFramework, ...] = ()
    targets: tuple[ComplianceTarget, ...] = ()
    binding: ScopeBindingMode
    declared_by: Principal

    def covers(self, target: ComplianceTarget) -> bool:
        raise NotImplementedError("stub: replaces compliance/scope.resolve")


class ControlResult(Model):
    control: ControlRef
    verdict: ComplianceVerdict
    source: ComplianceVerdictSource
    evidence: tuple[EvidenceId, ...] = ()


class ComplianceAssessment(Model):
    scope_id: UUID
    framework: ComplianceFramework
    assessed_at: datetime
    results: tuple[ControlResult, ...] = ()
    artifact: ArtifactRef

    def posture(self) -> CompliancePosture:
        raise NotImplementedError("stub: replaces compliance/dashboard.latest_per_target_framework")


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
