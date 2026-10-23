from __future__ import annotations

from typing import overload
from uuid import UUID

from traust_core.v1.models.artifacts import (
    ComplianceAssessmentArtifact,
    ComplianceScopeArtifact,
    DocVarianceArtifact,
)
from traust_core.v1.models.common import ArtifactRef, Page, PageRequest, Provenance
from traust_core.v1.models.compliance import (
    Adr,
    ComplianceAssessment,
    ComplianceDimension,
    ComplianceFilter,
    ComplianceInput,
    ComplianceRollup,
    ComplianceScope,
    DocVariance,
    DocVarianceFilter,
    EvaluationRun,
    InventorySnapshot,
    ScopeFilter,
)
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.repositories.traust.assessments import AssessmentsUnitOfWork


class ComplianceService:
    def __init__(self, uow: AssessmentsUnitOfWork) -> None:
        self._uow = uow

    def set_scope(self, doc: ComplianceScopeArtifact, principal: Principal) -> ComplianceScope:
        raise NotImplementedError("stub: replaces compliance_scope_intake.py")

    def collect_inventory(self, scope_id: UUID) -> InventorySnapshot:
        raise NotImplementedError("stub: replaces collect_cloud_inventory.py")

    def evaluate(self, scope_id: UUID, framework: ComplianceFramework) -> EvaluationRun:
        raise NotImplementedError("stub: replaces compliance_assert.py, run_compliance_check.py")

    def prepare(self, scope_id: UUID, framework: ComplianceFramework) -> ComplianceInput:
        raise NotImplementedError("stub: replaces run_compliance_check bundle inputs")

    @overload
    def record(
        self, doc: ComplianceAssessmentArtifact, provenance: Provenance
    ) -> ComplianceAssessment: ...
    @overload
    def record(self, doc: DocVarianceArtifact, provenance: Provenance) -> list[DocVariance]: ...
    def record(
        self, doc: ComplianceAssessmentArtifact | DocVarianceArtifact, provenance: Provenance
    ) -> ComplianceAssessment | list[DocVariance]:
        raise NotImplementedError(
            "stub: replaces validate_compliance_assessment.py, emit_doc_variance.py"
        )

    def index_adrs(self, product_id: UUID) -> list[Adr]:
        raise NotImplementedError("stub: replaces ops/index_adrs.py")

    def collect_product_docs(self, product_id: UUID) -> list[ArtifactRef]:
        raise NotImplementedError("stub: replaces ops/fetch_product_docs.py")

    def get_scope(self, scope_id: UUID) -> ComplianceScope:
        raise NotImplementedError("stub: replaces compliance/scope.load_scope")

    def scopes(self, filter: ScopeFilter, page: PageRequest) -> Page[ComplianceScope]:
        raise NotImplementedError("stub: replaces compliance/scope.graph_product_repos")

    def latest(self, scope_id: UUID, framework: ComplianceFramework) -> ComplianceAssessment | None:
        raise NotImplementedError("stub: replaces compliance/dashboard.latest_per_target_framework")

    def summary(
        self, filter: ComplianceFilter, group_by: ComplianceDimension
    ) -> list[ComplianceRollup]:
        raise NotImplementedError("stub: replaces compliance_posture")

    def adrs(self, product_id: UUID) -> list[Adr]:
        raise NotImplementedError("stub: replaces adr_registry reads")

    def doc_variances(self, filter: DocVarianceFilter, page: PageRequest) -> Page[DocVariance]:
        raise NotImplementedError("stub: replaces threat-register doc_variance_cut")
