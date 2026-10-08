from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.artifacts import (
    CloudConfigAuditArtifact,
    PrivProfileArtifact,
    SecurityAuditArtifact,
    ThreatModelArtifact,
)
from traust_core.v1.models.assessment import Assessment, AssessmentKind, Freshness
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.storage import BindingContext
from traust_core.v1.repositories.assessment import AssessmentUnitOfWork


class AssessmentService:
    def __init__(self, uow: AssessmentUnitOfWork) -> None:
        self._uow = uow

    def record_audit(
        self, audit: SecurityAuditArtifact | CloudConfigAuditArtifact, context: BindingContext
    ) -> JobResult:
        raise NotImplementedError("stub: replaces corpus/store_ingest.py, report_store.py")

    def record_threat_model(self, model: ThreatModelArtifact, context: BindingContext) -> JobResult:
        raise NotImplementedError("stub: replaces threat-model scripts, corpus/threat_model.py")

    def record_priv_profile(
        self, profile: PrivProfileArtifact, context: BindingContext
    ) -> JobResult:
        raise NotImplementedError("stub: replaces operator-priv-profile scripts")

    def latest(self, code_line_id: UUID, kind: AssessmentKind) -> Assessment | None:
        raise NotImplementedError("stub: replaces corpus/resolver.py lookups")

    def population(self, as_of: datetime) -> list[Assessment]:
        raise NotImplementedError("stub: replaces census/build_census.py, corpus/resolver.py")

    def freshness(self, code_line_id: UUID) -> Freshness:
        raise NotImplementedError("stub: replaces audit_age_days/churn_ratio in traust#58")
