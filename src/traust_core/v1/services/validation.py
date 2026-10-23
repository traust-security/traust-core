from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.common import Page, PageRequest, Provenance
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.validation import (
    Authorization,
    FindingChain,
    RefusalReason,
    TargetAttestation,
    TargetObservation,
    ValidationAttempt,
    ValidationDimension,
    ValidationFilter,
    ValidationInput,
    ValidationPlan,
    ValidationRollup,
    ValidationRun,
    ValidationScope,
)
from traust_core.v1.models.vocabulary import ValidationTechnique
from traust_core.v1.providers.validation import ValidationAdapter
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions


class ValidationService:
    def __init__(
        self,
        uow: TraustUnitOfWork,
        decisions: FindingDecisions,
        adapters: Sequence[ValidationAdapter],
    ) -> None:
        self._uow = uow
        self._decisions = decisions
        self._adapters = adapters

    def prepare(self, finding_id: UUID) -> ValidationInput:
        raise NotImplementedError("stub: replaces validate-findings/ingest.py")

    def plan(self, finding_id: UUID, technique: ValidationTechnique) -> ValidationPlan:
        raise NotImplementedError("stub: replaces validate-findings/plan.py, novel.py")

    def chains(self, finding_ids: Sequence[UUID]) -> list[FindingChain]:
        raise NotImplementedError("stub: replaces validate-findings/chain.py")

    def authorize(
        self, plan_id: UUID, scope: ValidationScope, principal: Principal
    ) -> Authorization:
        raise NotImplementedError("stub: replaces validation/scope.build, approval mode")

    def attest_target(self, plan_id: UUID, observed: TargetObservation) -> TargetAttestation:
        raise NotImplementedError("stub: replaces attest_target.py")

    def execute(self, plan_id: UUID, authorization: Authorization) -> ValidationRun:
        raise NotImplementedError("stub: replaces validate-findings/execute.py, run.py")

    def record(self, doc: ValidationArtifact, provenance: Provenance) -> list[ValidationAttempt]:
        raise NotImplementedError("stub: replaces emit_validation_ledger_events.py")

    def refuse(self, plan_id: UUID, reason: RefusalReason) -> ValidationPlan:
        raise NotImplementedError("stub: replaces validate-findings refusal records")

    def get_plan(self, plan_id: UUID) -> ValidationPlan:
        raise NotImplementedError("stub: validation read")

    def attempts(self, finding_id: UUID) -> list[ValidationAttempt]:
        raise NotImplementedError("stub: replaces build_remediation_manifest.latest_validation")

    def list(self, filter: ValidationFilter, page: PageRequest) -> Page[ValidationAttempt]:
        raise NotImplementedError("stub: replaces validation_current")

    def summary(
        self, filter: ValidationFilter, group_by: ValidationDimension
    ) -> list[ValidationRollup]:
        raise NotImplementedError("stub: replaces validation_exposure, validation-fuzz dashboard")
