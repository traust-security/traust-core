from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1 import contracts
from traust_core.v1.errors import ConflictError, ValidationError
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import Finding, FindingCandidate, IdentityMove, IntakeResult
from traust_core.v1.repositories.contract import TraustUnitOfWork
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.taxonomy import TaxonomyPolicy


class FindingIntake:
    def __init__(
        self, uow: TraustUnitOfWork, identity: IdentityPolicy, taxonomy: TaxonomyPolicy
    ) -> None:
        self._uow = uow
        self._identity = identity
        self._taxonomy = taxonomy

    def record(self, finding: Finding) -> Finding:
        """Register an identified finding; classifier validation precedes deduplication."""
        finding = Finding.model_validate(dict(finding))
        if any(value is not None for value in (finding.id, finding.created_at, finding.updated_at)):
            raise ValidationError("new findings cannot supply database identity or timestamps")
        if finding.kind is not None:
            contracts.validate_enum("finding_kind", finding.kind)
        with self._uow as uow:
            previous = uow.findings.find_by_fingerprint(
                finding.repository_id, finding.fingerprint_algo, finding.fingerprint
            )
            if previous is not None:
                fields = {"id", "created_at", "updated_at"}
                if previous.model_dump(exclude=fields) != finding.model_dump(exclude=fields):
                    raise ConflictError("finding fingerprint already identifies a different record")
                return previous
            saved = uow.findings.add(finding)
            uow.commit()
            return saved

    def get(self, finding_id: UUID) -> Finding:
        with self._uow as uow:
            finding = uow.findings.get(finding_id)
            kind = finding.kind
            if kind is None:
                for decision in uow.decisions.list_for_finding(finding_id):
                    if decision.validity is None:
                        continue
                    for pair in contracts.normalize_enum("validity", decision.validity).pairs:
                        if pair.enum == "finding_kind":
                            kind = pair.value
            else:
                normalized = contracts.normalize_enum("finding_kind", kind)
                kind = next((p.value for p in normalized.pairs if p.enum == "finding_kind"), kind)
            return Finding.model_validate({**dict(finding), "kind": kind})

    def accept(
        self,
        assessment_id: UUID,
        candidates: Sequence[FindingCandidate],
        provenance: Provenance,
    ) -> IntakeResult:
        raise NotImplementedError(
            "stub: replaces route_impact_findings, route_regressions, emit_fuzz_events"
        )

    def rebaseline(self, moves: Sequence[IdentityMove], decision_id: UUID) -> list[Finding]:
        raise NotImplementedError("stub: replaces finding_identity.rebaseline")
