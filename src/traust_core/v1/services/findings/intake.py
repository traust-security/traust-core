from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.findings import Finding, FindingCandidate
from traust_core.v1.repositories.findings import FindingUnitOfWork
from traust_core.v1.services.findings.identity import IdentityPolicy


class FindingIntake:
    def __init__(self, uow: FindingUnitOfWork, identity: IdentityPolicy) -> None:
        self._uow = uow
        self._identity = identity

    def accept(self, assessment_id: UUID, candidates: Sequence[FindingCandidate]) -> list[Finding]:
        raise NotImplementedError(
            "stub: replaces route_impact_findings.py, route_regressions.py, emit_fuzz_events.py"
        )
