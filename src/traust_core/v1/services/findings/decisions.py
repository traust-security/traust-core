from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.findings import Decision, TriageVerdict
from traust_core.v1.models.operations import JobResult
from traust_core.v1.models.storage import BindingContext
from traust_core.v1.providers.clock import Clock
from traust_core.v1.repositories.findings import FindingUnitOfWork
from traust_core.v1.repositories.triage import TriageUnitOfWork
from traust_core.v1.services.findings.transitions import TransitionPolicy
from traust_core.v1.services.storage import RecordResult, bind_artifact


class FindingDecisions:
    def __init__(self, uow: FindingUnitOfWork, transitions: TransitionPolicy) -> None:
        self._uow = uow
        self._transitions = transitions

    def record(self, decision: Decision) -> None:
        raise NotImplementedError("stub: replaces emit_*_ledger_events.py")

    def record_triage(self, triage: TriageArtifact, context: BindingContext) -> JobResult:
        raise NotImplementedError(
            "stub: wraps record_triage as a JobResult; replaces emit_triage_ledger_events.py"
        )


def verdicts_from(triage: TriageArtifact, binding_id: str, digest: str) -> list[TriageVerdict]:
    return [
        TriageVerdict(
            binding_id=binding_id,
            artifact_digest=digest,
            finding_id=f.id,
            source_finding_id=f.orig_id,
            triage_completed=triage.triage_completed,
            verdict=f.verdict,
            severity=f.severity,
            vote_breakdown=_votes(f.vote_breakdown),
            rationale=f.rationale,
        )
        for f in triage.findings
    ]


def _votes(view: Any) -> dict[str, int] | None:
    if view is None:
        return None
    return {
        k: getattr(view, k)
        for k in ("true_positive", "hardening", "false_positive", "cannot_verify")
    }


def record_triage(
    uow: TriageUnitOfWork,
    triage: TriageArtifact,
    clock: Clock,
    context: BindingContext,
    references: Sequence[str] = (),
) -> RecordResult:
    with uow:
        result = bind_artifact(uow, triage.schema, triage.payload, clock, context, references)
        if not result.already_bound:
            uow.triage_verdicts.add_all(verdicts_from(triage, result.binding_id, result.digest))
        uow.commit()
    return result
