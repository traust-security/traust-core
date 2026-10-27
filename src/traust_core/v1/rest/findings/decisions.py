from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter
from pydantic import Field

from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import Decision, RecordDecision, Restatement
from traust_core.v1.models.vocabulary import (
    DecisionReason,
    DispositionResolution,
    EvidenceGrade,
    RestatementReason,
    Severity,
    SourceChannel,
    Validity,
)
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()

Text = Annotated[str, Field(max_length=20_000)]


class DecisionBody(Model):
    """A countersign or re-rating; the finding is the path, never the body (no id confusion)."""

    rationale: Text
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None
    severity: Severity | None = None
    reason: DecisionReason | None = None
    source_channel: SourceChannel | None = None
    repository_ref_id: UUID | None = None
    fixed_repository_ref_id: UUID | None = None
    artifact_id: UUID | None = None
    occurred_at: datetime | None = None


class RestatementBody(Model):
    """An administrator's correction; the decision is the path, never the body."""

    reason: RestatementReason
    ticket: Annotated[str, Field(max_length=200)]
    rationale: Text
    approvers: tuple[Annotated[str, Field(max_length=320)], ...] = ()
    validity: Validity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None
    severity: Severity | None = None
    fixed_repository_ref_id: UUID | None = None


@router.get("/v1/findings/{finding_id}/decisions", responses=PROBLEMS(401))
def list_decisions(finding_id: UUID, findings: Findings, _: Caller) -> list[Decision]:
    return findings.decisions.list_for_finding(finding_id)


@router.post("/v1/findings/{finding_id}/decisions", responses=PROBLEMS(401, 403, 404, 409, 422))
def decide(finding_id: UUID, body: DecisionBody, findings: Findings, caller: Caller) -> Decision:
    """Record the caller's statement on the finding; an identical repeat is idempotent."""
    command = RecordDecision(finding_id=finding_id, **body.model_dump())
    return findings.decisions.decide(command, caller)


@router.get("/v1/decisions/{decision_id}", responses=PROBLEMS(401, 404))
def get_decision(decision_id: UUID, findings: Findings, _: Caller) -> Decision:
    return findings.decisions.get(decision_id)


@router.get("/v1/repositories/{repository_id}/decisions", responses=PROBLEMS(401))
def list_repository_decisions(repository_id: UUID, findings: Findings, _: Caller) -> list[Decision]:
    return findings.decisions.for_repository(repository_id)


@router.post("/v1/decisions/{decision_id}/restatement", responses=PROBLEMS(401, 403, 404, 409, 422))
def restate(
    decision_id: UUID, body: RestatementBody, findings: Findings, caller: Caller
) -> Decision:
    """Correct a decision (administrators); the correction replaces the one it restates."""
    restatement = Restatement(decision_id=decision_id, **body.model_dump())
    return findings.decisions.restate(restatement, caller)
