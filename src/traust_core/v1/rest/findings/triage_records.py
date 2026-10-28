from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import TriageInput, TriageRecordResult
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()


class TriageRecordBody(Model):
    payload: str
    provenance: Provenance


@router.get("/v1/assessments/{assessment_id}/triage-input", responses=PROBLEMS(401, 404, 422))
def prepare_triage(assessment_id: UUID, findings: Findings, _: Caller) -> TriageInput:
    return findings.decisions.prepare(assessment_id)


@router.post(
    "/v1/assessments/{assessment_id}/triage-records", responses=PROBLEMS(401, 404, 409, 422, 500)
)
def record_triage(
    assessment_id: UUID, body: TriageRecordBody, findings: Findings, _: Caller
) -> TriageRecordResult:
    try:
        payload = body.payload.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValidationError("triage payload must be UTF-8 text") from e
    return findings.decisions.record_triage(
        assessment_id, TriageArtifact.parse(payload), body.provenance
    )
