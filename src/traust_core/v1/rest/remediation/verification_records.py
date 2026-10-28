from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import VerificationArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.remediation import Verification
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.remediation.service import Verifications

router = APIRouter()


class VerificationRecordBody(Model):
    payload: str
    provenance: Provenance


@router.post("/v1/verification-records", responses=PROBLEMS(401, 404, 409, 422))
def record_verification(
    body: VerificationRecordBody, verification: Verifications, _: Caller
) -> Verification:
    try:
        payload = body.payload.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValidationError("verification payload must be UTF-8 text") from e
    doc = VerificationArtifact.parse(payload)
    return verification.record(doc, body.provenance)
