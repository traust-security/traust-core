from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ValidationArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.validation import ValidationRecordInput, ValidationRecordResult
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.validation.service import Validation

router = APIRouter()


class RecordValidation(Model):
    payload: str
    provenance: Provenance
    bindings: ValidationRecordInput


@router.post("/v1/validation-records", responses=PROBLEMS(401, 404, 409, 422))
def record_validation(
    body: RecordValidation, validation: Validation, _: Caller
) -> ValidationRecordResult:
    try:
        payload = body.payload.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValidationError("validation payload must be UTF-8 text") from e
    return validation.record(ValidationArtifact.parse(payload), body.provenance, body.bindings)
