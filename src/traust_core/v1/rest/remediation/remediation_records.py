from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter
from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import RemediationArtifact
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.remediation import WorkItem
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.remediation.service import Remediation

router = APIRouter()


class RemediationRecordBody(Model):
    payload: str
    provenance: Provenance
    run_order_id: UUID
    lease_generation: Annotated[int, Field(strict=True, gt=0)]
    diff: str | None = None


@router.post("/v1/remediation-records", responses=PROBLEMS(401, 403, 404, 409, 422))
def record_remediation(
    body: RemediationRecordBody, remediation: Remediation, caller: Caller
) -> WorkItem:
    try:
        payload = body.payload.encode("utf-8")
        diff = body.diff.encode("utf-8") if body.diff is not None else None
    except UnicodeEncodeError as e:
        raise ValidationError("remediation payload and diff must be UTF-8 text") from e
    doc = RemediationArtifact.parse(payload)
    return remediation.record_order(
        doc,
        body.provenance,
        body.run_order_id,
        caller,
        lease_generation=body.lease_generation,
        diff=diff,
    )
