from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from traust_core.v1.models.findings import FindingView
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.findings.service import Findings

router = APIRouter()


@router.get("/v1/findings/{finding_id}", responses=PROBLEMS(401, 404))
def get_finding(finding_id: UUID, findings: Findings, _: Caller) -> FindingView:
    return findings.get(finding_id)
