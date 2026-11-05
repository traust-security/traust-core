from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.dependencies import (
    Advisory,
    AdvisoryIdentifier,
    AdvisoryPackage,
    AdvisoryRecord,
    AffectedDependency,
    ImpactExport,
    ImpactInput,
    ProvenanceReconciliation,
)
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.exposure.service import Exposure

router = APIRouter()


@router.get("/v1/advisories", responses=PROBLEMS(401, 404, 422))
def find_advisory(
    exposure: Exposure,
    _: Caller,
    identifier: Annotated[str, Query(min_length=1, max_length=128)],
) -> AdvisoryRecord:
    """An advisory by any id (CVE-, GHSA-, GO-, MAL-…) as its source states it now, kept with its
    aliases and packages; `advisory_id` is what `/affected` takes. 404 when the source has none."""
    found = exposure.find_advisory(AdvisoryIdentifier(identifier))
    if found is None:
        raise NotFoundError(f"advisory {identifier}: its source doesn't know it")
    return found


@router.get("/v1/advisories/{advisory_id}", responses=PROBLEMS(401, 404))
def get_advisory(advisory_id: UUID, exposure: Exposure, _: Caller) -> Advisory:
    return exposure.get_advisory(advisory_id)


@router.get("/v1/advisories/{advisory_id}/packages", responses=PROBLEMS(401))
def packages_affected(advisory_id: UUID, exposure: Exposure, _: Caller) -> list[AdvisoryPackage]:
    return exposure.packages_affected(advisory_id)


@router.get("/v1/advisories/{advisory_id}/affected", responses=PROBLEMS(401))
def affected(advisory_id: UUID, exposure: Exposure, _: Caller) -> list[AffectedDependency]:
    """The advisory's blast radius: the commits and the path by which each is affected."""
    return exposure.affected(advisory_id)


@router.get("/v1/advisories/{advisory_id}/impact-report", responses=PROBLEMS(401, 404))
def export_advisory_impacts(advisory_id: UUID, exposure: Exposure, _: Caller) -> ImpactExport:
    return exposure.export_impacts(advisory_id)


@router.get("/v1/advisories/{advisory_id}/impact-inputs", responses=PROBLEMS(401, 404, 422))
def prepare_advisory_impacts(
    advisory_id: UUID, repository_ref_id: UUID, exposure: Exposure, _: Caller
) -> tuple[ImpactInput, ...]:
    return exposure.prepare(advisory_id, repository_ref_id)


@router.post("/v1/provenance-reconciliations", responses=PROBLEMS(401, 404, 422))
def reconcile_cve_provenance(
    exposure: Exposure,
    _: Caller,
    min_score: Annotated[float, Query(ge=0, le=1, allow_inf_nan=False)] = 0.55,
    apply: bool = False,
) -> ProvenanceReconciliation:
    return exposure.reconcile_all_provenance(min_score=min_score, apply=apply)
