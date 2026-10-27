from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from traust_core.v1.models.dependencies import Advisory, AdvisoryPackage, AffectedDependency
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.exposure.service import Exposure

router = APIRouter()


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
