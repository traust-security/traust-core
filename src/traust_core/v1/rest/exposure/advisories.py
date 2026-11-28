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
    ImpactAnswer,
    ImpactExport,
    ImpactInput,
    parse_advisory_identifier,
)
from traust_core.v1.models.operations import RunBatch
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


@router.get("/v1/advisories/{identifier}/impact", responses=PROBLEMS(401, 404, 422))
def advisory_impact(identifier: str, exposure: Exposure, _: Caller) -> ImpactAnswer:
    """Every tracked ref's outcome for the advisory (any id its source knows, or its recorded
    id): rows for the refs using its ecosystems, counts for the proven rest and every gap, what
    a fill could fix, and how old the head observations are. Each in-range row carries its
    evidence grade — a range match alone is `likely_affected`; `affected` and `not_observed`
    rest on a reachability verdict recorded at that exact head — and the answer's caveats name
    what its evidence cannot see."""
    return exposure.impact(_advisory(identifier))


@router.post("/v1/advisories/{identifier}/impact/fill", responses=PROBLEMS(401, 403, 404, 422))
def fill_advisory_impact(identifier: str, exposure: Exposure, caller: Caller) -> RunBatch | None:
    """Queue the orders that complete the advisory's answer, in one batch; the running fill's
    batch when one is already going; null when there is nothing to fill."""
    return exposure.fill(_advisory(identifier), caller)


def _advisory(identifier: str) -> AdvisoryIdentifier | UUID:
    try:
        return UUID(identifier)
    except ValueError:
        return parse_advisory_identifier(AdvisoryIdentifier(identifier))


@router.get("/v1/advisories/{advisory_id}/impact-report", responses=PROBLEMS(401, 404))
def export_advisory_impacts(advisory_id: UUID, exposure: Exposure, _: Caller) -> ImpactExport:
    """Every commit's latest recorded verdicts for the advisory, one row per package and
    installed version, each with its complete document; read from what is kept, never refreshed."""
    return exposure.export_impacts(advisory_id)


@router.get("/v1/advisories/{advisory_id}/impact-inputs", responses=PROBLEMS(401, 404, 422))
def prepare_advisory_impacts(
    advisory_id: UUID, repository_ref_id: UUID, exposure: Exposure, _: Caller
) -> tuple[ImpactInput, ...]:
    """What one commit's analysis would work from, one input per package and installed version
    (the SBOM pass; nothing is recorded)."""
    return exposure.prepare(advisory_id, repository_ref_id)
