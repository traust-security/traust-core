from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.dependencies import Ecosystem, Package, RefDependency
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.exposure.service import Exposure

router = APIRouter()


@router.get("/v1/packages", responses=PROBLEMS(401, 404, 422))
def find_package(
    exposure: Exposure,
    _: Caller,
    ecosystem: Ecosystem,
    name: Annotated[str, Query(min_length=1, max_length=256)],
) -> Package:
    """One package by ecosystem and name (ecosystem-normalised); 404 when none is recorded."""
    found = exposure.find_package(ecosystem, name)
    if found is None:
        raise NotFoundError(f"no {ecosystem} package named {name!r}")
    return found


@router.get("/v1/packages/{package_id}/dependents", responses=PROBLEMS(401, 404))
def dependents(
    package_id: UUID,
    exposure: Exposure,
    _: Caller,
    version: Annotated[str | None, Query(max_length=256)] = None,
) -> list[UUID]:
    """The commits whose SBOMs hold the package (at `version` when given); 404 for an unknown id."""
    return exposure.dependents(package_id, version)


@router.get("/v1/refs/{repository_ref_id}/dependencies", responses=PROBLEMS(401, 404))
def dependencies(repository_ref_id: UUID, exposure: Exposure, _: Caller) -> list[RefDependency]:
    """The packages in the ref's manifest SBOM; 404 when none is ingested (never read as empty)."""
    return exposure.dependencies(repository_ref_id)
