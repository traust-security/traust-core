from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.providers.model_catalog import RoleRouting
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.registry.service import Models

router = APIRouter()


@router.get("/v1/registry/resolve", responses=PROBLEMS(401, 404, 422))
def resolve_role(role: str, _: Caller, models: Models, tier: str | None = None) -> RoleRouting:
    """The routing a role resolves to: its model, the provider section listing it and that
    provider's connection (wire, endpoint, harness, credential source) — what an executor
    delivers to its worker, the same resolved routing the in-process callers get."""
    return models.resolve_routing(role, tier)
