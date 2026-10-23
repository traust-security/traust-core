from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.identity import Principal
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS

router = APIRouter(tags=["identity"])


@router.get("/v1/whoami", responses=PROBLEMS(401))
def whoami(caller: Caller) -> Principal:
    """The verified caller, as the services will see it."""
    return caller
