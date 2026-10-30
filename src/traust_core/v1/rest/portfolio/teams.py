from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter

from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Portfolio

router = APIRouter()


@router.get("/v1/teams/{team_id}/repositories", responses=PROBLEMS(401, 404))
def list_owned_repositories(
    team_id: UUID, portfolio: Portfolio, _: Caller, as_of: datetime | None = None
) -> list[UUID]:
    """The repositories the team owns now, or at `as_of`."""
    return portfolio.list_owned_repositories(team_id, as_of)
