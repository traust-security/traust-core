from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter

from traust_core.v1.models.ledger import Checkpoint
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.ledger.service import Ledger

router = APIRouter()


@router.post(
    "/v1/repositories/{repository_id}/ledger/checkpoint", responses=PROBLEMS(401, 403, 404, 500)
)
def checkpoint(repository_id: UUID, ledger: Ledger, caller: Caller) -> Checkpoint:
    """Restamp and sign the repository's layer (admins), e.g. once a signing key is configured."""
    return ledger.checkpoint(repository_id, caller)
