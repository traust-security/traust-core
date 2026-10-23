from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.errors import NotFoundError
from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.ledger import LedgerService


def ledger(services: CoreServices) -> LedgerService:
    """The ledger is optional: a deployment without one has no ledger resources."""
    if services.ledger is None:
        raise NotFoundError("this deployment keeps no ledger (no ledger section)")
    return services.ledger


Ledger = Annotated[LedgerService, Depends(ledger)]
