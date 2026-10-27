from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.portfolio import PortfolioService


def portfolio(services: CoreServices) -> PortfolioService:
    return services.portfolio


Portfolio = Annotated[PortfolioService, Depends(portfolio)]
