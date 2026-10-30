from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.insight import InsightService


def insight(services: CoreServices) -> InsightService:
    return services.insight


Insight = Annotated[InsightService, Depends(insight)]
