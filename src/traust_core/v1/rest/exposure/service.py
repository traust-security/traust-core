from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.exposure import ExposureService


def exposure(services: CoreServices) -> ExposureService:
    return services.exposure


Exposure = Annotated[ExposureService, Depends(exposure)]
