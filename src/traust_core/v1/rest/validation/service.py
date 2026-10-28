from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.validation import ValidationService


def validation(services: CoreServices) -> ValidationService:
    return services.validation


Validation = Annotated[ValidationService, Depends(validation)]
