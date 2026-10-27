from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.assessment import AssessmentService


def assessments(services: CoreServices) -> AssessmentService:
    return services.assessment


Assessments = Annotated[AssessmentService, Depends(assessments)]
