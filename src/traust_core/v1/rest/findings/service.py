from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.findings.service import FindingService


def findings(services: CoreServices) -> FindingService:
    return services.findings


Findings = Annotated[FindingService, Depends(findings)]
