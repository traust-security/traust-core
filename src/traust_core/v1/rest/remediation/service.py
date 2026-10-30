from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.remediation import RemediationService, VerificationService


def verification(services: CoreServices) -> VerificationService:
    return services.verification


def remediation(services: CoreServices) -> RemediationService:
    return services.remediation


Verifications = Annotated[VerificationService, Depends(verification)]
Remediation = Annotated[RemediationService, Depends(remediation)]
