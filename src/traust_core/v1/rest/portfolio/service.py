from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.identity import Principal
from traust_core.v1.rest.common.deps import Caller, CoreServices
from traust_core.v1.services.onboarding import OnboardingService
from traust_core.v1.services.portfolio import PortfolioService


def portfolio(services: CoreServices) -> PortfolioService:
    return services.portfolio


def onboarding(services: CoreServices) -> OnboardingService:
    return services.onboarding


def person(caller: Caller) -> Principal:
    """The repository doors that act on a disposition are a person's (foundry plan
    repo-unreachable: the disposition is user-removable only, so the verify that clears
    it and the URL correction that repoints identity are never a machine's)."""
    if not caller.is_verified_human():
        raise ForbiddenError(f"repository care is a person's; {caller.ref} is not one")
    return caller


Portfolio = Annotated[PortfolioService, Depends(portfolio)]
Onboarding = Annotated[OnboardingService, Depends(onboarding)]
Person = Annotated[Principal, Depends(person)]
