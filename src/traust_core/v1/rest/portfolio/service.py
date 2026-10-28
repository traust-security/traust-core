from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from traust_core.v1.rest.common.deps import CoreServices
from traust_core.v1.services.onboarding import OnboardingService
from traust_core.v1.services.portfolio import PortfolioService


def portfolio(services: CoreServices) -> PortfolioService:
    return services.portfolio


def onboarding(services: CoreServices) -> OnboardingService:
    return services.onboarding


Portfolio = Annotated[PortfolioService, Depends(portfolio)]
Onboarding = Annotated[OnboardingService, Depends(onboarding)]
