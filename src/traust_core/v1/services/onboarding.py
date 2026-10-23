from __future__ import annotations

from traust_core.v1.models.identity import Principal
from traust_core.v1.models.onboarding import OnboardingPlan, OnboardingRequest, OnboardingResult
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import PortfolioService, PortfolioSync
from traust_core.v1.services.provider_catalog import ProviderCatalog


class OnboardingService:
    def __init__(
        self,
        portfolio: PortfolioService,
        sync: PortfolioSync,
        providers: ProviderCatalog,
        ops: OpsService,
    ) -> None:
        self._portfolio = portfolio
        self._sync = sync
        self._providers = providers
        self._ops = ops

    def plan(self, request: OnboardingRequest) -> OnboardingPlan:
        raise NotImplementedError("stub: replaces corpus_intake.validate_new / drift")

    def onboard(self, request: OnboardingRequest, principal: Principal) -> OnboardingResult:
        raise NotImplementedError("stub: replaces corpus-intake, add-inputs skill flows")
