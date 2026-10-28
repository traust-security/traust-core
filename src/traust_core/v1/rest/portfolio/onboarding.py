from __future__ import annotations

from fastapi import APIRouter

from traust_core.v1.models.onboarding import OnboardingPlan, OnboardingRequest, OnboardingResult
from traust_core.v1.rest.common.deps import Caller
from traust_core.v1.rest.common.problems import PROBLEMS
from traust_core.v1.rest.portfolio.service import Onboarding

router = APIRouter()


@router.post("/v1/onboarding", responses=PROBLEMS(401, 422))
def onboard(request: OnboardingRequest, onboarding: Onboarding, caller: Caller) -> OnboardingResult:
    """Add inventory: register the product and its repositories (refs, teams) and plan the
    baseline orders. Re-running is a no-op apart from refs whose branch moved."""
    return onboarding.onboard(request, caller)


@router.post("/v1/onboarding/plan", responses=PROBLEMS(401, 422))
def plan_onboarding(
    request: OnboardingRequest, onboarding: Onboarding, _: Caller
) -> OnboardingPlan:
    """What `onboard` would do, writing nothing (dry run): new vs existing repos, gaps, orders."""
    return onboarding.plan(request)
