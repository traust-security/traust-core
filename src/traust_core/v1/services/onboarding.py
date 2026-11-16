from __future__ import annotations

import logging
from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.onboarding import (
    Gap,
    OnboardingPlan,
    OnboardingRequest,
    OnboardingResult,
    PlannedOrder,
    RepositorySpec,
)
from traust_core.v1.models.operations import OrderRequest
from traust_core.v1.providers.clock import Clock, SystemClock
from traust_core.v1.services.operations import OpsService
from traust_core.v1.services.portfolio import PortfolioService, PortfolioSync

log = logging.getLogger(__name__)


class OnboardingService:
    """Brings a product and its repositories under the platform; progress is the baseline
    orders' state in OpsService."""

    def __init__(
        self,
        portfolio: PortfolioService,
        sync: PortfolioSync,
        ops: OpsService,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._portfolio = portfolio
        self._sync = sync
        self._ops = ops
        self._clock = clock or SystemClock()

    def plan(self, request: OnboardingRequest) -> OnboardingPlan:
        """What `onboard` would do, writing nothing."""
        specs = self._specs(request)
        known = {str(s.url): self._portfolio.find_repository(s.url) for s in specs}
        return OnboardingPlan(
            new=tuple(s for s in specs if known[str(s.url)] is None),
            existing_repository_ids=tuple(r.id for r in known.values() if r and r.id),
            gaps=self._gaps(request),
            orders=tuple(
                PlannedOrder(asset=a, repo=s.url) for s in specs for a in request.baseline
            ),
        )

    def onboard(self, request: OnboardingRequest, principal: Principal) -> OnboardingResult:
        """Register the product and repositories (refs, teams), then plan the baseline orders.
        Re-running is a no-op apart from refs whose branch has moved."""
        if gaps := self._gaps(request):
            raise ValidationError("; ".join(f"{g.subject}: {g.reason}" for g in gaps))
        product = self._portfolio.find_product(request.product)
        if product is None:
            assert request.label is not None
            product = self._portfolio.register_product(request.product, request.label)
        onboarded = [self._onboard_repository(spec) for spec in self._specs(request)]
        repository_ids = [repository_id for repository_id, _ in onboarded]
        orders = [
            self._ops.plan(
                OrderRequest(asset=asset, priority=0, repository_id=repository_id), principal
            )
            for repository_id in self._active(repository_ids)
            for asset in request.baseline
        ]
        assert product.id is not None
        return OnboardingResult(
            product_id=product.id,
            repository_ids=tuple(repository_ids),
            order_ids=tuple(o.id for o in orders if o.id),
            skipped=tuple(why for _, skipped in onboarded for why in skipped),
        )

    def _active(self, repository_ids: Sequence[UUID]) -> list[UUID]:
        """The repositories still in the planner's universe: a repository carrying the
        unreachable disposition (foundry plan repo-unreachable) is planned nothing by
        onboarding either — the collector re-registering a vacated URL must not
        re-enter it through the baseline (Qodo #474). Its disposition stays until a
        person's verify clears it."""
        active = []
        for repository in self._portfolio.inventory.list_repositories(repository_ids):
            if repository.id is not None and repository.disposition is None:
                active.append(repository.id)
        return active

    def _onboard_repository(self, spec: RepositorySpec) -> tuple[UUID, tuple[str, ...]]:
        """The repository's id, and what its import couldn't refresh."""
        report = self._sync.import_repository(spec.url)
        repository_id = (*report.added, *report.unchanged)[0]
        if report.skipped:
            log.warning(
                "onboarding repository %s: forge facts not refreshed (%d)",
                repository_id,
                len(report.skipped),
            )
        for ref in spec.refs:
            self._sync.import_branch(repository_id, spec.url, ref)
        if spec.team is not None:
            self._portfolio.assign_owner(repository_id, spec.team, self._clock.now())
        return repository_id, report.skipped

    def _specs(self, request: OnboardingRequest) -> list[RepositorySpec]:
        """The repositories named, then the organisation's others; one spec per URL."""
        listed = [] if request.org is None else self._sync.list_org(request.org, request.host)
        specs: dict[str, RepositorySpec] = {}
        for spec in (*request.repositories, *(RepositorySpec(url=i.repo) for i in listed)):
            specs.setdefault(str(spec.url), spec)
        return list(specs.values())

    def _gaps(self, request: OnboardingRequest) -> tuple[Gap, ...]:
        if request.label or self._portfolio.find_product(request.product) is not None:
            return ()
        reason = "product is not registered: give a label to register it"
        return (Gap(subject=str(request.product), reason=reason),)
