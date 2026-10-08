from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.models.portfolio import (
    CodeLine,
    Designation,
    ExposureClass,
    Repository,
    RiskTier,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.repositories.portfolio import PortfolioUnitOfWork


class PortfolioPolicy:
    def exposure_class(
        self, designation: Designation | None, public: bool | None, public_upstream: bool | None
    ) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def risk_tier(self, open_critical_high: int, archived: bool, dormant: bool) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")


class PortfolioService:
    def __init__(self, uow: PortfolioUnitOfWork, policy: PortfolioPolicy) -> None:
        self._uow = uow
        self._policy = policy

    def register_repository(self, url: HttpsRepoUrl, product: str) -> Repository:
        raise NotImplementedError("stub: replaces corpus_intake.py, inventory.py")

    def register_code_line(self, repository_id: UUID, ref: str) -> CodeLine:
        raise NotImplementedError("stub: replaces product_repo (product, repo, ref) rows")

    def set_owner(self, repository_id: UUID, team: str) -> None:
        raise NotImplementedError("stub: replaces fetch_forge_owners.py")

    def designation(self, repository_id: UUID) -> Designation | None:
        raise NotImplementedError("stub: replaces build_rescan_worklist.lookup_designation")

    def record_liveness(
        self, repository_id: UUID, archived: bool, pushed_at: datetime | None
    ) -> None:
        raise NotImplementedError("stub: replaces check_repo_liveness.py")

    def exposure(self, repository_id: UUID) -> ExposureClass:
        raise NotImplementedError("stub: replaces build_rescan_worklist.exposure_class")

    def risk_tier(self, repository_id: UUID, open_critical_high: int) -> RiskTier:
        raise NotImplementedError("stub: replaces build_rescan_worklist.risk_tier")

    def by_org(self, org: str) -> list[Repository]:
        raise NotImplementedError("stub: replaces build_org_index.py")
