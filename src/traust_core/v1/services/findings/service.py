from __future__ import annotations

from traust_core.v1.repositories.findings import FindingUnitOfWork
from traust_core.v1.services.findings.decisions import FindingDecisions
from traust_core.v1.services.findings.identity import IdentityPolicy
from traust_core.v1.services.findings.intake import FindingIntake
from traust_core.v1.services.findings.precedents import FindingPrecedents
from traust_core.v1.services.findings.rating import RatingPolicy
from traust_core.v1.services.findings.review import FindingReview
from traust_core.v1.services.findings.transitions import TransitionPolicy


class FindingService:
    def __init__(self, uow: FindingUnitOfWork) -> None:
        self.identity = IdentityPolicy()
        self.transitions = TransitionPolicy()
        self.rating = RatingPolicy()
        self.intake = FindingIntake(uow, self.identity)
        self.decisions = FindingDecisions(uow, self.transitions)
        self.review = FindingReview(uow)
        self.precedents = FindingPrecedents(uow)
