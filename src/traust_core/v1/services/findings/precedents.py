from __future__ import annotations

from traust_core.v1.models.findings import Decision, FindingCandidate
from traust_core.v1.repositories.findings import FindingUnitOfWork


class FindingPrecedents:
    def __init__(self, uow: FindingUnitOfWork) -> None:
        self._uow = uow

    def match(self, candidate: FindingCandidate) -> list[Decision]:
        raise NotImplementedError("stub: replaces corpus/precedent.py, compile_precedent_cards.py")
