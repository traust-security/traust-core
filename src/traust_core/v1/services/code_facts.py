from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.code_facts import CodeFact
from traust_core.v1.models.operations import JobResult
from traust_core.v1.repositories.code_facts import CodeFactsUnitOfWork


class CodeFactsService:
    def __init__(self, uow: CodeFactsUnitOfWork) -> None:
        self._uow = uow

    def enumerate(self, revision_id: UUID, kinds: Sequence[str]) -> JobResult:
        raise NotImplementedError(
            "stub: replaces secure-code-audit enumerators, enumerate_taint_flows.py"
        )

    def symbol(self, revision_id: UUID, name: str) -> list[CodeFact]:
        raise NotImplementedError("stub: replaces build_symbol_index.py, query_index.py")
