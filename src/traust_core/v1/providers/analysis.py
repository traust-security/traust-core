from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.dependencies import Dependency, ImpactEvidence, ImpactQuery
from traust_core.v1.models.vocabulary import Ecosystem, ImpactTier
from traust_core.v1.providers.base import Readiness, Result
from traust_core.v1.providers.tools import ToolRequest


class DependencyExtractor(Protocol):
    name: str

    def check(self) -> Readiness: ...

    def extract(self, request: ToolRequest) -> Result[list[Dependency]]: ...


class ImpactAnalyzer(Protocol):
    """One analysis tier over a checkout; it fills only the evidence fields it observes."""

    name: str
    tier: ImpactTier
    ecosystems: frozenset[Ecosystem]

    def check(self) -> Readiness: ...

    def evidence(self, query: ImpactQuery, request: ToolRequest) -> Result[ImpactEvidence]: ...
