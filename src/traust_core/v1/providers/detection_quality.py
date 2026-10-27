from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.detection_quality import CanaryRepo, CanarySource, RulePack
from traust_core.v1.providers.base import Readiness


class RulePackSource(Protocol):
    """The rule packs a deployment scans with: rules are a swappable input, never vendored."""

    name: str

    def check(self) -> Readiness: ...

    def packs(self) -> list[RulePack]: ...


class CanaryMaterializer(Protocol):
    """Canary sources and the deterministic local repositories they are committed into."""

    name: str

    def check(self) -> Readiness: ...

    def sources(self) -> list[CanarySource]: ...

    def materialize(self, source: CanarySource) -> CanaryRepo: ...
