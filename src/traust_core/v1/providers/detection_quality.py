from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

from traust_core.v1.models.detection_quality import CanaryRepo, CanarySource, RulePack
from traust_core.v1.models.rule_mining import RepoSweep, RuleFile, SweepRepo
from traust_core.v1.providers.base import Readiness


class RulePackSource(Protocol):
    """The rule packs a deployment scans with: rules are a swappable input, never vendored."""

    name: str

    def check(self) -> Readiness: ...

    def packs(self) -> list[RulePack]: ...

    def cached(self, name: str, source: str) -> RulePack | None: ...


class CanaryMaterializer(Protocol):
    """Canary sources and the deterministic local repositories they are committed into."""

    name: str

    def check(self) -> Readiness: ...

    def sources(self) -> list[CanarySource]: ...

    def materialize(self, source: CanarySource) -> CanaryRepo: ...


class RuleSweeper(Protocol):
    """One rule over one repository at a time, in a work root the sweep holds for its run."""

    name: str

    def check(self, binary: str) -> Readiness: ...

    def workspace(self, work_dir: Path | None) -> AbstractContextManager[Path]: ...

    def scan(
        self, repo: SweepRepo, rule: RuleFile, work: Path, binary: str, timeout: int
    ) -> RepoSweep: ...

    def trial(
        self, rule: str, target: Path | Mapping[str, str], binary: str, timeout: int
    ) -> RepoSweep: ...
