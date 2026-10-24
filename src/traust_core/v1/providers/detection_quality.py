from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.detection_quality import CanaryRepo, CanarySource, RulePack
from traust_core.v1.providers.base import Readiness


# NEED(engine: rule-pack source): the bundled opengrep pack (or locations.opengrep_rules) plus
# rule-pack-allowlist supplements, read as rule ids with their languages and metadata CWEs
# (from traust-engine adapters/opengrep.resolve_rule_pack_dir); Context registers it.
class RulePackSource(Protocol):
    """The rule packs a deployment scans with: rules are a swappable input, never vendored."""

    name: str

    def check(self) -> Readiness: ...

    def packs(self) -> list[RulePack]: ...


# NEED(engine: canary materialiser): reads canary and seeded-fixture sources ({canary,seed}.yaml
# + tree/) from the config home and commits each tree into a local git repository with a fixed
# author and date, unsigned (from traust recall-benchmark build_canaries.materialize).
class CanaryMaterializer(Protocol):
    """Canary sources and the deterministic local repositories they are committed into."""

    name: str

    def check(self) -> Readiness: ...

    def sources(self) -> list[CanarySource]: ...

    def materialize(self, source: CanarySource) -> CanaryRepo: ...
