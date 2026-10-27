from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.remediation import FleetFixDiff


class FleetFixApplier(Protocol):
    """Applies a recorded fleet-fix spec to a clean checkout of one commit; diffs only."""

    def apply(self, spec: FleetFixArtifact, repository_url: str, sha: str) -> FleetFixDiff: ...


class GoldenRunner(Protocol):
    """Runs a spec over one golden fixture alone in a scratch checkout; returns the file after."""

    def after(self, spec: FleetFixArtifact, file: str, before: str) -> str: ...
