from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.remediation import FleetFixDiff


# NEED(engine: fleet-fix applier): a fresh https-only clone of the commit, the spec applied
# (`rewrite_pinned_refs` with a `git ls-remote` resolver, or `ast-grep` after its golden tests)
# and `git diff` are subprocesses and network; traust-engine implements this from
# apply_fleet_fix.py and Context registers it. It never commits, forks or opens a PR.
class FleetFixApplier(Protocol):
    """Applies a recorded fleet-fix spec to a clean checkout of one commit; diffs only."""

    def apply(self, spec: FleetFixArtifact, repository_url: str, sha: str) -> FleetFixDiff: ...
