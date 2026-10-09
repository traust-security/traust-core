from __future__ import annotations

from collections.abc import Sequence

from tests.v1.example.continuous_ops.model import ObserveStatus, RepoState
from traust_core.v1.models.operations import Refusal, Route


class RepoRouter:
    def route(self, state: RepoState, events: Sequence[str], refusals: Sequence[Refusal]) -> Route:
        if state.status is not ObserveStatus.OK:
            return Route(lane=None, priority=0, reason=f"not observable: {state.status}")
        if state.audited_head is None:
            return Route(lane="full-audit", priority=10, reason="never audited")
        if not state.changed_since_audit:
            return Route(lane=None, priority=0, reason="unchanged since audit")
        if "diff-scan" in {r.lane for r in refusals if r.subject == str(state.repo)}:
            return Route(lane="full-audit", priority=5, reason="diff-scan refused before")
        return Route(lane="diff-scan", priority=5, reason="changed since audit")
