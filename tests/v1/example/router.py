from __future__ import annotations

from collections.abc import Sequence

from tests.v1.example.model import Task, TaskStatus
from traust_core.v1.models.operations import Refusal, Route


class TaskRouter:
    MAX_ATTEMPTS = 3

    def route(self, state: Task, events: Sequence[str], refusals: Sequence[Refusal]) -> Route:
        refused = {r.lane for r in refusals if r.subject == state.task_id}
        if state.status is TaskStatus.DONE:
            return Route(lane=None, priority=0, reason="done")
        if (state.attempts or 0) >= self.MAX_ATTEMPTS:
            return Route(lane="manual-review", priority=1, reason="too many attempts")
        if "retry" in refused:
            return Route(lane=None, priority=0, reason="refused in retry lane")
        return Route(lane="retry", priority=10 - (state.attempts or 0), reason="queued")
