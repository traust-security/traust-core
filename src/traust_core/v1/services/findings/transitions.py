from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from traust_core.v1.models.findings import Decision, Disposition


class TransitionPolicy:
    def allow(self, current: Disposition, decision: Decision) -> None:
        raise NotImplementedError("stub: replaces traust-ledger _internal/gates.py")

    def fold(self, finding_id: UUID, decisions: Sequence[Decision]) -> Disposition:
        raise NotImplementedError(
            "stub: replaces traust-ledger _internal/disposition.py, corpus/disposition.py"
        )
