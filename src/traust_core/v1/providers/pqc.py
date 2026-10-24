from __future__ import annotations

from typing import Protocol

from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.pqc import PqcScan, PqcStamps
from traust_core.v1.providers.base import Readiness, Result


# NEED(engine: pqc-scan provider): the pinned pqc-scan binary over the merged rules pack
# (vendored + HP supplement) is a subprocess; traust-engine implements this from
# pqc_facts.run_scanner / rules_pack_sha and Context registers it.
class PqcScanner(Protocol):
    """The pinned Layer-1 scanner: raw rule hits over a checkout, stamped with its pack."""

    name: str

    def check(self) -> Readiness: ...

    def stamps(self) -> PqcStamps:
        """What a scan by the current binary and rules pack would be stamped with."""
        ...

    def scan(self, request: ToolRequest) -> Result[PqcScan]: ...
