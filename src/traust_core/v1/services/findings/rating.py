from __future__ import annotations

from datetime import datetime

from traust_core.v1.models.artifacts import Severity
from traust_core.v1.models.findings import Finding


class RatingPolicy:
    def severity(self, finding: Finding) -> Severity:  # type: ignore[valid-type]
        raise NotImplementedError("stub: replaces threat_rating.py, contracts risk_rating.py")

    def sla_due(self, finding: Finding, opened_at: datetime) -> datetime:
        raise NotImplementedError("stub: replaces metrics/sla.py")
