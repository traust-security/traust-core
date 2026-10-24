from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pydantic

from traust_core.v1.models.assessment import Threat
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import Disposition, Occurrence, RatingInputs, RiskRating
from traust_core.v1.models.vocabulary import RiskRatingBand, ScannerSeverity, Severity

_DEFAULT_RESOLVE_DAYS: Mapping[Severity, int | None] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 60,
    Severity.MEDIUM: 90,
    Severity.LOW: None,
}
# CVSS v3 band midpoints for a finding its report gave no score (build_trends' risk index).
_BAND_MIDPOINT: Mapping[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.0,
    Severity.INFORMATIONAL: 0.0,
}


class CvssFloor(Model):
    """Any finding at or above `threshold` CVSS gets `resolve_days`, whatever its severity."""

    threshold: Decimal
    resolve_days: int


class SlaConfig(Model):
    """Days to resolve per severity; a severity mapped to None, or not listed, has no deadline."""

    resolve_days: Mapping[Severity, int | None] = pydantic.Field(
        default_factory=lambda: dict(_DEFAULT_RESOLVE_DAYS)
    )
    cvss_floor: CvssFloor | None = None


class RatingConfig(Model):
    sla: SlaConfig = SlaConfig()


class RatingPolicy:
    def __init__(self, config: RatingConfig) -> None:
        self._config = config

    def rate(self, inputs: RatingInputs) -> RiskRating:
        raise NotImplementedError("stub: replaces contracts risk_rating.py, build_trends ratings")

    def effective_severity(
        self, occurrence: Occurrence | None, disposition: Disposition | None
    ) -> Severity | None:
        """The latest re-rating, else the latest report's severity (the finding_status view)."""
        if disposition is not None and disposition.severity is not None:
            return disposition.severity
        if occurrence is None or occurrence.severity == ScannerSeverity.UNRATED:
            return None
        return Severity(occurrence.severity)

    def sla_due(
        self, severity: Severity | None, opened_at: datetime, cvss_score: Decimal | None = None
    ) -> datetime | None:
        """When the finding must be resolved by, or None when this severity has no deadline."""
        opened_at = opened_at.astimezone(UTC)
        sla = self._config.sla
        floor = sla.cvss_floor
        if floor is not None and cvss_score is not None and cvss_score >= floor.threshold:
            return opened_at + timedelta(days=floor.resolve_days)
        days = sla.resolve_days.get(severity)
        return None if days is None else opened_at + timedelta(days=days)

    def risk_weight(self, occurrence: Occurrence | None, severity: Severity) -> float:
        """What a finding adds to a risk index: its CVSS score, else its band's midpoint."""
        if occurrence is not None and occurrence.cvss_score is not None:
            return float(occurrence.cvss_score)
        return _BAND_MIDPOINT[severity]

    def threat_rating(self, threat: Threat) -> RiskRatingBand:
        raise NotImplementedError("stub: replaces reporting/threat_rating.py")
