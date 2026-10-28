from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pydantic

from traust_core.v1.models.assessment import Threat
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import (
    LIKELIHOOD_FACTORS,
    Disposition,
    Occurrence,
    RatingInputs,
    RiskLevel,
    RiskRating,
)
from traust_core.v1.models.vocabulary import (
    OwaspImpactBasis,
    RiskRatingBand,
    ScannerSeverity,
    Severity,
)

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


# OWASP Risk Rating Methodology (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology,
# CC BY-SA 4.0), reimplemented; CVSS v3 metric tables: build_trends' methodology 1.1.0.
_SEVERITY_TABLE: Mapping[tuple[RiskLevel, RiskLevel], str] = {
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "critical",
    ("medium", "low"): "low",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("low", "low"): "note",
    ("low", "medium"): "low",
    ("low", "high"): "medium",
}
_CVSS_LIKELIHOOD: Mapping[str, Mapping[str, int]] = {
    "AV": {"N": 9, "A": 7, "L": 5, "P": 3},
    "AC": {"L": 9, "H": 3},
    "PR": {"N": 9, "L": 5, "H": 2},
    "UI": {"N": 9, "R": 4},
}
_CVSS_IMPACT: Mapping[str, Mapping[str, int]] = {
    m: {"H": 9, "L": 4, "N": 0} for m in ("C", "I", "A")
}
_DEFAULT_LIKELIHOOD = 4.5
_SEVERITY_IMPACT: Mapping[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFORMATIONAL: 0.0,
}
_KEV_SCORE = 9
_EPSS_BANDS = ((0.5, 9), (0.1, 7), (0.01, 5), (0.0, 2))
# Legacy threat-model labels onto OWASP levels, for ordering unrated threats only.
THREAT_IMPACT_LEVEL: Mapping[str, RiskLevel] = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
    "existential": "high",
}
THREAT_LIKELIHOOD_LEVEL: Mapping[str, RiskLevel] = {
    "very_rare": "low",
    "rare": "low",
    "possible": "medium",
    "likely": "high",
    "almost_certain": "high",
}
_PRECISION = 3


def risk_level(score: float) -> RiskLevel:
    """low below 3, medium below 6, otherwise high."""
    return "low" if score < 3 else "medium" if score < 6 else "high"


def risk_band(impact: RiskLevel, likelihood: RiskLevel) -> RiskRatingBand:
    return RiskRatingBand(_SEVERITY_TABLE[(impact, likelihood)])


def _mean(scores: Sequence[float]) -> float:
    return sum(scores) / len(scores)


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
        """The OWASP rating: from a person's factor scores when given, else derived from the
        CVSS v3 vector (plus KEV / EPSS as one more likelihood factor), else from severity."""
        if (f := inputs.factors) is not None:
            basis = f.impact_basis()
            likelihood = _mean([f.likelihood[n] for n in LIKELIHOOD_FACTORS])
            impact_factors = f.business if basis == "business" else f.technical
            impact = _mean(list(impact_factors.values()))  # type: ignore[union-attr]
            return self._rating(likelihood, impact, basis)
        assert inputs.severity is not None  # RatingInputs needs factors or a severity
        metrics = _cvss_metrics(inputs.cvss_vector)
        likely = [t[metrics[m]] for m, t in _CVSS_LIKELIHOOD.items() if metrics.get(m) in t]
        if (exploited := _exploit_score(inputs.kev, inputs.epss)) is not None:
            likely.append(exploited)
        hurts = [t[metrics[m]] for m, t in _CVSS_IMPACT.items() if metrics.get(m) in t]
        return self._rating(
            _mean(likely) if likely else _DEFAULT_LIKELIHOOD,
            _mean(hurts) if hurts else _SEVERITY_IMPACT[inputs.severity],
            OwaspImpactBasis("technical") if hurts else None,
        )

    def _rating(
        self, likelihood: float, impact: float, basis: OwaspImpactBasis | None
    ) -> RiskRating:
        lk, im = risk_level(likelihood), risk_level(impact)
        return RiskRating(
            likelihood=round(likelihood, _PRECISION),
            likelihood_level=lk,
            impact=round(impact, _PRECISION),
            impact_level=im,
            impact_basis=basis,
            band=risk_band(im, lk),
        )

    def effective_severity(
        self, occurrence: Occurrence | None, disposition: Disposition | None
    ) -> Severity | None:
        """The strongest re-rating, else the latest report's severity."""
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

    def risk_weight(self, occurrence: Occurrence | None, severity: Severity | None) -> float | None:
        """What a finding adds to a risk index: its CVSS score, else its band's midpoint."""
        if occurrence is not None and occurrence.cvss_score is not None:
            return float(occurrence.cvss_score)
        return _BAND_MIDPOINT[severity] if severity is not None else None

    def threat_rating(self, threat: Threat) -> RiskRatingBand:
        """The band a threat's legacy impact and likelihood labels order as: a crosswalk onto
        OWASP levels for ordering, never written back as a rating."""
        return risk_band(
            THREAT_IMPACT_LEVEL[threat.impact], THREAT_LIKELIHOOD_LEVEL[threat.likelihood]
        )


def _cvss_metrics(vector: str | None) -> dict[str, str]:
    if not vector or not vector.startswith("CVSS:3"):
        return {}
    return dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)


def _exploit_score(kev: bool, epss: float | None) -> int | None:
    if kev:
        return _KEV_SCORE
    if epss is None:
        return None
    return next(score for floor, score in _EPSS_BANDS if epss >= floor)
