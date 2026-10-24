"""RatingPolicy.rate and threat_rating, ported from traust-contracts tests/test_risk_rating.py
(the OWASP worked example), traust build_trends.owasp_rating and traust-engine
tests/test_threat_rating.py (the legacy crosswalk)."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.models.assessment import Threat
from traust_core.v1.models.findings import (
    BUSINESS_IMPACT_FACTORS,
    LIKELIHOOD_FACTORS,
    TECHNICAL_IMPACT_FACTORS,
    OwaspFactors,
    RatingInputs,
)
from traust_core.v1.services.findings.rating import (
    RatingConfig,
    RatingPolicy,
    risk_band,
    risk_level,
)

POLICY = RatingPolicy(RatingConfig())
L = dict(zip(LIKELIHOOD_FACTORS, [5, 2, 7, 1, 3, 6, 9, 2], strict=True))
T = dict(zip(TECHNICAL_IMPACT_FACTORS, [9, 7, 5, 8], strict=True))
B = dict(zip(BUSINESS_IMPACT_FACTORS, [1, 2, 1, 5], strict=True))


@pytest.mark.parametrize(
    ("factors", "want"),
    [
        ({}, (4.375, "medium", 7.25, "high", "technical", "high")),
        ({"business": B}, (4.375, "medium", 2.25, "low", "business", "low")),
        (
            {"business": B, "basis": "technical"},
            (4.375, "medium", 7.25, "high", "technical", "high"),
        ),
    ],
    ids=["technical", "business-preferred", "technical-chosen"],
)
def test_owasp_worked_example(factors: dict[str, Any], want: tuple[Any, ...]) -> None:
    r = POLICY.rate(
        RatingInputs(severity="low", factors=OwaspFactors(likelihood=L, technical=T, **factors))
    )
    assert (
        r.likelihood,
        r.likelihood_level,
        r.impact,
        r.impact_level,
        r.impact_basis,
        r.band,
    ) == want


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"likelihood": {**L, "motive": 10}}, "0 to 9"),
        ({"likelihood": {**L, "motive": -1}}, "0 to 9"),
        (
            {"likelihood": {k: v for k, v in L.items() if k != "awareness"}},
            "missing factors ['awareness']",
        ),
        ({"technical": {**T, "extra": 1}}, "unknown factors ['extra']"),
        ({"basis": "business"}, "needs its factor set"),
    ],
)
def test_factors_are_complete_and_in_range(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        OwaspFactors(**{"likelihood": L, "technical": T, **changes})


@pytest.mark.parametrize(
    ("inputs", "band", "likelihood", "impact"),
    [
        (
            {"severity": "high", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "critical",
            9.0,
            9.0,
        ),
        (
            {"severity": "high", "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
            "low",
            3.0,
            1.333,
        ),
        (
            {
                "severity": "high",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                "kev": True,
            },
            "low",
            4.6,
            1.333,
        ),
        (
            {
                "severity": "high",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H",
                "epss": 0.2,
            },
            "high",
            4.2,
            9.0,
        ),
        (
            {
                "severity": "high",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H",
                "epss": 0.0,
            },
            "high",
            3.2,
            9.0,
        ),
        ({"severity": "critical"}, "high", 4.5, 9.0),
        ({"severity": "informational"}, "low", 4.5, 0.0),
        ({"severity": "medium", "cvss_vector": "CVSS:2.0/AV:N/AC:L"}, "medium", 4.5, 5.0),
        ({"severity": "low", "kev": True}, "medium", 9.0, 2.0),
    ],
    ids=[
        "all-high",
        "physical-low",
        "kev",
        "epss-0.1",
        "epss-floor",
        "severity-only",
        "info",
        "cvss2-ignored",
        "kev-no-vector",
    ],
)
def test_rating_from_cvss_and_exploit_signals(
    inputs: dict[str, Any], band: str, likelihood: float, impact: float
) -> None:
    r = POLICY.rate(RatingInputs(**inputs))
    assert (r.band, r.likelihood, r.impact) == (band, likelihood, impact)


@pytest.mark.parametrize(
    ("score", "want"),
    [(0, "low"), (2.999, "low"), (3, "medium"), (5.999, "medium"), (6, "high"), (9, "high")],
)
def test_level_boundaries(score: float, want: str) -> None:
    assert risk_level(score) == want


@pytest.mark.parametrize(
    ("impact", "likelihood", "want"),
    [
        ("high", "low", "medium"),
        ("high", "medium", "high"),
        ("high", "high", "critical"),
        ("medium", "low", "low"),
        ("medium", "medium", "medium"),
        ("medium", "high", "high"),
        ("low", "low", "note"),
        ("low", "medium", "low"),
        ("low", "high", "medium"),
    ],
)
def test_severity_table(impact: Any, likelihood: Any, want: str) -> None:
    assert risk_band(impact, likelihood) == want


@pytest.mark.parametrize(
    ("impact", "likelihood", "want"),
    [
        ("existential", "almost_certain", "critical"),
        ("critical", "likely", "critical"),
        ("high", "possible", "high"),
        ("medium", "possible", "medium"),
        ("low", "very_rare", "note"),
        ("existential", "rare", "medium"),
    ],
)
def test_threat_labels_cross_walk_onto_owasp(impact: str, likelihood: str, want: str) -> None:
    threat = Threat(
        assessment_id=uuid4(),
        label="T1",
        title="Example threat",
        status="unmitigated",
        actor="remote_unauth",
        likelihood=likelihood,
        impact=impact,
    )
    assert POLICY.threat_rating(threat) == want
