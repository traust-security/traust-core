"""RatingPolicy: effective severity (the finding_status rule) and SLA deadlines, ported from
traust-engine metrics/sla.py resolve_days_for at 435225b."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from traust_core.v1.models.findings import Disposition, Occurrence
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.services.findings.rating import (
    CvssFloor,
    DowngradeDocumentation,
    RatingConfig,
    RatingPolicy,
    SlaConfig,
    cvss_band,
    severity_cvss_diagnostic,
)

T0 = datetime(2026, 10, 1, tzinfo=UTC)
DEFAULT = RatingPolicy(RatingConfig())


def occurrence(severity: str = "high") -> Occurrence:
    return Occurrence(finding_id=uuid4(), assessment_id=uuid4(), severity=severity)


def disposition(severity: Severity | None) -> Disposition:
    return Disposition(
        finding_id=uuid4(), assurance=DispositionAssurance.CLAIMED, severity=severity
    )


def test_a_re_rating_wins_over_the_report() -> None:
    assert DEFAULT.effective_severity(occurrence("high"), disposition(Severity.LOW)) is Severity.LOW


@pytest.mark.parametrize("judged", [None, disposition(None)])
def test_without_a_re_rating_the_report_rates_it(judged: Disposition | None) -> None:
    assert DEFAULT.effective_severity(occurrence("critical"), judged) is Severity.CRITICAL


def test_a_re_rating_alone_is_enough() -> None:
    assert DEFAULT.effective_severity(None, disposition(Severity.MEDIUM)) is Severity.MEDIUM


@pytest.mark.parametrize("reported", [None, occurrence("unrated")])
def test_missing_or_unrated_observation_stays_unknown_until_a_human_rates_it(
    reported: Occurrence | None,
) -> None:
    assert DEFAULT.effective_severity(reported, None) is None
    assert DEFAULT.effective_severity(reported, disposition(Severity.MEDIUM)) is Severity.MEDIUM


@pytest.mark.parametrize(
    ("severity", "days"),
    [
        (Severity.CRITICAL, 30),
        (Severity.HIGH, 60),
        (Severity.MEDIUM, 90),
        (Severity.LOW, None),
        (Severity.INFORMATIONAL, None),
    ],
)
def test_default_deadlines(severity: Severity, days: int | None) -> None:
    due = DEFAULT.sla_due(severity, T0)
    assert due == (None if days is None else T0 + timedelta(days=days))


FLOORED = RatingPolicy(
    RatingConfig(
        sla=SlaConfig(
            resolve_days={Severity.MEDIUM: 90},
            cvss_floor=CvssFloor(threshold=Decimal("4.0"), resolve_days=30),
        )
    )
)


@pytest.mark.parametrize(
    ("severity", "cvss", "days"),
    [
        (Severity.LOW, Decimal("4.0"), 30),
        (Severity.MEDIUM, Decimal("9.8"), 30),
        (Severity.MEDIUM, Decimal("3.9"), 90),
        (Severity.MEDIUM, None, 90),
        (Severity.HIGH, None, None),
    ],
)
def test_cvss_floor_overrides_severity_at_or_above_the_threshold(
    severity: Severity, cvss: Decimal | None, days: int | None
) -> None:
    due = FLOORED.sla_due(severity, T0, cvss)
    assert due == (None if days is None else T0 + timedelta(days=days))


@pytest.mark.parametrize(
    ("policy", "severity", "days"),
    [(DEFAULT, Severity.HIGH, 60), (FLOORED, Severity.LOW, 30)],
)
def test_deadlines_preserve_elapsed_days_across_a_daylight_saving_transition(
    policy: RatingPolicy,
    severity: Severity,
    days: int,
) -> None:
    opened = datetime(2026, 10, 15, 12, tzinfo=UTC)
    local = opened.astimezone(ZoneInfo("America/New_York"))
    assert policy.sla_due(severity, local, Decimal("9.0")) == opened + timedelta(days=days)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("0", "informational"),
        ("0.1", "low"),
        ("3.9", "low"),
        ("4", "medium"),
        ("6.9", "medium"),
        ("7", "high"),
        ("8.9", "high"),
        ("9", "critical"),
        ("10", "critical"),
    ],
)
def test_cvss_banding_uses_the_qualitative_boundaries(score: str, expected: str) -> None:
    assert cvss_band(Decimal(score)) == expected


@pytest.mark.parametrize(
    ("severity", "score", "rationale", "expected"),
    [
        ("low", "7", "", (2, False, "undocumented")),
        ("medium", "9", "Deployment context limits the exposed path.", (2, False, "documented")),
        ("informational", "0", "", (0, True, "undocumented")),
        ("informational", "3.9", "Contextual downgrade.", (1, True, "documented")),
        (
            "low",
            "8.1",
            "An input flaw reachable from the query handler.",
            (2, False, "undocumented"),
        ),
        ("low", "8.1", "The sink is not attacker-reachable.", (2, False, "documented")),
        ("low", "8.1", "The vulnerable operation is unreachable.", (2, False, "documented")),
        ("medium", "8.9", "", None),
        ("high", "4", "", None),
        ("unrated", "9.8", "", None),
        (None, "9.8", "", None),
        ("low", None, "", None),
    ],
)
def test_diagnostic_distinguishes_contextual_downgrades_and_scored_informationals(
    severity: str | None,
    score: str | None,
    rationale: str,
    expected: tuple[int, bool, str] | None,
) -> None:
    diagnostic = severity_cvss_diagnostic(
        severity, None if score is None else Decimal(score), rationale
    )
    if expected is None:
        assert diagnostic is None
    else:
        assert diagnostic is not None
        assert (
            diagnostic.bands_below,
            diagnostic.scored_informational,
            diagnostic.documentation,
        ) == (*expected[:2], DowngradeDocumentation(expected[2]))
