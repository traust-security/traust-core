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
from traust_core.v1.services.findings.rating import CvssFloor, RatingConfig, RatingPolicy, SlaConfig

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
