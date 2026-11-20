"""RatingPolicy: effective severity (the finding_status rule) and SLA deadlines, ported from
traust-engine metrics/sla.py resolve_days_for at 435225b."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from traust_core.v1.models.cvss import severity_of
from traust_core.v1.models.findings import Disposition, Occurrence
from traust_core.v1.models.vocabulary import DispositionAssurance, Severity
from traust_core.v1.services.findings.rating import (
    CvssFloor,
    RatingConfig,
    RatingPolicy,
    SeverityLabel,
    SlaConfig,
)

T0 = datetime(2026, 10, 1, tzinfo=UTC)
DEFAULT = RatingPolicy(RatingConfig())


def occurrence(severity: str = "high", vector: str | None = None) -> Occurrence:
    return Occurrence(
        finding_id=uuid4(), assessment_id=uuid4(), severity=severity, cvss_vector=vector
    )


def disposition(severity: Severity | None) -> Disposition:
    return Disposition(
        finding_id=uuid4(), assurance=DispositionAssurance.CLAIMED, severity=severity
    )


def test_a_re_rating_beats_the_scanner_word_for_an_unscored_finding() -> None:
    assert DEFAULT.effective_severity(occurrence("high"), disposition(Severity.LOW)) is Severity.LOW


@pytest.mark.parametrize(
    ("vector", "band"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Severity.HIGH),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", Severity.MEDIUM),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", Severity.LOW),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Severity.INFORMATIONAL),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Severity.CRITICAL),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", Severity.INFORMATIONAL),
    ],
)
def test_the_band_is_firsts_whatever_any_word_says(vector: str, band: Severity) -> None:
    # no word — the scanner's or a judgement's — moves a scored finding off its vector's band
    lying = occurrence("informational", vector=vector)
    judged = disposition(Severity.LOW)
    assert DEFAULT.effective_severity(lying, judged) is band
    assert DEFAULT.severity_label(lying, judged) == SeverityLabel(severity=band, basis="computed")


def test_a_vector_the_scoring_path_refuses_never_labels() -> None:
    # out-of-order 4.0 metrics: score_of rejects them, so severity_of does too —
    # a malformed vector never supplies a computed label
    assert severity_of("CVSS:4.0/PR:N/AV:N/AC:L/AT:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H") is None


def test_a_scored_report_bands_its_severity_whatever_anyone_says() -> None:
    # the defect: a 9.8 the triage harness called medium — the vector, never a word, labels it
    scored = occurrence("medium", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert DEFAULT.effective_severity(scored, disposition(Severity.LOW)) is Severity.CRITICAL


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
