"""Report provenance cannot infer evidence strength; disposition carries explicit re-ratings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from traust_core.v1.models.findings import Decision, Disposition
from traust_core.v1.models.vocabulary import Severity

T0 = datetime(2026, 10, 1, tzinfo=UTC)
FINDING = uuid4()


@pytest.mark.parametrize("source", ["validation_report", "verification_report", "interactive"])
def test_report_or_human_provenance_cannot_supply_an_omitted_grade(source: str) -> None:
    decision = Decision(
        id=uuid4(),
        finding_id=FINDING,
        statement_key="ungraded",
        assessment_id=uuid4() if source != "interactive" else None,
        actor="human:reviewer" if source == "interactive" else None,
        source_channel=source,
        validity="confirmed",
        occurred_at=T0,
    )
    folded = Disposition.fold(FINDING, [decision])
    assert folded.assurance == "claimed"
    assert decision.evidence_grade is None


def test_disposition_carries_the_latest_equally_supported_re_rating() -> None:
    def at(day: int, **kw: Any) -> Decision:
        return Decision(
            id=uuid4(),
            finding_id=FINDING,
            statement_key=f"k{day}",
            occurred_at=T0 + timedelta(days=day),
            **kw,
        )

    rated = [at(1, severity="high"), at(2, validity="confirmed"), at(3, severity="medium")]
    assert Disposition.fold(FINDING, rated).severity is Severity.MEDIUM
    assert Disposition.fold(FINDING, [at(1, validity="confirmed")]).severity is None
    assert (
        Disposition.fold(
            FINDING, [at(1, severity="high", evidence_grade="E0"), at(3, severity="low")]
        ).severity
        is Severity.HIGH
    )
