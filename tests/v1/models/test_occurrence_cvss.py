"""An occurrence's CVSS score serializes as Core's canonical decimal on every backend."""

from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from traust_core.v1.models.findings import Occurrence


@pytest.mark.parametrize(
    ("stored", "served"),
    [
        (Decimal("0E-10"), "0"),  # SQLite's zero
        (Decimal("7.5000000000"), "7.5"),  # SQLite's fixed scale
        (Decimal("10"), "10"),
        (Decimal("9.80"), "9.8"),
        (None, None),
    ],
)
def test_an_occurrence_serves_its_cvss_score_canonically(
    stored: Decimal | None, served: str | None
) -> None:
    occurrence = Occurrence(
        finding_id=uuid4(), assessment_id=uuid4(), severity="high", cvss_score=stored
    )
    assert occurrence.model_dump(mode="json")["cvss_score"] == served
    assert occurrence.cvss_score == stored  # the value itself is untouched
