from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError as ModelValidationError

from traust_core.v1.models.findings import Decision, Occurrence

FINDING_ID = UUID("00000000-0000-4000-8000-000000000001")
ASSESSMENT_ID = UUID("00000000-0000-4000-8000-000000000002")
NOW = datetime(2026, 10, 22, tzinfo=UTC)


@pytest.mark.parametrize("severity", ["urgent", ""])
def test_occurrence_rejects_invalid_severity(severity: str) -> None:
    with pytest.raises(ModelValidationError, match="severity"):
        Occurrence(finding_id=FINDING_ID, assessment_id=ASSESSMENT_ID, severity=severity)


@pytest.mark.parametrize("severity", ["urgent", ""])
def test_decision_rejects_invalid_severity(severity: str) -> None:
    with pytest.raises(ModelValidationError, match="severity"):
        Decision(
            finding_id=FINDING_ID,
            statement_key="test-statement",
            severity=severity,
            actor="user:test",
            occurred_at=NOW,
        )
