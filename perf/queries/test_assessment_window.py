"""3a · Assessments in a time window: the critical-miss sweep's occurred_at keyset page."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from perf.harness import Profile


def test_a_months_window_is_one_bounded_page(explained: Profile) -> None:
    end = datetime.now(UTC)
    (statement,) = explained(
        lambda uow: uow.assessments.search(since=end - timedelta(days=30), until=end, limit=500)
    )
    # NEED(contracts: idx_assessment_occurred): no index leads with occurred_at, so the page
    # filters a scan of the table; the budget pins one bounded statement until it lands.
    assert statement.execution_ms < 50, statement.plan
