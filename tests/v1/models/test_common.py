from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from traust_core.v1.models.common import TimeBucket, TimeWindow


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("at", "start", "end"),
    [
        (utc(2026, 10, 5, 12), utc(2026, 10, 1), utc(2026, 11, 1)),
        (utc(2026, 10, 1), utc(2026, 10, 1), utc(2026, 11, 1)),
        (utc(2026, 12, 31, 23, 59), utc(2026, 12, 1), utc(2027, 1, 1)),
        (utc(2028, 2, 29), utc(2028, 2, 1), utc(2028, 3, 1)),
        (
            datetime(2026, 11, 1, 1, tzinfo=timezone(timedelta(hours=3))),
            utc(2026, 10, 1),
            utc(2026, 11, 1),
        ),
    ],
    ids=["mid-month", "first instant", "december rolls the year", "leap day", "offset to utc"],
)
def test_month_of_is_the_utc_calendar_month(at: datetime, start: datetime, end: datetime) -> None:
    assert TimeWindow.month_of(at) == TimeWindow(start=start, end=end)


@pytest.mark.parametrize(
    ("bucket", "at", "start", "end"),
    [
        (TimeBucket.DAY, datetime(2026, 10, 1, 23, 59, tzinfo=UTC), (2026, 10, 1), (2026, 10, 2)),
        # 01:00 at UTC+2 is still the previous UTC day
        (
            TimeBucket.DAY,
            datetime(2026, 10, 2, 1, tzinfo=timezone(timedelta(hours=2))),
            (2026, 10, 1),
            (2026, 10, 2),
        ),
        (TimeBucket.WEEK, datetime(2026, 10, 1, 12, tzinfo=UTC), (2026, 9, 28), (2026, 10, 5)),
        (TimeBucket.WEEK, datetime(2026, 10, 5, tzinfo=UTC), (2026, 10, 5), (2026, 10, 12)),
        (TimeBucket.WEEK, datetime(2026, 12, 31, tzinfo=UTC), (2026, 12, 28), (2027, 1, 4)),
        (TimeBucket.MONTH, datetime(2026, 12, 31, 23, tzinfo=UTC), (2026, 12, 1), (2027, 1, 1)),
    ],
)
def test_time_bucket_window_is_the_utc_bucket_containing_the_instant(
    bucket: TimeBucket, at: datetime, start: tuple[int, ...], end: tuple[int, ...]
) -> None:
    window = bucket.window_of(at)
    assert (window.start, window.end) == (datetime(*start, tzinfo=UTC), datetime(*end, tzinfo=UTC))
