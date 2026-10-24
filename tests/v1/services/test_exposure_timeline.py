"""ExposureService.timeline and summary as of a point in time, on SQLite and Postgres: derived
from the recorded impact analyses, never snapshotted."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.engine import Engine

from tests.v1.services.test_exposure_impact import AT, engine
from tests.v1.services.test_exposure_reads import OUT, fleet, record
from traust_core.v1.models.common import TimeBucket
from traust_core.v1.models.dependencies import ExposureDimension, ExposureFilter
from traust_core.v1.models.vocabulary import Ecosystem, ImpactClassification

__all__ = ["engine"]


def day(n: int) -> datetime:
    return datetime(2026, 10, 23, tzinfo=UTC) + timedelta(days=n)


STEADY, FIXED = (3, 2, 1, 0), (3, 1, 0, 0)


@pytest.mark.parametrize(
    ("bucket", "as_of", "expected"),
    [
        (
            TimeBucket.DAY,
            None,
            [
                (day(0), 1, 1, 1, 1),
                (day(1), 2, 2, 1, 1),
                (day(2), 3, 2, 1, 1),
                *((day(n), *STEADY) for n in range(3, 9)),
                (day(9), 3, 1, 0, 1),
            ],
        ),
        (
            TimeBucket.WEEK,
            None,
            [
                (datetime(2026, 10, 19, tzinfo=UTC), 3, 2, 1, 3),
                (datetime(2026, 10, 26, tzinfo=UTC), 3, 1, 0, 1),
            ],
        ),
        (
            TimeBucket.MONTH,
            None,
            [
                (datetime(2026, 10, 1, tzinfo=UTC), 3, 2, 1, 3),
                (datetime(2026, 11, 1, tzinfo=UTC), 3, 1, 0, 1),
            ],
        ),
        (TimeBucket.DAY, AT + timedelta(days=1), [(day(0), 1, 1, 1, 1), (day(1), 2, 2, 1, 1)]),
        (
            TimeBucket.DAY,
            AT + timedelta(days=11),
            [
                (day(0), 1, 1, 1, 1),
                (day(1), 2, 2, 1, 1),
                (day(2), 3, 2, 1, 1),
                *((day(n), *STEADY) for n in range(3, 9)),
                (day(9), 3, 1, 0, 1),
                (day(10), *FIXED),
                (day(11), *FIXED),
            ],
        ),
        (TimeBucket.DAY, AT - timedelta(seconds=1), []),
    ],
)
def test_the_timeline_replays_the_latest_analyses_bucket_by_bucket(
    engine: Engine,
    bucket: TimeBucket,
    as_of: datetime | None,
    expected: list[tuple[datetime, int, int, int, int]],
) -> None:
    exposure, _, ids = fleet(engine)
    record(exposure, ids[0], *OUT, day=9)  # the affected commit, rescanned after its fix
    points = exposure.timeline(ExposureFilter(as_of=as_of), bucket)
    assert [(p.bucket, p.commits, p.exposed, p.affected, p.analysed) for p in points] == expected


def test_the_timeline_narrows_like_summary_and_is_empty_with_nothing_recorded(
    engine: Engine,
) -> None:
    exposure, recorded, _ = fleet(engine)
    assert exposure.timeline(ExposureFilter(ecosystem=Ecosystem.NPM), TimeBucket.DAY) == []
    narrowed = exposure.timeline(
        ExposureFilter(advisory_id=recorded[0].advisory_id, ecosystem=Ecosystem.GO), TimeBucket.DAY
    )
    assert narrowed == exposure.timeline(ExposureFilter(), TimeBucket.DAY)
    assert narrowed[-1].by_classification == {
        ImpactClassification.AFFECTED: 1,
        ImpactClassification.INCONCLUSIVE: 1,
        ImpactClassification.VERSION_NOT_IN_RANGE: 1,
    }


@pytest.mark.parametrize(
    ("as_of", "expected"),
    [
        (None, {"inconclusive": 1, "version_not_in_range": 2}),
        (AT + timedelta(days=8), {"affected": 1, "inconclusive": 1, "version_not_in_range": 1}),
        (AT + timedelta(days=1), {"affected": 1, "inconclusive": 1}),
        (AT, {"affected": 1}),
        (AT - timedelta(microseconds=1), {}),
    ],
)
def test_summary_counts_the_latest_analyses_as_of_a_point_in_time(
    engine: Engine, as_of: datetime | None, expected: dict[str, int]
) -> None:
    exposure, _, ids = fleet(engine)
    record(exposure, ids[0], *OUT, day=9)
    rollups = exposure.summary(ExposureFilter(as_of=as_of), ExposureDimension.CLASSIFICATION)
    assert {r.key: r.commits for r in rollups} == expected
