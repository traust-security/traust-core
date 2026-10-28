from datetime import timedelta, timezone
from uuid import UUID

from tests.v1.repositories.tables.conftest import T0, Seed, saved_id


def test_validation_evidence_matches_each_assessment_with_its_own_timestamp(seed: Seed) -> None:
    first = seed.assessment(occurred_at=T0)
    second = seed.assessment(occurred_at=T0 + timedelta(days=1))
    timestamps = {
        saved_id(first): second.occurred_at,
        saved_id(second): first.occurred_at,
        UUID("00000000-0000-4000-8000-000000000099"): T0,
    }
    assert seed.uow.assessments.list_at(timestamps) == []
    timestamps[saved_id(first)] = T0.astimezone(timezone(timedelta(hours=5)))
    assert seed.uow.assessments.list_at(timestamps) == [first]
    assert seed.uow.assessments.list_at({}) == []


def test_validation_timestamp_lookup_uses_the_storages_fractional_precision(seed: Seed) -> None:
    precise = T0.replace(microsecond=123456)
    first = seed.assessment(occurred_at=precise)
    assert seed.uow.assessments.list_at({saved_id(first): precise}) == [
        seed.uow.assessments.get(saved_id(first))
    ]
    assert (
        seed.uow.assessments.list_at({saved_id(first): precise + timedelta(milliseconds=1)}) == []
    )
