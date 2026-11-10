"""SpendService.attribute_by and skill-carrying collect, on SQLite and Postgres.

Rules ported from traust-engine metrics/attribute_spend.py: usage lands on the skill that was
running, usage no skill claims stays in an `unattributed` bucket that is always reported, and the
split must be lossless against the total.
"""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from tests.v1.conftest import SQL_BACKENDS, contract_db
from tests.v1.repositories.tables.conftest import T0, Seed
from tests.v1.services.test_operations_series import DAY, collector, events, usage
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    SpendBreakdown,
    SpendDimension,
    SpendEvent,
    SpendFilter,
    SpendRollup,
    SpendSource,
)
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.operations import SpendService
from traust_core.v1.services.portfolio import Inventory

OCTOBER = TimeWindow.month_of(T0)


@pytest.fixture(params=SQL_BACKENDS)
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    with contract_db(request.param, tmp_path) as eng:
        yield eng


def spend(engine: Engine) -> SpendService:
    return SpendService(SqlTraustUnitOfWork(engine), FixedClock(T0 + 3 * DAY), ())


def fleet(engine: Engine) -> None:
    """Declared triage spend, two orders on the audit lane, and spend nobody claims."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        audit = [seed.run_order(lane="audit").id for _ in range(2)]
        uow.commit()
    service = spend(engine)
    for event in (
        SpendEvent(provider="anthropic", model="m", skill="triage", tokens_in=10, tokens_out=1,
                   cost_usd=Decimal("1.50"), occurred_at=T0),
        SpendEvent(provider="anthropic", model="m", skill="triage", run_order_id=audit[0],
                   tokens_in=20, tokens_out=2, cost_usd=Decimal("2.25"), occurred_at=T0),
        SpendEvent(provider="anthropic", model="m", run_order_id=audit[1], tokens_in=40,
                   tokens_out=4, cost_usd=Decimal("4"), occurred_at=T0 + DAY),
        SpendEvent(provider="anthropic", model="m", tokens_in=80, tokens_out=8,
                   cost_usd=Decimal("0.125"), occurred_at=T0 + DAY),
        SpendEvent(provider="anthropic", model="m", skill="triage", tokens_in=1, tokens_out=1,
                   cost_usd=Decimal(9), occurred_at=T0 - 30 * DAY),
    ):  # fmt: skip
        service.record(event)


def rollup(events: int, tokens_in: int, tokens_out: int, cost: str, key: str | None = None):
    return SpendRollup(
        key=key, events=events, tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=Decimal(cost)
    )


@pytest.mark.parametrize(
    ("by", "rows", "unattributed"),
    [
        (SpendDimension.SKILL, [rollup(2, 30, 3, "3.75", "triage")], rollup(2, 120, 12, "4.125")),
        (SpendDimension.LANE, [rollup(2, 60, 6, "6.25", "audit")], rollup(2, 90, 9, "1.625")),
    ],
)
def test_spend_splits_by_skill_or_lane_and_keeps_the_rest_unattributed(
    engine: Engine, by: SpendDimension, rows: list[SpendRollup], unattributed: SpendRollup
) -> None:
    fleet(engine)
    split = spend(engine).attribute_by(SpendFilter(window=OCTOBER), by)
    assert (list(split.rows), split.unattributed) == (rows, unattributed)
    assert split.total == rollup(4, 150, 15, "7.875")
    assert split.lossless


def test_a_lane_filter_narrows_the_skill_split(engine: Engine) -> None:
    fleet(engine)
    split = spend(engine).attribute_by(
        SpendFilter(window=OCTOBER, lane="audit"), SpendDimension.SKILL
    )
    assert [(r.key, r.cost_usd) for r in split.rows] == [("triage", Decimal("2.25"))]
    assert split.unattributed.cost_usd == Decimal(4)
    assert split.lossless


def test_an_empty_window_is_all_zero_and_still_lossless(engine: Engine) -> None:
    split = spend(engine).attribute_by(SpendFilter(window=OCTOBER), SpendDimension.SKILL)
    assert split.rows == () and split.unattributed == split.total == rollup(0, 0, 0, "0")
    assert split.lossless


def test_a_split_that_drops_spend_is_not_lossless() -> None:
    assert not SpendBreakdown(
        filter=SpendFilter(window=OCTOBER),
        by=SpendDimension.SKILL,
        rows=(rollup(1, 1, 1, "1", "triage"),),
        unattributed=rollup(0, 0, 0, "0"),
        total=rollup(2, 2, 2, "2"),
    ).lossless


@pytest.mark.parametrize(
    "by", [SpendDimension.MONTH, SpendDimension.MODEL, SpendDimension.PROVIDER]
)
def test_attribution_is_by_skill_or_lane_only(engine: Engine, by: SpendDimension) -> None:
    with pytest.raises(ValidationError, match="skill or lane"):
        spend(engine).attribute_by(SpendFilter(window=OCTOBER), by)


def test_collect_records_each_skills_usage_apart(engine: Engine) -> None:
    source = SpendSource(
        name="sessions",
        usages=(
            usage(T0, skill="triage"),
            usage(T0 + DAY / 2, skill="triage"),
            usage(T0, skill="secure-code-audit"),
            usage(T0),
        ),
    )
    service, _ = collector(engine)
    assert service.collect(source, OCTOBER) == 3
    split = service.attribute_by(SpendFilter(window=OCTOBER), SpendDimension.SKILL)
    assert [(r.key, r.events, r.tokens_in) for r in split.rows] == [
        ("secure-code-audit", 1, 500),
        ("triage", 1, 1000),
    ]
    assert (split.unattributed.events, split.unattributed.tokens_in) == (1, 500)
    assert split.lossless


def test_collect_with_skills_again_adds_nothing(engine: Engine) -> None:
    source = SpendSource(name="sessions", usages=(usage(T0, skill="triage"), usage(T0)))
    assert collector(engine)[0].collect(source, OCTOBER) == 2
    assert collector(engine)[0].collect(source, OCTOBER) == 0
    assert len(events(engine)) == 2


def test_a_day_collected_without_skills_is_not_attributed_twice(engine: Engine) -> None:
    plain = SpendSource(name="sessions", usages=(usage(T0), usage(T0 + DAY)))
    assert collector(engine)[0].collect(plain, OCTOBER) == 2
    attributed = SpendSource(
        name="sessions",
        usages=(usage(T0, skill="triage"), usage(T0 + DAY, model="claude-opus", skill="triage")),
    )
    assert collector(engine)[0].collect(attributed, OCTOBER) == 1
    assert sorted((e.occurred_at, e.model, e.skill) for e in events(engine)) == [
        (T0, "claude-sonnet", None),
        (T0 + DAY, "claude-opus", "triage"),
        (T0 + DAY, "claude-sonnet", None),
    ]


@pytest.mark.parametrize("reference", ["url", "id", "explicit"])
def test_declared_spend_retains_metadata_and_resolves_only_registered_identity(
    engine: Engine, reference: str
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        repo = Seed(uow).repository()
        event = Seed(uow).new_spend_event(
            repository_id=repo.id if reference == "explicit" else None,
            repository_label=str(repo.url if reference == "url" else repo.id),
            loc=0,
            batch="calibration-1",
            note="measured target",
        )
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    saved = service.record(event)
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.spend_events.get(saved.id)
    assert (
        stored.repository_id,
        stored.repository_label,
        stored.loc,
        stored.batch,
        stored.note,
    ) == (repo.id, event.repository_label, 0, "calibration-1", "measured target")
    assert stored.lane is None and stored.run_order_id is None
    assert service.summary(SpendFilter(window=OCTOBER), SpendDimension.REPOSITORY) == [
        rollup(1, 100, 20, "0.25", str(repo.id))
    ]


def test_ambiguous_repository_label_preserves_cost_without_guessing(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.repository(url="https://github.com/team-a/project")
        seed.repository(url="https://github.com/team-b/project")
        event = seed.new_spend_event(repository_label="project", loc=1234, note="calibration")
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    saved = service.record(event)
    assert saved.repository_id is None
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.spend_events.get(saved.id)
    assert (stored.repository_label, stored.loc, stored.note) == ("project", 1234, "calibration")
    assert service.summary(SpendFilter(window=OCTOBER), SpendDimension.REPOSITORY) == [
        rollup(1, 100, 20, "0.25")
    ]


@pytest.mark.parametrize("reference", ["none", "id", "url"])
def test_order_spend_derives_repository_without_storing_it(engine: Engine, reference: str) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        order = seed.run_order(repository_id=repo.id, lane="audit")
        event = seed.new_spend_event(
            run_order_id=order.id,
            repository_id=repo.id if reference == "id" else None,
            repository_label=repo.url if reference == "url" else "raw label",
            loc=123,
            batch="batch-1",
            note="ordered measurement",
        )
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    saved = service.record(event)
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.spend_events.get(saved.id)
    assert stored == saved
    assert stored.repository_id is None and stored.lane == "audit"
    assert stored.model_copy(update={"id": None, "created_at": None, "lane": None}) == (
        event.model_copy(update={"repository_id": None})
    )
    assert service.summary(SpendFilter(window=OCTOBER), SpendDimension.REPOSITORY) == [
        rollup(1, 100, 20, "0.25", str(repo.id))
    ]


@pytest.mark.parametrize("reference", ["id", "url"])
def test_order_spend_cannot_be_reattributed_to_another_repository(
    engine: Engine, reference: str
) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo, other = seed.repository(), seed.repository()
        order = seed.run_order(repository_id=repo.id)
        event = seed.new_spend_event(
            run_order_id=order.id,
            repository_id=other.id if reference == "id" else None,
            repository_label=other.url if reference == "url" else None,
        )
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    with pytest.raises(ValidationError, match="disagrees"):
        service.record(event)
    assert service.summary(SpendFilter(window=OCTOBER), None) == []


@pytest.mark.parametrize("reference", ["id", "url"])
def test_fleet_wide_order_spend_refuses_an_attested_repository(
    engine: Engine, reference: str
) -> None:
    """A fleet-wide order names no repository, so an event attesting one disagrees with
    the order's scope — and the schema keeps ordered rows from storing a repository of
    their own (`run_order_id IS NULL OR repository_id IS NULL`), so the attestation
    cannot be preserved either. Refuse it, as the repository-scoped mismatch does,
    rather than silently overwrite the attested identity with None."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        repo = seed.repository()
        order = seed.run_order(lane="audit")
        event = seed.new_spend_event(
            run_order_id=order.id,
            repository_id=repo.id if reference == "id" else None,
            repository_label=repo.url,
            loc=0,
            batch="batch-1",
            note="fleet-wide order",
        )
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    with pytest.raises(ValidationError, match="disagrees"):
        service.record(event)
    assert service.summary(SpendFilter(window=OCTOBER), None) == []


def test_fleet_wide_order_spend_keeps_unattributed_metadata(engine: Engine) -> None:
    """An unresolvable label is supplied metadata, not identity: it rides along
    unchanged, the row stays unattributed, and the rollup follows the order."""
    with SqlTraustUnitOfWork(engine) as uow:
        seed = Seed(uow)
        seed.repository(url="https://github.com/team-a/project")
        seed.repository(url="https://github.com/team-b/project")
        order = seed.run_order(lane="audit")
        event = seed.new_spend_event(
            run_order_id=order.id,
            repository_label="project",
            loc=0,
            batch="batch-1",
            note="fleet-wide order",
        )
        uow.commit()
    service = SpendService(
        SqlTraustUnitOfWork(engine),
        FixedClock(T0),
        (),
        inventory=Inventory(SqlTraustUnitOfWork(engine)),
    )
    saved = service.record(event)
    with SqlTraustUnitOfWork(engine) as uow:
        stored = uow.spend_events.get(saved.id)
    assert stored == saved
    assert stored.repository_id is None and stored.lane == "audit"
    assert stored.model_copy(update={"id": None, "created_at": None, "lane": None}) == event
    assert service.summary(SpendFilter(window=OCTOBER), SpendDimension.REPOSITORY) == [
        rollup(1, 100, 20, "0.25")
    ]


def test_spend_for_a_missing_order_is_not_recorded(engine: Engine) -> None:
    with SqlTraustUnitOfWork(engine) as uow:
        event = Seed(uow).new_spend_event(run_order_id=uuid4())
    service = spend(engine)
    with pytest.raises(NotFoundError):
        service.record(event)
    assert service.summary(SpendFilter(window=OCTOBER), None) == []


@pytest.mark.parametrize("loc", [-1, 1.5, True, "1"])
def test_declared_size_rejects_negative_or_noninteger_values(loc: object) -> None:
    with pytest.raises(ValueError, match="loc"):
        SpendEvent(
            provider="anthropic",
            model="m",
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal(0),
            occurred_at=T0,
            loc=loc,
        )
