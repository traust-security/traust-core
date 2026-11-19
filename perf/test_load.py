"""The duress apparatus: dashboard reads under the stamped write door.

The duress run is gated by TRAAST_PERF_LOAD (it mutates the rig: decisions
are written); `make perf-load` sets it. Readers default past the engine
pool's size — the 504 shape the first concurrent receipt could not reach.
The card population itself is pure and always runs."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy.engine import Engine

from perf.load import cards, run_duress
from traust_core.v1.context import Context
from traust_core.v1.models.dashboard import Dimension, Subject

skip_unless_gated = pytest.mark.skipif(
    not os.environ.get("TRAUST_PERF_LOAD"), reason="TRAUST_PERF_LOAD not set (make perf-load)"
)


def _grants() -> tuple[tuple, tuple]:
    return tuple(uuid4() for _ in range(3)), tuple(uuid4() for _ in range(366))


def test_the_population_covers_every_card_shape_over_every_grant_size() -> None:
    small, granted = _grants()
    population = cards(small, granted)
    assert len(population) == 15  # five shapes x three grant sizes
    assert all(card.subject is Subject.FINDINGS for card in population)
    grants = {card.repository_ids for card in population}
    assert grants == {small, granted, ()}
    shapes = {card.group_by for card in population}
    assert {(Dimension.SEVERITY,), (Dimension.CATEGORY,), (Dimension.REPOSITORY,)} <= shapes


def test_every_card_is_a_body_the_route_accepts() -> None:
    from traust_core.v1.models.dashboard import DashboardQuery

    small, granted = _grants()
    for card in cards(small, granted):
        body = card.model_dump(mode="json")
        assert DashboardQuery.model_validate(body) == card


@skip_unless_gated
def test_dashboard_reads_under_the_stamped_write_door(engine: Engine, context: Context) -> None:
    duress = run_duress(engine, context, seconds=int(os.environ.get("TRAUST_PERF_SECONDS", "60")))
    print(duress.report())
    assert duress.writes.failures == 0, "the write door must not fail under read load"
