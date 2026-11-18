"""The duress apparatus: dashboard reads under the stamped write door.

Gated by TRAAST_PERF_LOAD (the run mutates the rig: decisions are
written); `make perf-load` sets it. Readers default past the engine
pool's size — the 504 shape the first concurrent receipt could not
reach."""

from __future__ import annotations

import os

import pytest
from sqlalchemy.engine import Engine

from perf.load import run_duress
from traust_core.v1.context import Context

pytestmark = pytest.mark.skipif(
    not os.environ.get("TRAUST_PERF_LOAD"), reason="TRAUST_PERF_LOAD not set (make perf-load)"
)


def test_dashboard_reads_under_the_stamped_write_door(engine: Engine, context: Context) -> None:
    duress = run_duress(engine, context, seconds=int(os.environ.get("TRAUST_PERF_SECONDS", "60")))
    print(duress.report())
    assert duress.writes.failures == 0, "the write door must not fail under read load"
