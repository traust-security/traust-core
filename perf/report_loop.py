"""The reports role under load, in its own process: request a fresh report build and build it
through the role's own worker, in a loop - it competes with the request path for the database,
never for its interpreter.

    python -m perf.report_loop <database-url> <seconds>  ->  one JSON line: latencies, failures
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from perf.conftest import ATTACK_MAPPING, ATTACK_TECHNIQUES, REGISTRY, SLA_POLICY
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.models.identity import ActorKind, IdentitySource, Principal
from traust_core.v1.models.insight import ViewName
from traust_core.v1.models.operations import WorkerId
from traust_core.v1.models.reports import ReportRequest, ReportStatus
from traust_core.v1.services.identity import IdentityConfig
from traust_core.v1.services.reports import ReportWorker

PAUSE = 5.0  # between builds, as a report queue drains


def main(url: str, seconds: float) -> None:
    latencies: list[float] = []
    failures = 0
    with tempfile.TemporaryDirectory() as home:
        context = Context(
            Config(
                home=Path(home),
                database=DatabaseConfig(url=url),
                identity=IdentityConfig(trust_local=True),
            )
        )
        context.register_model_catalog(REGISTRY)
        context.register_default_sla_policy(SLA_POLICY)
        context.register_attack_catalog(ATTACK_TECHNIQUES, ATTACK_MAPPING)
        services = context.services()
        caller = Principal(
            identity="load@example.com",
            kind=ActorKind("human"),
            display="load",
            verified_by=IdentitySource("local-user"),
        )
        worker = ReportWorker(services.ops, services.reports, WorkerId("reports-load"))
        ends = time.monotonic() + seconds
        while time.monotonic() < ends:
            started = time.perf_counter()
            report = services.reports.request(
                ReportRequest(report=ViewName.FINDINGS_ROLLUP, refresh=True), caller
            )
            worker.run_once()
            built = services.reports.get(report.order_id)
            if built.status is ReportStatus.READY:
                latencies.append(time.perf_counter() - started)
            else:
                failures += 1
            time.sleep(PAUSE)
    print(json.dumps({"latencies": latencies, "failures": failures}))


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]))
