"""A report-grade build looping in its own process: the shape a report worker role runs in -
it competes with the request path for the database, never for its interpreter.

    python -m perf.report_loop <database-url> <seconds>  ->  one JSON line: latencies, failures
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

from perf.conftest import ATTACK_MAPPING, ATTACK_TECHNIQUES, REGISTRY, SLA_POLICY
from perf.load import PageReader
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.services.identity import IdentityConfig

REPORT = "/v1/insights/findings-rollup?refresh=true"


def main(url: str, seconds: float) -> None:
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
        context.local_issuer.mint("load@example.com")  # the signing key, before the loop
        builder = PageReader(context, [REPORT], pause=5.0)
        stop = threading.Event()
        threading.Timer(seconds, stop.set).start()
        builder.run(stop)
    print(json.dumps({"latencies": builder.latencies, "failures": builder.failures}))


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]))
