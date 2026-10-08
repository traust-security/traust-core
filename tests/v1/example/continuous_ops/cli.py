from __future__ import annotations

import argparse
import sys

from traust_core.v1.models.operations import AssetRequest, JobResult, Outcome
from traust_core.v1.services.operations import Materializer

EXIT_CODES = {Outcome.SUCCEEDED: 0, Outcome.FAILED: 1, Outcome.DEGRADED: 4, Outcome.REFUSED: 5}


def main(argv: list[str], materializer: Materializer) -> int:
    parser = argparse.ArgumentParser(prog=f"traust observe {materializer.asset}")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--audited-head")
    parser.add_argument("--run-id", default="manual")
    args = parser.parse_args(argv)
    params = {"audited_head": args.audited_head} if args.audited_head else {}
    request = AssetRequest(
        asset=materializer.asset, run_id=args.run_id, partition=args.repo, params=params
    )
    result: JobResult = materializer.materialize(request)
    sys.stdout.write(result.model_dump_json() + "\n")
    return EXIT_CODES[result.outcome]
