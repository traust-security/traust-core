"""Run the k6 ops API load against a fresh copy of the seeded database and gate the result.

Seeds Postgres from `perf/seed.py` (the same volumes the query layer uses), copies it so the
mutating scenarios get a clean database, starts `traust-server` over it, mints a runner and a
reader token, runs `ops.js`, then compares the summary to `baseline.json` (a regression is more
than 20% slower, or more than 20% lower throughput). `--update-baseline` writes the baseline
instead of gating. `--breakpoint` runs `breakpoint.js` instead: a reader ramp that reports where
the API stops holding, not gated.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import sqlalchemy as sa

from perf.seed import seeded_database
from traust_core.v1.context import Config, Context

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "ops.js"
BREAKPOINT_SCRIPT = HERE / "breakpoint.js"
HERD_SCRIPT = HERE / "herd.js"
BASELINE = HERE / "baseline.json"
SUMMARY = HERE.parent.parent / ".perf" / "api-summary.json"
BREAKPOINT_SUMMARY = HERE.parent.parent / ".perf" / "api-breakpoint.json"
HERD_SUMMARY = HERE.parent.parent / ".perf" / "api-herd.json"
SWEEP_SUMMARY = HERE.parent.parent / ".perf" / "api-sweep.json"
# Every read SCI calls, herded one at a time over one server (herd.js READS).
SWEEP_TARGETS = (
    "dashboard",
    "findings_page",
    "findings_count",
    "findings_summaries",
    "review_queue",
    "repo_findings",
    "repo_summary",
    "repo_timeline",
    "feed",
    "orders",
    "insight_rollup",
    "insight_trend",
    "insight_coverage",
    "insight_remediation",
)
API_DATABASE = "traust_perf_api"
REGRESSION = 1.20  # a run more than 20% slower, or more than 20% lower throughput, fails
LATENCY_KEYS = (
    "claim_p95_ms",
    "list_p95_ms",
    "feed_p95_ms",
    "insight_p95_ms",
    "consumer_p95_ms",
    "dashboard_p95_ms",
)
RATE_KEYS = (
    "claim_rps",
    "list_rps",
    "feed_rps",
    "insight_rps",
    "consumer_rps",
    "dashboard_rps",
    "http_reqs_rate",
)
GATE_KEYS = LATENCY_KEYS + RATE_KEYS
# --dashboard-only: the personas alone, without the ops load on the same process
DASHBOARD_KEYS = ("dashboard_p95_ms", "dashboard_rps")
QUEUE_DEPTH = 70_000  # the breakpoint ramp must claim against a queue, not an empty pool


def _admin(url: str) -> sa.Engine:
    return sa.create_engine(sa.make_url(url).set(database="postgres"), isolation_level="AUTOCOMMIT")


def fresh_copy(url: str, template: str) -> sa.URL:
    """A clean copy of the seeded template; the scenarios commit, so each run owns its own."""
    engine = _admin(url)
    with engine.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {API_DATABASE} WITH (FORCE)")
        conn.exec_driver_sql(f"CREATE DATABASE {API_DATABASE} TEMPLATE {template}")
    engine.dispose()
    return sa.make_url(url).set(database=API_DATABASE)


def drop_copy(url: str) -> None:
    engine = _admin(url)
    with engine.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {API_DATABASE} WITH (FORCE)")
    engine.dispose()


def config_file(home: Path, database_url: sa.URL) -> Path:
    path = home / "perf-api.yaml"
    path.write_text(
        f"home: {home}\n"
        f"database:\n  url: {database_url.render_as_string(hide_password=False)}\n"
        f"identity:\n  trust_local: true\n"
    )
    return path


def tokens(config: Path) -> tuple[str, str]:
    context = Context(Config.from_file(config))
    runner = context.local_issuer.mint("perf-runner", machine=True)
    reader = context.local_issuer.mint("perf-reader@example.com")
    return runner.token.get_secret_value(), reader.token.get_secret_value()


def serve(config: Path, port: int) -> subprocess.Popen[bytes]:
    server = subprocess.Popen(["traust-server", "--config", str(config), "--port", str(port)])
    health = f"http://127.0.0.1:{port}/v1/healthz"
    for _ in range(60):
        if server.poll() is not None:
            raise RuntimeError(f"traust-server exited early ({server.returncode})")
        try:
            with urllib.request.urlopen(health, timeout=1) as response:
                if response.status == 200:
                    return server
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.5)
    server.terminate()
    raise RuntimeError("traust-server did not become healthy within 30s")


def k6_binary(explicit: str | None) -> str:
    local = HERE.parent.parent / ".perf" / "bin" / "k6"
    found = explicit or (str(local) if local.exists() else shutil.which("k6"))
    if not found:
        sys.exit("k6 not found: run `make k6` to fetch it, or pass --k6 <path>")
    return found


def run_k6(
    k6: str, port: int, runner: str, reader: str, duration: str, script: Path, summary: Path
) -> int:
    summary.parent.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "BASE_URL": f"http://127.0.0.1:{port}",
        "RUNNER_TOKEN": runner,
        "READER_TOKEN": reader,
        "SUMMARY": str(summary),
        "DURATION": duration,
    }
    return subprocess.run([k6, "run", str(script)], env=env, check=False).returncode


def reset_queue(url: sa.URL) -> int:
    """Open every unfinished order and top the queue up from finished ones; returns its depth."""
    engine = sa.create_engine(url)
    cleared = (
        "state = 'queued', lease_holder = NULL, lease_expires_at = NULL,"
        " started_at = NULL, finished_at = NULL"
    )
    with engine.begin() as conn:
        conn.exec_driver_sql(
            f"UPDATE traust_ops.run_order SET {cleared}"
            " WHERE state IN ('planned', 'awaiting_approval', 'leased')"
        )
        queued = conn.exec_driver_sql(
            "SELECT count(*) FROM traust_ops.run_order WHERE state = 'queued'"
        ).scalar_one()
        conn.exec_driver_sql(
            f"UPDATE traust_ops.run_order o SET {cleared}"
            f" FROM (SELECT id FROM traust_ops.run_order WHERE state = 'succeeded'"
            f"     ORDER BY created_at DESC LIMIT {QUEUE_DEPTH - queued}) t"
            " WHERE o.id = t.id"
        )
        queued = conn.exec_driver_sql(
            "SELECT count(*) FROM traust_ops.run_order WHERE state = 'queued'"
        ).scalar_one()
    engine.dispose()
    return queued


def persona_rows(summary: dict[str, float | None]) -> tuple[str, ...]:
    """The per-persona rows ops.js emits (persona_<name>_p95_ms / _rps), gated the same
    20% way once a baseline carries them; a run that never reached a persona emits none."""
    return tuple(sorted(k for k in summary if k.startswith("persona_") and summary[k] is not None))


def gate(summary: dict[str, float | None], update: bool, keys: tuple[str, ...] = GATE_KEYS) -> int:
    personas = persona_rows(summary)
    if update:
        rows = {k: round(summary[k], 2) for k in (*keys, *personas) if summary.get(k) is not None}
        if keys != GATE_KEYS and BASELINE.exists():  # a subset run merges, never drops rows
            rows = {**json.loads(BASELINE.read_text()), **rows}
        BASELINE.write_text(json.dumps(rows, indent=2))
        print(f"baseline written: {BASELINE}")
        return 0
    if not BASELINE.exists():
        sys.exit(f"no baseline at {BASELINE}; create one with --update-baseline")
    baseline = json.loads(BASELINE.read_text())
    latency_keys = (
        *(k for k in LATENCY_KEYS if k in keys),
        *(k for k in personas if k.endswith("_p95_ms")),
    )
    rate_keys = (*(k for k in RATE_KEYS if k in keys), *(k for k in personas if k.endswith("_rps")))
    regressions = [
        f"  {k}: {summary[k]:.1f} ms vs baseline {baseline[k]:.1f} ms (> {REGRESSION:.0%})"
        for k in latency_keys
        if k in baseline and summary[k] > baseline[k] * REGRESSION
    ] + [
        f"  {k}: {summary[k]:.1f} vs baseline {baseline[k]:.1f} req/s (< {1 / REGRESSION:.0%})"
        for k in rate_keys
        if k in baseline and summary[k] < baseline[k] / REGRESSION
    ]
    for key in latency_keys:
        if key in baseline:
            print(f"  {key}: {summary[key]:.1f} ms (baseline {baseline[key]:.1f} ms)")
    for key in rate_keys:
        if key in baseline:
            print(f"  {key}: {summary[key]:.1f} req/s (baseline {baseline[key]:.1f})")
    stale = [k for k in (*keys, *personas) if k not in baseline]
    if stale:
        print(f"baseline predates {', '.join(stale)}; refresh it with --update-baseline")
    if regressions:
        print("regression:\n" + "\n".join(regressions))
        return 1
    return 0


def sweep(k6: str, port: int, runner: str, reader: str, duration: str) -> int:
    """Herd each SCI read in turn; print one row per read and keep them all."""
    rows = []
    chosen = os.environ.get("TARGETS")
    targets = tuple(chosen.split(",")) if chosen else SWEEP_TARGETS
    for target in targets:
        os.environ["TARGET"] = target
        run_k6(k6, port, runner, reader, duration, HERD_SCRIPT, HERD_SUMMARY)
        row = json.loads(HERD_SUMMARY.read_text())
        rows.append(row)
        p50, p95 = row["herd_p50_ms"] or 0, row["herd_p95_ms"] or 0
        failed = row["herd_failed_rate"] or 0
        print(
            f"{target:20s} p50 {p50:8.0f} ms  p95 {p95:8.0f} ms"
            f"  failed {failed:6.1%}  n={row['herd_requests']}",
            flush=True,
        )
    SWEEP_SUMMARY.write_text(json.dumps(rows, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="perf-api", description=__doc__)
    parser.add_argument(
        "--update-baseline", action="store_true", help="write the baseline, don't gate"
    )
    parser.add_argument(
        "--breakpoint",
        action="store_true",
        help="run the reader ramp instead of the gate; reports the edge, doesn't gate",
    )
    parser.add_argument(
        "--herd",
        action="store_true",
        help="HERD users (env, default 50) hit the landing card at once; reports, doesn't gate",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="herd every read SCI calls, one at a time over one server; reports, no gate",
    )
    parser.add_argument(
        "--dashboard-only",
        action="store_true",
        help="run the dashboard personas alone and gate only their rows",
    )
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--duration", default="20s")
    parser.add_argument("--k6", help="path to the k6 binary (default: .perf/bin/k6 or $PATH)")
    args = parser.parse_args(argv)

    url = os.environ.get("TRAUST_TEST_DATABASE_URL")
    if not url:
        sys.exit("TRAUST_TEST_DATABASE_URL not set (run `make db-up`)")
    k6 = k6_binary(args.k6)
    keys = DASHBOARD_KEYS if args.dashboard_only else GATE_KEYS
    if args.dashboard_only:
        os.environ["ONLY"] = "dashboard"

    seeded = seeded_database(url)
    template = seeded.url.database
    seeded.dispose()  # CREATE DATABASE ... TEMPLATE needs the template idle
    database_url = fresh_copy(url, template)
    if args.breakpoint:
        print(f"queued orders: {reset_queue(database_url)}")
    script, summary_path = (
        (BREAKPOINT_SCRIPT, BREAKPOINT_SUMMARY)
        if args.breakpoint
        else (HERD_SCRIPT, HERD_SUMMARY)
        if args.herd
        else (SCRIPT, SUMMARY)
    )
    server = None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            config = config_file(Path(tmp), database_url)
            runner, reader = tokens(config)
            server = serve(config, args.port)
            if args.sweep:
                return sweep(k6, args.port, runner, reader, args.duration)
            code = run_k6(k6, args.port, runner, reader, args.duration, script, summary_path)
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)
        drop_copy(url)

    summary = json.loads(summary_path.read_text())
    if args.breakpoint or args.herd:
        # discovery runs: their summary prints what they measured, no gate
        print(json.dumps(summary, indent=2))
        return code
    if any(summary.get(k) is None for k in LATENCY_KEYS if k in keys):
        sys.exit(f"k6 produced no latencies: {summary}")
    return code or gate(summary, args.update_baseline, keys)


if __name__ == "__main__":
    raise SystemExit(main())
