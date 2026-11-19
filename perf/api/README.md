# perf/api

k6 load over the REST API (`traust-server`) at fixture volume, so we know it holds the runners
and a year of data. The query layer (`../queries`) asks whether each query uses its index; this
layer asks whether the endpoints hold up under concurrency.

```bash
make db-up && make perf-api            # fetch k6, seed, run, gate against baseline.json
make db-up && make perf-api-baseline   # same, but overwrite baseline.json
make db-up && make perf-api-breakpoint # reader ramp to find where the API stops holding
```

| File | What |
|---|---|
| `ops.js` | the gate's scenarios and their weights (the only place those live): runners claim + complete while readers page `/v1/orders`, read `/v1/feed`, build one scoped `/v1/insights/findings-rollup` (the whole-portfolio cost is bounded in `../queries`), and drive `POST /v1/dashboards:query` as personas — a grant × an app area × a cadence (findings subject only so far): poll personas re-read a card at their own cadence, visit personas read once, each with a staggered start and its own baseline row. Correctness gates (no failures, every claim 200/204) fail the run here; latency and throughput are gated by `run.py` |
| `breakpoint.js` | discovery ramp: the runners keep claiming while readers climb to the ramp's ceiling. Correctness gates only; `run.py --breakpoint` prints where latency and throughput land, no gate |
| `lib.js` | the scenarios and summary both scripts share (endpoints, metrics, request rates) |
| `run.py` | copies the seeded database (`../seed.py`) so the mutating scenarios get a clean one, starts `traust-server` over it, mints a runner and a reader token, runs k6, then fails if any p95 is more than 20% over `baseline.json` or any request rate more than 20% under it (the dashboard's per-persona rows, when a baseline carries them, gate the same way); `--breakpoint` resets the order queue to ~70k queued first, so the ramp claims against a queue, not an empty pool |
| `baseline.json` | committed p95 and req/s per scenario; `run.py --update-baseline` writes it |

## The baseline is host-specific

Absolute p95 depends on the machine (cores, disk, one uvicorn worker). The committed baseline is a
starting point; the real guard is the **>20% regression** check against it. Refresh the baseline on
CI hardware so the nightly comparison is apples-to-apples: run the `perf-api` workflow with
`update_baseline=true`, which opens a PR with the recomputed `baseline.json`.

The nightly `perf-api` workflow runs the gate on a Postgres service; `workflow_dispatch` runs it on
demand. While the rewrite lives on `development` (not the default branch), the schedule cannot fire
from here, so `perf-api-schedule.yml` on `main` dispatches this workflow nightly on `development`.
Fixing a slow query is a separate PR on the owning repository or a contracts index, not here.
