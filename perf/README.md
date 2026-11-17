# perf

Query plans at production volume, on Postgres. Continuous ops issues these queries on every tick and claim, so each case checks the plan uses the index it should, has no sequential scan, and stays inside a time budget.

```bash
make db-up && make perf     # first run seeds ~20s; reruns reuse the database
```

`.perf/report.md` lists each statement's plan key line and execution time, ready for the PR (quality checklist item 8).

| File | What |
|---|---|
| `seed.py` | volumes (`REPOSITORIES`, `RUN_ORDERS`, …) and the bulk-insert SQL; the database name carries a digest of DDL + seed, so a change to either rebuilds it |
| `harness.py` | `profile(engine, call)`: runs a repository or service call, captures every statement it issues, replays each under `EXPLAIN (ANALYZE, BUFFERS)`, rolls back |
| `queries/test_<section>.py` | one case per named query on that section's tables |

## Add a case

1. New table in a query? Add its rows to `SEED` at the data model's growth figures (Appendix D).
2. Call the real repository method through the `explained` fixture; never hand-write the SQL:

   ```python
   def test_claim_takes_the_queue_head_by_index(explained):
       lease, reread = explained(lambda uow: uow.run_orders.claim("perf", NOW, LEASE))
       fast(lease, "idx_ops_run_order_claim", 5)
   ```

3. Unpacking the result also pins how many statements the call issues, which catches N+1.

A query that needs a new index is a traust-contracts change.

Not in CI per PR (seeding is slow); run it when a query changes.

## Layers

| Layer | Asks | Where |
|---|---|---|
| query | does each repository query use its index at volume? | `queries/` (this) |
| API | does `traust serve` hold the runners and a year of data (p95, throughput)? | `api/`, k6, nightly, committed baseline (performance harness) |

Both layers seed from `seed.py`. API scenarios commit, so they run against a fresh copy of the seeded database per run.
