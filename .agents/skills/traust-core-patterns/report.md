# Report

Three steps, three owners:

```python
with uow: rows = uow.<repo>.list_...()  # read through a repository
report = build_report(rows, clock)  # pure: rows -> Report
ref = publish(report, MarkdownRenderer(), artifacts, ObjectKey.parse("reports/<name>.md"))
```

2. `build_report(rows, clock) -> Report` is pure: no I/O, time from `Clock`. Unmeasured values render as `—`, not `0`.
3. List sources in `Report.sources`.
4. Never format strings into files directly; a new output format is a new `Renderer`.
5. As-reported dashboard history belongs to `InsightService.capture(view, filter, note)`,
   using typed reference artifacts and content-addressed ObjectStore bytes. Preserve original
   exports and methodology/version metadata; `as_of` recomputation is not a saved report.
   Use `snapshot`/`snapshot_bytes`, `history`/`report_history` and `compare`/`report_comparison`;
   never rewrite an earlier bundle when a counting policy or recorded population changes.
6. Tests: `build_report` on fixed rows with `FixedClock`; the job end to end with an in-memory unit of work and `InMemoryObjectStore`. Archive regressions also exercise the real artifact repositories and compare a saved report against late-ingestion replay without changing its bytes.

## Router

1. `route(state, events, refusals) -> tuple[Route, ...]` on a typed state: the decision table's route first (its lane may be None), then additive lanes; pure, no I/O, clock or env.
2. A subject refused in a lane is never routed back to that lane.
3. Table test: one row per rule.
