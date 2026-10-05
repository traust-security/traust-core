# Provider (tool, source, feed)

1. Request `Dto` extending `ToolRequest`, `CheckoutRequest` or the feed's own request.
2. Provider class with `name`, `check() -> Readiness`, and `acquire(request) -> Result[T]` (or the source/feed methods in `interfaces/providers.py`).
3. Constructor takes what it needs (`ProcessRunner`, `Clock`, ...); never builds them.
4. Tools: build argv from typed fields, `--` before user values, run through `ProcessRunner`, parse output into models.
5. Every result carries `Provenance` (provider, version, source, acquired_at, stale).
6. `check()` returns `Readiness(ready=False, detail=...)` instead of raising.
7. Register at startup: `ctx.tools.register("<name>", lambda: Provider(ctx.process))`.
8. Generic providers (git, forges) live in core; security tools and feeds live in the consuming package.
9. Tests: ready / not ready, parsed result, provenance set, bad input rejected.
