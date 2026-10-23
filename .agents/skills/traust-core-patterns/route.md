# REST routes

Rules: `AGENTS.md` → Layers (**REST API**). Shape to copy: `src/traust_core/v1/rest/ledger/`, tests in `tests/v1/rest/ledger/`.

A domain's routes:

1. One package per domain: `rest/<domain>/`. Its `__init__.py` builds `router` from one module per resource (`layers.py`, `checkpoints.py`); add the package to `DOMAINS` in `rest/domains.py`. A domain never imports another domain's routes; cross-domain work happens in the services.
2. A route validates, calls **one** service method and returns its core model (or `Page[...]`). No branches on domain state, no second call, no hand-built dict. Behaviour you're tempted to write here belongs in the service so the in-process path gets it too.
3. Authorization is the service's: pass the `Caller` (`Principal`) to methods that decide who may act (`checkpoint(repository_id, principal)`). Routes that only read take `_: Caller`, so the caller is verified.
4. Dependencies come from `rest/common/deps.py`: `Caller` (bearer → `Principal`), `CoreServices` (one unit of work per request). An optional service (the ledger) gets a small dependency in the domain package that raises `NotFoundError` when it's off (`rest/ledger/service.py`).
5. Resources by UUID: `/v1/<plural>/{<entity>_id}`, nested under their parent when they belong to one (`/v1/repositories/{repository_id}/ledger/layers`); verbs only as HTTP methods. Lists page with `limit` (`Query(ge=1, le=1000)`) and `cursor`, passed as `PageRequest`; the service owns what the cursor means.
6. Errors are typed core errors raised by the service; `rest/common/problems.py` maps them to problem+json once. Document each route's errors with `responses=PROBLEMS(401, 404, ...)`.
7. Plain `def` routes (SQL is synchronous and runs in the threadpool, keeping the loop free for `/v1/healthz`); `async def` only for routes that touch nothing.
8. Tests (`tests/v1/rest/<domain>/`): a real `Context` on SQLite with rows seeded through `Seed` and tokens from `bearer(context)` (its local issuer). Every route: the HTTP body equals the in-process call (`same_as_in_process`); 401 without a token; each documented error as problem+json; paging's empty, one-page and last-page cases. The service's own tests stay in `tests/v1/services/`.
9. `make api-check` must still build the OpenAPI document; a new or changed query also gets its `perf/` case.
