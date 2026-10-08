# Service functions and interfaces

Service functions (the default):

1. `services/<area>.py`: plain functions taking a unit of work (or a repository) plus `Clock`; see `services/storage.py::record_artifact`.
2. Validate input first (models, value objects), then open the unit of work, call repositories, commit.
3. Return `Dto`s or domain `Model`s, never `dict`.
4. Contract tests run the function against every unit-of-work implementation.

Interfaces (when traust-engine or traust-ledger owns the implementation):

1. Request/response `Dto`s in `models/<subject>.py`; the `Protocol` in the service module that consumes it.
2. The owning repo implements it in-process; core never calls over HTTP.
3. Export from `services/__init__.py`; README row.

## Config

1. Add a frozen `_Model` section in `context/config.py`; unknown keys stay rejected.
2. Secrets are referenced by env var name (`*_env`), read through `_read_env`.
3. `Context` reads the section; nothing else reads config or env.
4. Test: valid file, typo rejected, secret read from env.

## Job (engine and LLM entry)

1. The work is a service function: takes a unit of work, providers, `Clock`; returns `JobResult` (`succeeded`, `partly(degraded)`, `refused`, `failed`). Never raises on source trouble; report it as degraded.
2. `Materializer` (`services.operations`): `asset` name + `materialize(AssetRequest) -> JobResult`. Parse partition/params into value objects; bad input → `JobResult.failed`; then call the one service.
3. CLI for LLMs: argv → `AssetRequest` → the same materializer → print `JobResult` JSON → exit code.
4. traust-engine registers materializers at startup: `ctx.assets.register(name, factory)`.
5. Worked example: `tests/v1/example/continuous_ops/`.
