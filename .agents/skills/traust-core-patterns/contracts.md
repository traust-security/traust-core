# Contracts and named artifacts

traust-contracts is a pinned dependency. Read its data only through `traust_core.v1.contracts`.

Bump the pin:

1. Change the `rev` for `traust-contracts` under `[tool.uv.sources]` in `pyproject.toml`.
2. `uv sync`, then `make test`; fix any artifact type or repository the tests flag.

Write (exact):

- `contracts.validate(name, document)` / `contracts.validate_json(name, payload)` → `DocumentError` with `{path, message}` issues
- `ArtifactPublisher` and `record_artifact` already call it

Read:

- Named artifact types live in `src/traust_core/v1/models/artifacts.py`; add one line per new artifact: `class XArtifact(Artifact, name="x", schema="x", kind=ResultKind.X): ...`
- Fields come from the installed schema; never declare them by hand
- To see what fields exist: `XArtifact.describe()` (types, required/optional) or open `XArtifact.schema_path()`
- `ctx.analysis_results().read(XArtifact, subject)` / `.read_all(XArtifact, tree)`; `XArtifact.parse(raw)` when you have bytes
- Enums: `contracts.enum("<enum-file>")` (e.g. `Verdict`, `Severity` in the catalog)

Database:

- `apply_schema(engine, contracts.ddl("storage", dialect))`; check repositories with `schema_drift`
