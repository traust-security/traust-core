# Contracts and named artifacts

traust-contracts is a pinned dependency. Read its data only through `traust_core.v1.contracts`.

Bump the pin:

1. Change the commit in the `traust-contracts @ git+…@<sha>` line of `[project] dependencies` in `pyproject.toml` (a direct reference, so traust and traust-engine get the same pin through core; the ledger pin works the same way).
2. `uv sync`, then `make test`; fix any artifact type or repository the tests flag.

Write (exact):

- `contracts.validate(name, document)` / `contracts.validate_json(name, payload)` → `DocumentError` with `{path, message}` issues
- `ArtifactPublisher` already calls it

Read:

- Named artifact types live in `src/traust_core/v1/models/artifacts.py`; add one line per new artifact: `class XArtifact(ArtifactDocument, name="x", schema="x", kind=ResultKind.X): ...`
- Fields come from the installed schema; never declare them by hand
- To see what fields exist: `XArtifact.describe()` (types, required/optional) or open `XArtifact.schema_path()`
- `ctx.artifact_publisher(specs).get(artifact_id)`; `XArtifact.parse(raw)` when you have bytes. Path-keyed `analysis_results()` reads are legacy.
- Enums: `contracts.enum("<enum-file>")` (e.g. `Verdict`, `Severity` in the catalog)

Database:

- `apply_schema(engine, contracts.database_ddl(dialect))` creates every namespace (traust, traust_ops, traust_ledger) in bootstrap order
- The DDL is contracts' to own and test; core declares each table once as a `TableSpec` and tests repository behaviour (see [repository.md](repository.md))
