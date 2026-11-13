# Publishing an artifact

Every artifact the harness or an LLM produces has a `PublishSpec` published through `ArtifactPublisher`.

1. Add a contract-backed named document to `models/artifacts.py`. New primary artifacts need no `ResultKind`.
2. In the repo that owns the artifact (traust for harness artifacts; see `tests/v1/example/artifact_publishing.py`):
   - `artifact`: the named type from `traust_core.v1.models.artifacts`
   - `input`: `JsonInput()` (default) or another `InputFormat`
   - `companions`: `Companion(ResultKind.<X>_MD, render_<x>_md)` for files rendered from the validated model; no caller-supplied companions except the reviewed remediation git patch exception below
3. Add it to that repo's `PublishSpecs` and pass it to `ctx.artifact_publisher(specs)`.
4. Tests: publish writes primary then companions; invalid input writes nothing and returns issues with paths; rendered markdown from a fixture; validate a sample of real files.

Call sites:

```python
publisher = ctx.artifact_publisher(SPECS)
published = publisher.publish("triage", raw_bytes)
published = publisher.publish_artifact(TriageArtifact.from_document(doc))
triage = publisher.get(published.artifact_id)
```

The publisher always records an artifact UUID on SQLite and Postgres. Bytes and
companions use content-addressed keys, and `get` validates against the persisted
digest after closing its database read. An artifact-row write failure raises a
typed error. `record_artifact` is the shared metadata writer for aggregates that
already own a transaction; the caller commits.

For locked aggregate writes, call `stage(document)` or `stage_companion(...)` before
taking write intent, then `publish_staged(staged)` or `record_companion(staged)` inside
the metadata transaction. Staging never writes rows; indexing never accesses objects.
Conflicts and rollbacks may leave unreferenced content-addressed objects, safe to retry.

Before any write, every publication entry point scans the validated JSON content
and all UTF-8 text companions with `RedactionPolicy.scan`. High-confidence hits
raise `DocumentError` with categories only; malformed companion text also fails
before writing. Decoded strings and JSON context are both checked; duplicate JSON
members are rejected because parsing would otherwise discard stored evidence.
Accepted bytes and digests are unchanged: callers explicitly redact evidence
before constructing a document and retrying when needed. The redactor's exact
sanitized PEM placeholder is accepted; blocks with remaining key material are not.

The sole rendering exception is producer-generated remediation git patches;
it is pending human review, with no human sign-off yet. Scope, rationale
and approval requirements are recorded in
[Remediation patch retention](../../../README.md#remediation-patch-retention).
Only `RemediationArtifact` with `ResultKind.REMEDIATION_PATCH` uses
`publish_companion(document, kind, bytes)`. The publisher derives the expected digest
from the validated report's `document.patch.diff_sha256`; missing declarations and
mismatched bytes are refused. Only matching UTF-8 text is in scope, with existing
secret checks unchanged. The publisher stores content-addressed bytes and indexes
their artifact ID. Attach that reference through `AssessmentLog` in the report's
metadata transaction. Reads use `payload(id)`.
All other companions must be renderer functions over the validated primary model.

Role aliases of one schema inherit its common document type (e.g.
`SecurityAuditArtifact` and `FindingsCurrentArtifact` inherit `ReportArtifact`).
ID reads return that neutral schema type because artifact rows store schema IDs,
not a role. Unrelated aliases are rejected when registering specs.

`DocumentError.issues` contains the validation paths/messages for the caller to fix.
