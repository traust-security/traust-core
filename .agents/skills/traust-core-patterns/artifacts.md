# Publishing an artifact

Every artifact the harness or an LLM produces is an `PublishSpec` published through `ArtifactPublisher`.

1. Add the file kind to `ResultKind` (value = today's suffix) and, if it has a contract schema, to `SCHEMA_FOR_KIND`.
2. In the repo that owns the artifact (traust for harness artifacts; see `tests/v1/example/artifact_publishing.py`):
   - `artifact`: the named type from `traust_core.v1.artifacts` (add it to the catalog if missing)
   - `input`: `JsonInput()` (default) or another `InputFormat`
   - `companions`: `Companion(ResultKind.<X>_MD, render_<x>_md)` for files rendered from the validated model; never accept hand-written companions
3. Add it to that repo's `PublishSpecs` and pass it to `ctx.artifact_publisher(specs)`.
4. Tests: publish writes primary then companions; invalid input writes nothing and returns issues with paths; rendered markdown from a fixture; validate a sample of real files.

Call sites:

```python
publisher = ctx.artifact_publisher(SPECS)
publisher.publish("triage", subject, raw_bytes, run_id)  # LLM output
publisher.publish_artifact(TriageArtifact.from_document(doc), subject, run_id)  # typed code
```

`ArtifactValidationError.issues` is a list of `{path, message}`; return it to the LLM so it can fix and retry.
