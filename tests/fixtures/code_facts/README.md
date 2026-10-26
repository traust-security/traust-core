# Recorded code-facts producers

`producer-output.json` is actual tool output over the public-safe sample in
`source/`, recorded 2026-10-23. It contains no estate data.

- Symbols: released `traust.cli.build_symbol_index.extract_builtin` from traust
  `b2ddbeb087593df6a77035ccdcd73ca7a9fb4ee5` (`origin/main`), without its SQLite writer.
- Language counters: `scc 4.1.0 --format json source/`, installed through mise.

The round-trip test normalizes these recorded fields into `CodeFactsArtifact`,
publishes it, records its `tool_scan` assessment, and calls the real service.
Tests never run the producers or query a live repository. Tool execution and
producer adapters belong to the skill-port work; this slice reads recorded facts.

`priv_profile/operator/` is a synthetic operator tree (no estate data) shaped like the
manifests the operator-priv-profile skill met in the field (CSV, kustomize RBAC, kubebuilder
markers, samples, a helm template, vendored and unparseable files). `priv_profile/widget-priv-profile.json`
is the profile `CodeFactsService.priv_profile` writes for it; on 2026-10-25 it matched
traust `build_priv_profile.py` (`b48ff14`) field for field, up to list order. Since then a `groups=""`
marker counts as the core group (controller-gen's reading), so `secrets` get/list are no longer surplus.

`xcrypto/repo/` is a synthetic Go module (no estate data) using golang.org/x/crypto from a main
package, a library, a test, docs, a vendored copy and a third_party tree. `xcrypto/cmd-app.digraph`
is the subset of `callgraph -format=digraph ./cmd/app` (golang.org/x/tools v0.38.0, x/crypto
v0.43.0, recorded 2026-10-26) whose callers are the module's own or bcrypt's functions.
