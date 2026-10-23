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
