---
name: traust-core-patterns
description: How to add code to traust-core the way the platform API expects. Use when adding or changing a repository, unit of work, artifact store, service interface, provider (tool, source, feed), report, router or config field. Read AGENTS.md → Design rules first.
---

# traust-core patterns

Rules live in `AGENTS.md` → **Design rules**: one owner per capability, one service per domain, behaviour placed by responsibility, no cross-domain repository access or joins, typed IDs. This skill is the recipe for each kind of change. Copy the worked example; don't invent a new shape.

| Adding | Recipe | Worked example |
|---|---|---|
| A repository (or a query) over a contracts table | [repository.md](repository.md) | `src/traust_core/v1/repositories/traust/inventory/repository.py`; tests in `tests/v1/repositories/tables/` |
| Cross-section writes in one transaction | [repository.md](repository.md#unit-of-work) | `src/traust_core/v1/repositories/contract.py` (`SqlTraustUnitOfWork`) |
| A domain service, policy or interface | [service.md](service.md) | `src/traust_core/v1/services/portfolio.py` (shape) |
| A tool, source or feed provider | [provider.md](provider.md) | `tests/v1/example/provider.py` |
| A REST route (a domain's HTTP resources) | [route.md](route.md) | `src/traust_core/v1/rest/ledger/`; tests in `tests/v1/rest/ledger/` |
| An artifact type the harness/LLM produces | [artifacts.md](artifacts.md) | `tests/v1/example/artifact_publishing.py` (`TRIAGE`) |
| A job the engine runs or an LLM triggers | [service.md](service.md#job-engine-and-llm-entry) | `tests/v1/example/continuous_ops/` |
| A report | [report.md](report.md) | `tests/v1/example/report.py` |
| A router | [report.md](report.md#router) | `tests/v1/example/router.py` |
| A config field | [service.md](service.md#config) | `src/traust_core/v1/context/` |
| A contracts bump or a named artifact | [contracts.md](contracts.md) | `src/traust_core/v1/models/artifacts.py`, `tests/v1/models/test_artifacts.py` |

## Who owns what

| Layer | Owns | Never |
|---|---|---|
| Model (`models/<section>.py`) | a contract table row (`Entity`/`AppendOnly`, fields = columns); other types are plain `Model`; pure rules on one value | I/O, database types, behaviour on row models |
| Repository (`repositories/traust*/<section>/<table>.py`) | SQL for its one table: inherited `add`/`get`/`update` + named queries | rules, joins to another section, files |
| Unit of work (`SqlTraustUnitOfWork`) | one connection, one transaction across every repository | logic |
| Policy | pure rules needing config or spanning domains | I/O |
| Service (`services/<domain>.py`) | use cases: read via repositories, apply policies, write, commit | SQL, another domain's repositories, files, env, clocks |
| Provider (`providers/`) | anything outside the process | domain rules |
| Route / CLI / materializer | validate → call one service → return its result ([route.md](route.md)) | logic |

```text
needs SQL?                      → named query on the table's repository (one table)
several tables of one section?  → service method over that section's repositories
two domains?                    → call the other domain's service; compose by <entity>_id
rule with no I/O?               → policy (or the model, if it's about one value)
outside the process?            → provider
SQL rule several readers share? → a view in traust-contracts
```

## Two defaults

- **Convention over configuration.** Copy the worked example's shape (names, verbs, layout); don't add a setting or flag to choose between behaviours. Config is for what truly differs per deployment, read once in `Context`.
- **Fallbacks are a decision, not a default.** No silent `except: return default` or "if missing, use X". Missing or malformed input raises a typed `traust_core.v1.errors` error, logged once where handled. A fallback is fine only when the domain defines it as behaviour (a degraded outcome with a reason), and then it's explicit and tested.

## Quality checklist (every PR)

1. Comments only for a non-obvious *why*; nothing that restates the code.
2. Docstrings: one or two lines on public API where name and types don't say it; none on private helpers or tests.
3. Don't reinvent: search `src/` for an existing function first and extend it.
4. Generic logic used in more than one place is one helper where its kind lives (`models/values.py`, a provider, the owning repository).
5. Tests cover edges: empty, not found, re-runs, invalid values, boundaries, each typed error, rollback.
6. Integration tests run the real path on SQLite and Postgres with sanitized copies of real data under `tests/fixtures/<domain>/` (people, hosts, org/repo names, tokens replaced). Never live systems.
7. Minimal code: shrink the diff (inline one-use helpers, merge near-duplicates, drop dead code and unused parameters).

## No duplicated responsibility

- One query, one place: the owning table's repository. Filtering rows in Python that SQL could filter → a named query.
- A repository never decides (thresholds, status rules) → policy.
- One model per concept: extend it; never a parallel `ObservedX` / flattened copy of a DTO.
- One id scheme: `<entity>_id: UUID`.
- No `Protocol` without a second implementation.
- When a change touches a module that duplicates a responsibility, move it to its owner in the same PR and delete the copy.

`tests/v1/test_architecture.py` enforces the structural rules (row models are tables, services use their own section, no file/sqlite access in services or table repositories, no side repositories, no in-memory stand-ins in `src/`, one engine in `Context`). If it fails, the code is in the wrong place; don't widen the allowlists without review.

Python style (typing, models, errors, idioms): [../python-patterns/SKILL.md](../python-patterns/SKILL.md).

Finish every change with `make lint-fix && make test`.
