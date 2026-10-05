---
name: traust-core-patterns
description: How to add code to traust-core the way the platform API expects. Use when adding or changing a repository, unit of work, artifact store, service interface, provider (tool, source, feed), report, router, config field, or when making a breaking change that needs a v2.
---

# traust-core patterns

Rules live in `AGENTS.md`. This skill is the recipe for each kind of change. Copy the worked example; don't invent a new shape.

| Adding | Recipe | Worked example |
|---|---|---|
| An aggregate repository over a contracts table | [repository.md](repository.md#aggregate-repository) | `src/traust_core/v1/security/triage.py` |
| A table and its repository | [repository.md](repository.md) | `tests/v1/example/repository.py`; over a contracts table: `src/traust_core/v1/repositories/storage.py` |
| A service function or interface | [service.md](service.md) | `src/traust_core/v1/services/storage.py` |
| A tool, source or feed provider | [provider.md](provider.md) | `tests/v1/example/provider.py` |
| An artifact type the harness/LLM produces | [artifacts.md](artifacts.md) | `tests/v1/example/artifact_publishing.py` (`TRIAGE`) |
| A job the engine runs or an LLM triggers | [service.md](service.md#job-engine-and-llm-entry) | `tests/v1/example/continuous_ops/` |
| A report | [report.md](report.md) | `tests/v1/example/report.py` |
| A router | [report.md](report.md#router) | `tests/v1/example/router.py` |
| A config field | [service.md](service.md#config) | `src/traust_core/v1/context/` |
| A contracts bump or a named artifact | [contracts.md](contracts.md) | `src/traust_core/v1/security/artifacts.py`, `tests/v1/test_artifact_types.py` |
| A breaking change | [versioning.md](versioning.md) | — |

Finish every change with `make lint-fix && make test`.
