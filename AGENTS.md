# traust-core

Python 3.11+ library. The platform API lives in `traust_core.v1`. Overview: [README.md](README.md).

## Agent files

- `AGENTS.md` (this file): rules, always loaded. `CLAUDE.md` imports it for Claude Code
- `.agents/skills/`: recipes loaded on demand (Agent Skills standard). `.claude/skills` is a symlink to it
- Edit only `AGENTS.md` and `.agents/skills/`; never fork content into `CLAUDE.md` or `.claude/`

## Before done

- `make lint-fix` then `make test`; both must pass. Database changes also need `make db-up && make test-integration`
- Tests that need Postgres are marked `@pytest.mark.integration`; `make test` excludes them
- Commits: conventional `type(scope): subject`
- Public repo: no deployment-specific hostnames or figures in code, tests or docs

## Versioning

- Everything public is under `traust_core/v1/`; tests mirror it under `tests/v1/`
- Within `v1`, changes are additive only: new modules, new optional fields, new methods
- A breaking change (rename, removed field, changed signature or behaviour) goes into a new `traust_core/v2/` package; `v1` stays until its consumers move
- `v2` may import `v1`; `v1` never imports `v2`

## Layers

- `domain` → `contracts` → `artifacts` → `interfaces` → `repositories` → `rendering` → `services` → `security` → `clients` → `context`; each imports only earlier ones (`tests/v1/test_layering.py`)
- Framework packages never import `security`; `security` holds the shared security data model (named artifacts, aggregate repositories, domain services)
- Pack policy (routing rules, cadences, lanes, skills, CLIs) stays in traust
- No imports from other traust repos
- No HTTP. In-process library for traust, traust-engine and traust-ledger; an SDK comes later

## Contracts

- traust-contracts is a pinned dependency; read its data through `traust_core.v1.contracts` only, never import `traust_contracts`
- Nothing from traust-contracts is copied or generated into this repo
- Artifacts are named types in `security/artifacts.py` (`TriageArtifact`, ...); their fields come from the installed schema, never a hand-written copy
- Read with `AnalysisResultsRepository.read(XArtifact, subject)`, write with `ArtifactPublisher` (exact schema gate); no `json.load`/`.get()`/`json.dump` on artifacts
- Names: `artifacts/` = what an artifact is; `repositories/object_store.py` = raw bytes; `services/artifact_publishing.py` = the publish use case. Modules name the subject; the package names the role (no `_service` suffix)
- Every repository `sa.Table` over a contracts table has a `schema_drift` test
- Artifacts produced by the harness or an LLM go through `ArtifactPublisher`; nothing writes `analysis-results` files directly
- `interfaces/` holds only interfaces tied to a decided pattern or backlog item; each gets an implementation in the repo that owns it
- Work is a service. A `Materializer` (for traust-engine) and a CLI command (for LLMs) are thin adapters that validate input, call one service and return its `JobResult`; no logic in either

## Coding practices

**Comments and docs**
- The code explains itself: clear names, small functions, types. No narrating comments, no docstrings that restate the signature
- Comment only a non-obvious *why* (a workaround, a constraint), in one line
- API overviews belong in the README, not in module docstrings

**Types and data**
- Type hints on every signature
- `Model` for internal objects (strict), `Dto` for boundary data (tolerant); frozen dataclasses for value objects
- Parse once at the edge; no bare `dict` across a function boundary
- Enums, not strings, for closed sets
- Unknown or unmeasured is `None`, never `0`

**Structure**
- Repository pattern: one repository per aggregate, written on SQLAlchemy Core; no ORM mapped classes, no generic CRUD base
- Domain objects never know about the database; rows map to models only inside repositories
- Service functions receive a unit of work, a service or a provider; they never open connections, build paths, read env vars or start processes
- `Context` only at entry points; pass the specific dependency, not `Context`
- No `subprocess` outside `ProcessRunner`, no clock reads outside `Clock`
- Interfaces are `Protocol`s defined where they are consumed
- Pure logic (routing, report building) has no I/O

**Errors**
- Raise `traust_core.v1.domain` errors with context: what was being done, on what
- Wrap driver and library errors with `raise ... from e`; never swallow them

**Tests**
- Every repository, store and provider has contract tests that run against each implementation (memory, sqlite, Postgres when `TRAUST_TEST_DATABASE_URL` is set)
- Pure functions get table tests
- Test names say the behaviour they protect
- Worked examples in `tests/v1/example/` are the pattern to copy; keep them current

**Scope**
- Smallest change that does the job; no drive-by refactors
- A new public module needs a README row and contract tests before merge
- Lint: line length 100; ruff E/W/F/I/UP/B/SIM/PTH/RUF
