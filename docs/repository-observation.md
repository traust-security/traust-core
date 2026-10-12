# Repository observation ownership and migration sources

This implements the observation part of [XWING-2214](https://redhat.atlassian.net/browse/XWING-2214), revised October 9, 2026, on top of [Core PR #4](https://github.com/traust-security/traust-core/pull/4). It moves the domain work introduced in [Traust PR #58](https://github.com/traust-security/traust/pull/58) into Core. It does not implement the pack router or the engine controller.

## Source for each move

The October 9 placement sections in [XWING-2205](https://redhat.atlassian.net/browse/XWING-2205) and XWING-2214 supersede older pack-based sketches. [Shaun's review](https://github.com/traust-security/traust/pull/58#issuecomment-6069412172) explains the ownership correction; the newer ticket further specifies that only forge facts are persisted.

| From Traust #58 / its legacy source | Destination | Requirement/source |
|---|---|---|
| `traust_pack_security.models` and observation comparison vocabulary | `models.portfolio`: `ObservationTarget`, `ForgeFacts`, assembled `RepoState`, `ComparisonStatus` | XWING-2214 “Where code goes”: models in Core; unknown facts remain `None`; pack keeps lane/event vocabulary |
| `traust_pack_security.repos.repo_state` and its embedded DDL | `repositories.portfolio` stores only `ForgeFacts`; `portfolio_forge_facts` DDL is owned by Contracts | XWING-2214 explicitly says never store `RepoState`; XWING-2205 assigns storage contracts to Contracts |
| `observe_repo` / stage1 and stage2 per-repository observation | `PortfolioService.record_forge_facts`, typed source provider | XWING-2214 assigns observation, quota and breaker handling to PortfolioService using SourceProvider |
| `ForgeClient`, `LegacyForgeClient`, `gh_*` and `gitlab_*` fetch helpers | `providers.sources` extended with compare/quota; `providers.forge.CommandSourceProvider` uses ProcessRunner | XWING-2214 says extend the existing source provider, drop the private ForgeClient; Core PR #4 supplies the provider/process pattern |
| Date/LOC-based age and churn calculation | `AssessmentService.freshness` | XWING-2214 names this owner; existing formulas come from `build_rescan_worklist.py` |
| `_LIVE_SQL` and maximum live critical/high count across sibling filings | `repositories.findings.open_count`, composed by PortfolioService | XWING-2214 prerequisite note: whoever lands first implements XWING-2213's count; [XWING-2213](https://redhat.atlassian.net/browse/XWING-2213) assigns findings reads to Core |
| `_REPOS_SQL`, freshest-audit dedupe, `_report_meta`, inventory membership and exposure designations | Core assessment/analysis-results/portfolio/designation repositories; AssessmentService assembles the baseline | XWING-2214 removes LegacyObservationInputs; XWING-2213 places these reads and population/bootstrap policy in Core |
| `risk_tier`, `exposure_class`, change metrics | `PortfolioPolicy` and pure functions in `services.portfolio` | XWING-2214 names PortfolioPolicy; XWING-2205 keeps data meaning/rules in Core |
| Observer construction and connection/process configuration | `Context.repository_observation`; `context.observation.command_source` supports the transitional batch adapter | Core PR #4 and [XWING-2208](https://redhat.atlassian.net/browse/XWING-2208) require Context wiring and repository/unit-of-work patterns |
| Observation fixtures and storage/provider tests | Core tests; thin CLI tests stay in Traust | XWING-2214 says retain recorded fixtures, field mapping, failure behavior and batch guarantees |

The original behavior source is [the pre-migration worklist](https://github.com/traust-security/traust/blob/0b11ecc0d190edbe1e19b208bb4470e29f1cf70c/src/traust/cli/build_rescan_worklist.py). The observation expectations are retained byte-for-byte, not regenerated to match this implementation.

## Call flow

```text
Traust command -> Context.repository_observation
  -> PortfolioService.record_forge_facts
     -> AssessmentService.observation_target -> read-only legacy repositories
     -> SourceProvider.info / quota / compare -> ProcessRunner -> gh or glab
     -> PortfolioRepository.save_forge_facts -> configured Core database
  -> PortfolioService.repo_state
     -> latest baseline + stored forge facts + live findings + current clock
     -> freshly assembled RepoState (returned, never persisted)
```

`repo_state()` never makes forge calls. It recomputes age, churn, tier and exposure. Cached comparisons are usable only for the audited SHA, audit date and audited/bootstrap context against which they were measured. A changed baseline requires a new observation; the returned state does not reuse a comparison from another baseline.

## Implementation choices for review

These details are choices made here, not verbatim Jira API contracts:

- The observation lookup is canonical URL, falling back to the existing filing key for missing/invalid URLs. These are match keys, not replacements for Core entity UUIDs. Legacy projections do not yet carry registered CodeLine UUIDs, so `ObservationTarget.code_line_id` and `Freshness.code_line_id` can be absent. The existing UUID freshness call remains available when the supplied repository can resolve its baseline; the legacy SQL adapter cannot provide that mapping.
- Store the latest `ForgeFacts` with its baseline context and timezone-aware timestamp. Older observations cannot overwrite newer observations, including when a URL is repaired. Unavailable measurements are NULL, measured zero/false remains zero/false. This is not an event history.
- Legacy audit reports may contain abbreviated SHAs. Preserve those at this compatibility boundary rather than weakening the existing full `GitSha` value type.
- The read-only legacy metadata reader uses the named `SecurityAuditArtifact` schema view, without imposing a new whole-document validation gate on old partial reports. New artifact writes still use the existing strict publisher. LOC numbers and companion declarations retain the legacy parsing rules.
- Legacy SQLite findings/inventory inputs are opened read-only. They are separate from the explicitly configured Core database; the CLI does not invent a graph database or provision tables. Contracts owns bootstrap/migration. The adapters implement the observation reads needed now, not all of XWING-2213 or the full FindingRepository surface.
- Single-repository observations check live remaining GitHub quota. The batch path keeps its index-based quota allocation, shared ban breaker and thread pools. Explicit `quota_deferred`/breaker arguments support that boundary; an individual observation does not reserve fleet capacity.
- Forge host kinds are configured in Core's `forge_hosts`; subprocess allowlists, credential environment forwarding and timeouts use Core process configuration. GitHub commands explicitly select the validated host rather than relying on ambient GH_HOST. No HTTP client or SDK runner is introduced.

The Contracts dependency upgrade also requires Core to bootstrap product/repository tables before their foreign keys and recognize the newer optional artifact-binding columns. DDL execution explicitly disables parameter binding so literal percent signs and colon-prefixed words in Contracts SQL are not interpreted as driver placeholders. These are dependency compatibility changes, not additional observation requirements.

## Verification

`make lint-fix`, `make test`, and `make db-up && make test-integration` cover the new APIs and existing Core behavior. Repository contracts run against memory, SQLite and PostgreSQL. Observation tests replay the thirteen retained reference cases, cover every comparison status, assert no-network behavior, and show that current findings/age and changed audit baselines affect assembled state without mutating cached facts.

The corresponding Traust PR retains the old batch scheduler and its tests, replaces forge/policy internals with Core delegates, and tests the actual CLI through Context and SQLite. The new Router and its complete 302-case parity comparison remain separate work.
