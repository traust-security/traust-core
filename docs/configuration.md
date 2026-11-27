# Configuration: ledger and identity

traust-core reads one YAML file, `traust.yaml`, into `Config` (`Config.from_home(home)`, `Context.from_file(path)`; `traust-server --config path`), checked against traust-contracts' `config/v1/traust.schema.json`. Unknown keys are rejected. No `traust.yaml` keeps the zero-config defaults (SQLite and artifacts under `~/.traust`). This page covers the two sections that replaced traust-ledger's service settings; the rest are in `context/config.py`.

```yaml
ledger:                                   # absent: no proof chain; decisions are still recorded
  key_path: /etc/traust/cosign.key
  public_key_path: /etc/traust/cosign.pub
  previous_public_key_path: null          # during a key rotation: old signatures still verify
  required: true                          # refuse a write that can't be signed

identity:                                 # absent: no caller can be verified (REST answers 401)
  issuers:
    - issuer: https://sso.example.com/realms/example
      jwks_url: https://sso.example.com/realms/example/protocol/openid-connect/certs
      audience: traust                    # optional; without it, tokens for other services pass
  identity_claim: email                   # a token with this claim is a person
  machine_claim: azp                      # else this (or sub): a machine
  trust_local: false                      # local tokens (traust's own issuer) verify a person?
  directory_command: [python3, /opt/example/bin/validate_employee.py]
  directory_timeout_seconds: 60
  admins: [alice@example.com, key-rotation]   # people or service accounts
  restatement_approvers: 0                # independent approvers a correction must name
  login:                                  # where the CLI logs in (device code, service accounts)
    issuer: https://sso.example.com/realms/example
    client_id: traust-cli
```

## What each setting does

| Key | Effect |
|---|---|
| `ledger.key_path` | cosign private key; every decision write signs its layer's root (`decide`, `restate`), a triage `record` signs once at the end |
| `ledger.public_key_path` / `previous_public_key_path` | verify signatures; during a rotation set both, `checkpoint` each layer, then drop the previous key |
| `ledger.required` | a write whose layer can't be signed fails and nothing is written |
| `identity.issuers` | trusted OIDC issuers: a token's `iss` picks one; its JWKS checks the signature, then expiry, not-before and audience. Every entry names its `issuer` |
| `identity.trust_local` | whether tokens from this machine's `local` issuer (`<home>/local-jwks.json`) verify a person; leave off unless the deployment is one person |
| `identity.directory_command` | run as `<command> <identity>`, prints `RESULT uid=<identity> status=<status>`; only `active` passes. The program must exist at startup |
| `identity.admins` | may checkpoint ledger layers; people among them may also restate (corrections stay human-only). Empty: nobody |
| `identity.restatement_approvers` | how many approvers besides its author a correction must name |
| `identity.login` | the provider `traust auth` logs in against; tokens are kept in `<home>/credentials.json` (owner-only) |

A server with report-recording asset bindings probes its own identity verifier
at startup; a planner passing preflight is not evidence that the writer is ready.
Decision writers need a ledger. A triage writer also needs a working required
signing pair and a nonblank secret in the variable named by `review.valve_salt_env`.
A read-only server with no recording bindings does not require these credentials.

## From traust-ledger's service settings

| traust-ledger (env) | traust-core |
|---|---|
| `LAAS_BACKEND_TYPE`, `LAAS_DATABASE_URL`, `LAAS_DATA_DIR` | `database.url` (layers and events are contract tables in the record store; no file backend) |
| `LAAS_IDENTITY_PROVIDER=oidc`, `LAAS_OIDC_JWKS_URL`, `LAAS_OIDC_ISSUER`, `LAAS_OIDC_AUDIENCE`, `LAAS_OIDC_TRUST` | `identity.issuers` (one entry per issuer; `issuer` is required) |
| `LAAS_OIDC_IDENTITY_CLAIM`, `LAAS_OIDC_MACHINE_CLAIM` | `identity.identity_claim`, `identity.machine_claim` |
| `LEDGER_TRUST_LOCAL_IDENTITY` | `identity.trust_local` |
| `LEDGER_LOCAL_IDENTITY` | `traust auth local` (mints with `Context.local_issuer`) |
| `LEDGER_DIRECTORY_COMMAND`, `LEDGER_DIRECTORY_TIMEOUT` | `identity.directory_command`, `identity.directory_timeout_seconds` |
| `LAAS_ADMIN_IDENTITIES` | `identity.admins` |
| `LAAS_RESTATEMENT_MIN_APPROVERS` | `identity.restatement_approvers` |
| `LAAS_SIGNING_REQUIRED` | `ledger.required` |
| `LAAS_SIGNING_KEY_PATH` | `ledger.key_path` (and `public_key_path` to verify) |
| `LAAS_SIGNING_METHOD=cosign` | keypair signing, the only method today |
| `LAAS_SIGNING_METHOD=sigstore-oidc`, `LAAS_OIDC_ISSUER_URL`, `LAAS_OIDC_CLIENT_ID` | not yet: keyless signing is a followup |
| `LAAS_TOKEN`, `LEDGER_TOKEN`, `LEDGER_TOKEN_PATH` | not yet: tokens come from `traust auth` (`<home>/credentials.json`) |
| `LAAS_LOG_LEVEL` | not yet: one logging setup from `Config` is `NEED(logging)` |

## Locations

`locations:` in `traust.yaml` says where the harness reads and writes runtime data; it is read into `Config.locations`. Relative paths resolve against the directory holding `traust.yaml`, URIs stay as written, unknown keys are ignored, and there are no environment overrides.

| Accessor | Value |
|---|---|
| `workspace_dir()` | `workspace`; unset or remote: `ConfigError` |
| `inputs_dir()` | `inputs`, else `<workspace>/inputs`; remote `inputs`: `ConfigError` |
| `analysis_results_dir()`, `progress_tracker_dir()`, `feeds_cache_dir()` | the local path, or `None` when unset or remote |
| `rule_drafts_dir()` | `rule_drafts`, else `<progress_tracker>/metrics/rule-mining/rule-drafts` |
| `portfolio_graph_db()` | `portfolio_graph`, else `<analysis_results>/graph/portfolio-graph.db` |
| `findings_db()` | `<analysis_results>/graph/findings.db` |

`Locations.require(value, name)` turns a `None` into a `ConfigError` naming the location.

## Adopter settings and shipped files

| Key | Effect |
|---|---|
| `feeds.osv_access` | `api` (default) queries the OSV API; `air-gapped` reads exported OSV records only (`Context.use_exported_advisories`). The feeds registry no longer carries this switch |
| `feeds.api_keys` | feed source -> the environment variable holding its API key (`{nvd: NVD_API_KEY}`). Optional: a source not named goes keyless at its lower rate limit, with no warnings; a named variable that is unset or empty logs an error and the source goes keyless. See [Feed API keys](#feed-api-keys) |
| `execution.sandbox` | `none` (default) or `podman`: how lanes run a target's own build and test code |
| `campaign.tracking_reference`, `campaign.display_name` | the tracking key and title reports cite |
| `remediation.fork_org`, `remediation.patch_prefix`, `remediation.private_forge_hosts` | where fixes are pushed: the mirror org, the patch-repository name prefix the convention computes (`patch-` by default), and the deployment's own forge hosts |
| `remediation.committer` | the machine identity fix commits are authored under (`traust-remediation` by default; a name ending in `-remediation`, email `<name>@localhost`), handed to the skill with the fork |
| `forge_tokens` | forge host -> the environment variable holding its API token, beside `forge_hosts` |
| `overrides.rule_pack_allowlist` | enables explicitly selected supplemental rule packs; absent: none. Sources may be local directories relative to the allowlist or HTTPS Git repositories pinned to a 40-hex commit. Enabled packs must pass the same native quality gates as the shipped rules |

## Adopter Opengrep rules

Set `overrides.rule_pack_allowlist` to an adopter-owned allowlist. For example:

```yaml
packs:
  acme:
    enabled: true
    source: rules/acme
    rules: [acme-authentication-check]
```

The source above resolves beside the allowlist file, not the process's working directory.
Keep native Opengrep fixtures beside their rule YAML, sharing its basename; every authored
rule requires both `ruleid:` and `ok:` cases. A pinned HTTPS Git source uses the existing
checkout and rules-subtree convention and must carry those fixtures too. Relative local
sources cannot select a single file: an enabled local pack is a directory.

For YAML targets use native test names such as `policy.test.yaml` or `policy.test.yml`
beside `policy.yaml`; proposal examples and staged `rule.skeleton.yaml` drafts follow
the same `.test.yaml` / `.test.yml` convention.

Only fixture paths present in each rule's native `check.matches` count toward coverage.
Expected autofix outputs such as `policy.fixed.py` cannot supply missing negative cases.

`opengrep_quality_report` checks without a database. Actual scans run native validation
and strict native tests over private snapshots and then consume those same snapshots.
Missing fixtures, skipped/unreported tests, unknown test IDs, duplicate rule IDs, failed
assertions, abnormal native exits, or invalid enabled sources refuse the run; there is no
validation bypass or silent fallback to only the public pack. Per-rule selection still
limits reported supplemental hits, but the supplied pack must pass quality checks.
These checks establish fixture behavior, not real application exploitability.

Adopter packs are additive. Portfolio/ledger mining, regression drafts, proposal checks,
calibration and corpus sweeps remain available; custom packs do not replace those lanes.
A sweep runs quality before checking out or iterating repositories, then reuses that
operation's private snapshot. Resumable results include a digest of its rule and fixture
paths and bytes; legacy rule-quality failures and changed inputs are rescanned. Each
independent operation still performs native validation and strict tests: no process-global
cache can reuse a receipt for mutable local inputs or a different runner.

Reports list only `supplemental_packs.applied`; invalid packs fail instead of appearing
as skipped supplements. Scanner transport failures raise `traust_core.v1.errors.ScannerError`;
its `ScannerFailure` reason distinguishes `scan_timeout`, `opengrep_failed` and
`invalid_output`, with configured timeout or exit code when available. Diagnostics contain
bounded classifications, not native stdout/stderr or parser source excerpts. Proposal
scan failures retain passed native receipts and fail the examples or explosion check
with the actual scan cause.

## Feed API keys

Some feed sources accept an API key for a higher rate limit. NVD answers about 5
requests per 30 seconds without one and about 50 with one. A key is optional:
without it, the source is queried keyless and nothing warns.

- **Which sources take a key** is the feeds registry's (`context/shipped/feeds.yaml`):
  a source declares `api_key_header`, the header its key travels in (NVD: `apiKey`).
  Only per-identifier GET sources can declare one.
- **Which variable holds the key** is the deployment's: name it under
  `feeds.api_keys` in `traust.yaml`. The key itself never goes in either file; it comes
  from the environment, for example a secret store synced into the worker's
  environment.

```yaml
feeds:
  api_keys:
    nvd: NVD_API_KEY   # the variable's name; set NVD_API_KEY from your secret store
```

Core reads every named variable before it registers any feed (`Context.register_feeds`).
A named variable that is unset or empty is logged at error level
(`operation: feeds.api_key`, `outcome: keyless`), and the source keeps working keyless at
its lower rate limit. When that source then answers 403 or 429, its error and readiness
detail say it was sent keyless, naming the unset variable, and is most likely rate-limited.
A new context picks the key up once the variable is set.

Core refuses a key at load, never at the first request, when:
- the source isn't registered, or declares no `api_key_header`;
- the key holds anything but visible ASCII.

Only a per-identifier GET source (a live `url_template`, or a cached `doc_url_template`)
may declare `api_key_header`. A whole-file feed or a POST source that declares one is a
registry error.

The key is sent only to the host its per-identifier template names. A probe on another
host goes keyless, and the key is never carried onto a redirect. It never appears in a
URL, log line, error or `repr`.

When the source refuses a request carrying the key (a 4xx other than 429), the readiness
check and the error say so and point at `feeds.api_keys.<source>` before the registry URL,
since NVD answers a wrong or revoked key with 404.

The feeds registry refuses any field it doesn't read, so a setting that would do
nothing fails loudly instead of being ignored.

