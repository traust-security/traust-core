# Configuration: ledger, identity, locations and settings

Configuration has three tiers:

| Tier | What | Where |
|---|---|---|
| 0 · baked | tool pins, base safe-exec profiles, the feeds registry, each setting's shipped default | `context/defaults/` (package data); `register_toolchain()` and `register_feeds()` read it |
| 1 · bootstrap | what is needed before the database exists: record and object stores, identity, ledger keys, process, http and logging limits, `locations` | one `traust.yaml` (contracts `config/v1/traust.schema.json`), `Config.from_home(home)` / `Config.from_file(path)` |
| 2 · settings | lane budgets, SLA policy, rule-pack allowlist, feed access, execution boundaries, remediation target, product-definitions map, org parameters, ADR registry, compliance mapping, benchmark targets | versioned scope-ref documents through `SettingsService`, never a file |

`traust.yaml` is read into `Config` (`Context.from_file(path)`; `traust-server --config path`); unknown keys are rejected, so a Tier 2 key there is an error. This page covers the ledger and identity sections, locations and settings; the rest are in `context/config.py`.

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

`traust.yaml`'s `locations:` says where the harness reads and writes runtime data (it replaced `locations.yaml`). Relative paths resolve against the directory holding `traust.yaml` (the config home), URIs stay as written, and there are no environment overrides.

| Accessor | Value |
|---|---|
| `workspace_dir()` | `workspace`; unset or remote: `ConfigError` |
| `inputs_dir()` | `inputs`, else `<workspace>/inputs`; remote `inputs`: `ConfigError` |
| `analysis_results_dir()`, `progress_tracker_dir()`, `feeds_cache_dir()` | the local path, or `None` when unset or remote |
| `rule_drafts_dir()` | `rule_drafts`, else `<progress_tracker>/metrics/rule-mining/rule-drafts` |
| `portfolio_graph_db()` | `portfolio_graph`, else `<analysis_results>/graph/portfolio-graph.db` |
| `findings_db()` | `<analysis_results>/graph/findings.db` |

`Locations.require(value, name)` turns a `None` into a `ConfigError` naming the location.

## Settings (Tier 2)

`ctx.services().settings` (REST: `/v1/settings`) versions each contracts `settings-kind` as imported artifacts of the same schema; the newest stored version is in force. A kind with a real shipped default (budget, sla-policy, rule-pack-allowlist, feed-access, execution-boundaries; compliance-mapping once the pack registers its mapping with `register_compliance_mapping`) has it as version 1, never written to the database. The others (org-parameters, adr-registry, benchmark-target, product-definitions-map, remediation-target) are adopter facts: `show` raises `SettingNotSet` naming the `traust settings set` fix until someone sets them.

| Door | Does |
|---|---|
| `list()` | every kind: default, changed or not set, the version in force and a one-line summary |
| `show(kind)` / `document(XArtifact)` / `find_document(XArtifact)` | the effective document, its `revision` removed |
| `set(kind, document, reason, principal)` | a new version, schema- and rule-checked; content equal to the effective document is a no-op |
| `reset(kind, reason, principal)` | the shipped default as a new version |
| `history(kind, page)` / `diff(kind, a, b)` | versions newest first with who, why and when; a unified diff between two |
| `record(doc, provenance, reason)` | a domain door's write (compliance policies, the answer key), attributed to the run |
| `digests()` | the documents in force, as run-manifest `ConfigDigest`s |

Every stored version carries `revision: {set_by, reason, set_at}`, written from the verified principal (or `run:<id>`) and the clock; anything a caller puts there is replaced. `set` and `reset` need a verified admin (`identity.admins`); on a laptop with a local record store the CLI acts as the OS user (`Context.local_user()`), and a shared record store (`database.url`) refuses that.
