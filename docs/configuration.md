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
| `execution.sandbox` | `none` (default) or `podman`: how lanes run a target's own build and test code |
| `campaign.tracking_reference`, `campaign.display_name` | the tracking key and title reports cite |
| `remediation.fork_org`, `remediation.private_forge_hosts` | where fixes are pushed |
| `forge_tokens` | forge host -> the environment variable holding its API token, beside `forge_hosts` |
| `overrides.rule_pack_allowlist` | enables supplemental rule packs; absent: none. The only override: tool pins, safe-exec profiles and the feeds registry are the project's and ship in `context/shipped/` (`Context.register_toolchain()` / `register_feeds()` read them) |

### Safe execution

`ctx.safe_exec` uses the shipped profiles. `validation-step` has restricted posture, no
static curl hosts, and gives `KUBECONFIG`, `VF_OAUTH_TOKEN`, and caller-supplied environment
only to `curl`, `oc`, and `kubectl` pipeline segments. The other shipped profiles default to
baseline. Deploy the compatible contracts schema and core first, then the consumer that supplies
authorized per-request hosts, before enabling restricted validation in an estate. Keep the
estate on hold until those dependencies are deployed; otherwise HTTP validation is refused.

Profiles can set `posture` (`restricted`, `baseline`, `privileged`, or aliases `high`,
`medium`, `low`), `curl_allowed_hosts`, and `keep_env_heads`. Restricted requires an exact
host grant; baseline allows public names and global IP literals, plus explicitly granted
internal hosts; privileged allows hosts unless a list is supplied. Profile and call-time
`allowed_hosts` are combined, normalized, and matched as exact hostnames, not wildcard
patterns. Redirects are denied under restricted and baseline and whenever a host list is
enforced, as are Host/authority and request-target overrides. Curl options are allowlisted,
`.curlrc` is disabled, proxy routing is removed from inherited environments, and target-controlled
routing and `HOME` assignments are refused.
Hostname checks do not prove DNS ownership and safe execution is not a socket sandbox;
build tools can still reach their configured dependency mirrors.

`validate_argv`, `vet_command_string`, and `run` accept keyword `allowed_hosts`.
`run_segments` is a trusted low-level API for segments that the caller already vetted (or
an explicitly reported CLI bypass); it does not vet arbitrary command arguments. Structured
HTTP callers may provide `curl_connect_to=(host, origin_port, local_port)`,
`curl_stdin_headers=("Name: value", ...)`, `curl_ca_bundle=...`, and the trusted
`curl_insecure_tls`/`curl_insecure_lab` flags only from operator-authorized policy after vetting
the original command. The request must have exactly one explicit `--url`; core requires its host
and port to match the tunnel binding and passes headers through stdin. Private headers cannot
accompany redirects, tracing, or a Host/authority override. Disabling TLS verification requires
explicit lab authorization even for a tunnel or private headers; verification remains the default.
These bindings do not themselves authorize the target or credential.

Explicit validation scopes carry HTTP targets and per-context API identity and discovery policy,
including route domains, node networks, credential forwarding, TLS and session checks. Inline
and inferred scopes cannot grant these permissions. Node discovery names come from
`ClusterScope.http_discovery.nodes`: an absent grant denies discovery, empty names permit listing,
and nonempty names restrict it to those nodes. Node address types and networks remain mandatory
runtime checks. Scope binding rejects conflicting HTTP policies for the same context.
When a Route probe names a literal origin, approval requires that host to match its exact Route
target or an applicable discovery domain; execution must also verify the resolved Route origin.
Namespace-less direct HTTP uses a distinct HTTP action, not cluster-wide Kubernetes
permission. It requires an explicit exact-host grant, a named context with a pinned
API, and the permitted action; expiry, off-limits and denied verbs still apply.
Structured POST, PUT, PATCH and DELETE steps require destructive classification:
the structured HTTP contract has no compensating rollback.

`ValidationScope.expires` is valid through its date; timezone-aware `expires_at` expires at the
specified instant. Bindings intersect both constraints. `decide`/`permits` accept a date or an
aware datetime; timestamp-scoped grants require an aware datetime. Cluster crypto checks every
discovery read and exec against the current clock and action. A denied operation is recorded as a
gap and marks its requested namespace denied in the census scope. Expiry, off-limits and denied
verbs also apply to HTTP actions; node mutations still require
separate cluster-wide authorization.
