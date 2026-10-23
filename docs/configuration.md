# Configuration: ledger and identity

traust-core reads one YAML file into `Config` (`Context.from_file(path)`; `traust-server --config path`). Unknown keys are rejected. This page covers the two sections that replaced traust-ledger's service settings; the rest are in `context/config.py`.

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
