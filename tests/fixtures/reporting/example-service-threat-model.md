# Threat Model: example-service

## 1. System context

An attacker could take over the service by uploading a malformed audio
file. The most important action is sandboxing the decoder.

example-service decodes user-supplied audio files.

### Threat actor landscape

`opportunistic` — internet-exposed decoder with public exploit history.

## 2. Assets

| asset | description | sensitivity | regulatory_scope | example_records |
|---|---|---|---|---|
| host process integrity | native decoder memory | critical | none | |
| user PII | uploader account records | high | GDPR | name, email |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| audio file upload | WAV/FLAC decode path | untrusted file → process memory | host process integrity |
| admin API | operator-only config | remote_auth → admin | user PII |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | RCE via untrusted audio file parsing | remote_unauth | audio file upload | host process integrity | critical | likely | unmitigated | none | CVE-2026-29022, abc1234def |
| T2 | linddun: re-identification via exported logs | remote_auth | admin API | user PII | medium | possible | partially_mitigated | RBAC | |

## 5. Deprioritized

| threat | reason |
|---|---|
| physical access | out of scope |

## 6. Open questions

- Is the decoder sandboxed in production?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-12
- target: targets/example @ abc1234
- inputs: none
- owner: unset
- harness_version: 0.33.0-abc1234

### Update history

| date | changes | reason |
|---|---|---|
| 2026-07-12 | added T2 | LINDDUN overlay |

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| sandbox the decoder process | T1 | yes | M |

## 9. Attack scenarios

### T1 — RCE via untrusted audio file parsing

An opportunistic attacker uploads a crafted WAV file. The decoder trusts
the length field and corrupts memory, handing over the process. Every
upload endpoint reaches this code, and no sandbox contains it.
