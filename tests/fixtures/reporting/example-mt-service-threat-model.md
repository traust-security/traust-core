# Threat Model: example-mt-service

## 1. System context

A tenant could read another tenant's records through an authorization gap
in the shared API. The most important action is scoping queries by tenant.

example-mt-service serves many tenants from one shared deployment.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| tenant data | per-tenant records | critical |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| tenant api | REST API, per-tenant tokens | tenant → shared service | tenant data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs | isolation_dimensions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Cross-tenant data read via missing query scoping on the tenant api | remote_auth | tenant api | tenant data | critical | possible | unmitigated | none | | | privilege, authentication |
| T2 | DoS via tenant api flood | remote_unauth | tenant api | tenant data | medium | possible | mitigated | rate limit | | | |

## 5. Deprioritized

| threat | reason |
|---|---|

## 6. Open questions

- none

## 7. Provenance

- mode: bootstrap
- date: 2026-07-20
- target: targets/example-mt @ abc1234
- inputs: none
- owner: unset
- harness_version: 0.119.0-abc1234

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| scope every query by the caller's tenant id | T1 | yes | S |

## 10. Tenant boundaries

| boundary_id | interface | kind | exposure | complexity | privilege | encryption | authentication | connectivity | hygiene | threat_ids | isolation_review_ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
| IF-1 | tenant api | api | tenant | high | partial | yes | no | yes | partial | T1 | analysis-results/isolation/example-mt-service/ |
| IF-2 | metrics store | data-store | internal | low | yes | na | yes | yes | yes | | |
