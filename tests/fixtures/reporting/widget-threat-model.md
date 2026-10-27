# Threat Model: example-repo

## 1. System context

_not recorded_

## 2. Assets

| asset | description | sensitivity |
|---|---|---|

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|

## 4. Threats

| id | threat | actor | surface | asset | severity | likelihood | impact | status | controls | evidence | attack_refs | isolation_dimensions |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Cross-tenant data theft via SQL injection in list parameters | remote_auth, insider | list/search query parameters | fleet service-log database | unrated | legacy almost_certain | legacy critical | unmitigated | search values are parameterized, but orderBy is string-built | EXAMPLE-001, EXAMPLE-002 | T1190, T1078 | privilege |
| T2 | Operator service account can read secrets fleet-wide | local_admin | controller-manager ClusterRole | Cluster secrets | high | medium 4.375 | high 7.25 technical | partially_mitigated | namespaced in most install modes |  |  |  |

## 5. Deprioritized

| threat | reason |
|---|---|

## 6. Open questions

_none_

## 7. Provenance

- mode: bootstrap
- date: 2026-01-01
- target: https://example.test/repo @ abc1234
- inputs: unset
- owner: unset
- harness_version: 0.1.0-abc1234

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| parameterized queries everywhere | T1 | yes | S |

## 10. Tenant boundaries

| boundary_id | interface | kind | exposure | complexity | privilege | encryption | authentication | connectivity | hygiene | threat_ids | isolation_review_ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
| IF-1 | service-log list API | api | tenant | medium |  |  |  |  |  | T1 |  |

## 11. Risk ratings

Rated with the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) (OWASP Foundation). Each factor is scored 0-9; likelihood and impact are the means of their factors.

### T2 — high

| factor | score | reason |
|---|---|---|
| skill_level | 5 |  |
| motive | 2 |  |
| opportunity | 7 |  |
| population_size | 1 |  |
| ease_of_discovery | 3 |  |
| ease_of_exploit | 6 |  |
| awareness | 9 | the pattern is publicly documented |
| intrusion_detection | 2 |  |
| confidentiality | 9 |  |
| integrity | 7 |  |
| availability | 5 |  |
| accountability | 8 |  |
