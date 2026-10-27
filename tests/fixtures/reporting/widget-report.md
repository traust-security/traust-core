# Security audit: example/widget

| Field | Value |
| --- | --- |
| **Date** | 2026-10-20 |
| **Scope** | widget-operator image, linux/amd64 |
| **Repository** | https://git.example.test/example/widget |
| **Commit** | 0123456789abcdef0123456789abcdef01234567 |
| **Harness Version** | 0.61.2-dev |

---

## 1. Executive Summary

No exploitable issue in the image: the rootfs SBOM carries no package with a fixed advisory and the entrypoint runs as non-root.

| Severity | Count |
| --- | --- |
| **Critical** | 0 |
| **High** | 0 |
| **Medium** | 0 |
| **Low** | 0 |
| **Informational** | 0 |

---

## 2. Severity Criteria

| Level | Definition |
| --- | --- |
| **Critical** | Critical per the pack's severity rubric. |
| **High** | High per the pack's severity rubric. |
| **Medium** | Medium per the pack's severity rubric. |
| **Low** | Low per the pack's severity rubric. |

---

## 3. Detailed Findings

### WIDGET-0123456-001 — SQL built from request input

|  |  |
| --- | --- |
| **Severity** | **High** |
| **CWE** | CWE-89 |
| **CVSS** | 8.1 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Location** | `pkg/db/query.go:40-44` (query concatenation) |
| **Location** | `pkg/db/other.go:7` |
| **Category** | injection |

**Description**

A long enough description of the defect that satisfies the schema's fifty characters.

**Remediation**

Use parameterised queries.

---

### WIDGET-0123456-002 — Weak hash for tokens

|  |  |
| --- | --- |
| **Severity** | **Medium** |
| **CWE** | CWE-328 |
| **Location** | `pkg:golang/example.test/hash@v1.0.0` |
| **Location** | `internal/token.go:see above` |
| **Category** | cryptography |

**Description**

A long enough description of the defect that satisfies the schema's fifty characters.

**Remediation**

Switch to SHA-256.

---

### WIDGET-0123456-003 — Fixed path traversal

|  |  |
| --- | --- |
| **Severity** | **Critical** |
| **CWE** | CWE-22 |
| **Location** | `oci-config:User` |

**Description**

A long enough description of the defect that satisfies the schema's fifty characters.

**Remediation**

Already fixed upstream.

---

## 4. Findings Summary

| Severity | Count | Finding IDs |
| --- | --- | --- |
| **Critical** | 0 | — |
| **High** | 0 | — |
| **Medium** | 0 | — |
| **Low** | 0 | — |

---

## 5. Remediation Roadmap

| Priority | Action | Addresses |
| --- | --- | --- |
| **P3** | Pin the base image by digest in the Containerfile | hygiene |

---

## 6. Negative Results (Verified Clean)

- **fuzzing**: skipped: tool_missing
