"""OpenAPI metadata for the REST API: the description Swagger renders and per-domain tags."""

from __future__ import annotations

DESCRIPTION = """\
The deployable HTTP transport over traust-core's domain services, for SCI and other remote
callers. The local CLI and traust call the services in-process and need none of it.

**Conventions**

- **Authentication** — every route needs an OIDC/bearer token (`Authorize` above). The token
  verifies to a `Principal`; authorization runs in the service method, so the same check applies
  in-process. Runner identities may claim/heartbeat/complete their work, but authentication alone
  never authorizes a report mutation. Native recording requires an owned active lease, a
  server-authorized asset and repository, and run-order-bound provenance. Direct decisions and
  restatements need a verified human (restatement needs the `restate` role).
- **Errors** — one shape, `application/problem+json` (RFC 9457): `type`, `title`, `status`,
  `detail`, `instance`, `request_id`. Typed core errors map to status codes in one place.
- **Lists** — cursor paging (keyset); pass `limit` (1-1000) and the opaque `cursor`/`after`.
- **Correlation** — send `X-Request-ID` or W3C `traceparent`; it is echoed on the response and
  every log line. One is minted when absent.

The document is generated from the pydantic models and routes; it is not hand-edited. The SDK is
generated from it.
"""

TAGS: list[dict[str, str]] = [
    {"name": "health", "description": "Liveness; no authentication."},
    {"name": "identity", "description": "The verified caller (`whoami`)."},
    {
        "name": "ops",
        "description": "The run-order queue (claim/heartbeat/complete), reads and the feed.",
    },
    {
        "name": "findings",
        "description": "Native triage, findings, decisions (countersign, restate) and review.",
    },
    {"name": "portfolio", "description": "Inventory: repositories, refs, owners and products."},
    {"name": "assessments", "description": "Assessments of a ref or repository."},
    {"name": "exposure", "description": "Advisories, their blast radius, packages and dependents."},
    {"name": "remediation", "description": "Native remediation-verification report recording."},
    {"name": "validation", "description": "Native machine-validation records and evidence."},
    {
        "name": "ledger",
        "description": "The decision ledger: layers, events, verification and checkpoints.",
    },
]
