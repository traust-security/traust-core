# Revert the Kubernetes ServiceAccount approval authority

This is a **placeholder** — a tracked reminder, not an immediate change.

## What to revert

The ServiceAccount (machine-principal) approval authority landed across:

- **core#449** — "Machine principals at the approve and pull-request door": `approve()` accepts the machine principal (the ServiceAccount) with the recording-grant scope; `record_pull_request` extended the same way
- **core#450** — "A start scope can cover the whole estate": the `all_repositories` flag on the recording start scope
- **sci#343** — "The auto-approval loop and the wired PR recorder": the loop that auto-approves with the platform identity
- **sci#344** — the loop riding the reads gate
- **contracts#149** — the `all_repositories` schema key
- **foundry#58** — the design doc

## Why revert later

The current implementation authorizes the platform's actions via the **Kubernetes ServiceAccount** (the `machine:system:serviceaccount:sci:sci` principal, the projected SA tokens verified through the cluster's OIDC issuer). This works, but it's a **transition shape**: the platform will move to **platform-native ServiceAccounts** — proper service identities issued by the platform's own identity layer (or an IdP service account), not the Kubernetes-native SA that happens to be available.

When the platform-native identities land:

1. The K8s-SA approval path (the machine-principal branch of `approve()` and `record_pull_request`) reverts or deprecates
2. The new service-identity principal kind carries the authority (the grants, the scopes, the audit trail's approver naming)
3. The `all_repositories` flag rides along or is re-scoped for the new kind
4. The auto-approval loop's identity swaps

## The design questions for the revisit

- The principal-kind vocabulary: does the platform-native identity introduce a `service` kind beside `machine`/`human`, or does the `machine` kind's semantics narrow to "the platform's trusted service identity" regardless of the token mechanism?
- The authority model: the grants (the recording scopes, the approval scopes) — do they re-target the new kind, or does the flag carry the authority across kinds?
- The audit trail: the approval records naming `machine:system:serviceaccount:...` — historical immutability vs the new naming
- The migration: the cutover from the K8s SA tokens to the platform identities (both accepted during the transition? a flag?)

## Assignment

**Reviewers: smith-xyz, chubirka** — this is a design-level revisit that belongs to the identity model's owners.
