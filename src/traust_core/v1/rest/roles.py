"""Serving by role: one image, three roles, so a slow read can never starve a write. A
route belongs to exactly one role - ops (run orders and their leases), query (reads, and
the POSTs that only read), command (every other write) - and health and identity serve
in every role. `all` serves everything (the default, and a development server)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ALL = "all"
    QUERY = "query"
    COMMAND = "command"
    OPS = "ops"


_OPS_PREFIXES = ("/v1/orders", "/v1/preflight")
# POSTs that read: a query body too large or too structured for a query string
_READ_POSTS = frozenset({"/v1/dashboards:query", "/v1/repositories:resolve", "/v1/onboarding/plan"})
_READ_METHODS = frozenset({"GET", "HEAD"})
_EVERY_ROLE = ("/v1/healthz", "/v1/whoami")


def role_of(path: str, methods: set[str]) -> Role:
    """The one role a route belongs to."""
    if path.startswith(_OPS_PREFIXES):
        return Role.OPS
    if path in _READ_POSTS or methods <= _READ_METHODS:
        return Role.QUERY
    return Role.COMMAND


def serves(role: Role, path: str, method: str) -> bool:
    """Whether this role answers a request (health and identity in every role)."""
    return (
        role is Role.ALL or path.startswith(_EVERY_ROLE) or role_of(path, {method.upper()}) is role
    )
