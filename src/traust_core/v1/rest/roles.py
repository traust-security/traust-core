"""Serving by role: one image, four roles, so a slow read can never starve a write and a
report never shares the request path. A route belongs to exactly one HTTP role - ops (run
orders and their leases), query (reads, and the POSTs that only read), command (every other
write; a report request queues an order, so it is one) - and health and identity serve in
every role. The reports role serves no routes: it is the worker that builds report orders,
its own process. `all` serves every route (the default, and a development server). The
OpenAPI publishes each operation's serving role as its `x-traust-role` extension (`every`
for health and identity), so a client sends each call to that role's URL."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ALL = "all"
    QUERY = "query"
    COMMAND = "command"
    OPS = "ops"
    REPORTS = "reports"


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


def serving_role(path: str, method: str) -> str:
    """The role that serves a route, as the OpenAPI's `x-traust-role`: `every` for health
    and identity, else the route's one role (`role_of`)."""
    if path.startswith(_EVERY_ROLE):
        return "every"
    return role_of(path, {method.upper()}).value


def serves(role: Role, path: str, method: str) -> bool:
    """Whether this role answers a request (health and identity in every role)."""
    return (
        role is Role.ALL or path.startswith(_EVERY_ROLE) or role_of(path, {method.upper()}) is role
    )
