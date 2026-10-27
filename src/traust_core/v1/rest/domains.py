"""The domains the REST API serves: one package each under rest/, exposing `router`."""

from __future__ import annotations

from types import ModuleType

from traust_core.v1.rest import (
    assessments,
    findings,
    health,
    identity,
    ledger,
    ops,
    portfolio,
)

DOMAINS: tuple[ModuleType, ...] = (
    health,
    identity,
    ledger,
    ops,
    findings,
    portfolio,
    assessments,
)
