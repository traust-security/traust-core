"""The domains the REST API serves: one package each under rest/, exposing `router`."""

from __future__ import annotations

from types import ModuleType

from traust_core.v1.rest import (
    artifacts,
    assessments,
    exposure,
    findings,
    health,
    identity,
    ledger,
    ops,
    portfolio,
    remediation,
    validation,
)

DOMAINS: tuple[ModuleType, ...] = (
    health,
    identity,
    ledger,
    ops,
    findings,
    portfolio,
    artifacts,
    assessments,
    exposure,
    remediation,
    validation,
)
