"""The domains the REST API serves: one package each under rest/, exposing `router`."""

from __future__ import annotations

from types import ModuleType

from traust_core.v1.rest import (
    artifacts,
    assessments,
    dashboards,
    exposure,
    findings,
    health,
    identity,
    ledger,
    ops,
    portfolio,
    registry,
    remediation,
    reports,
    validation,
)

DOMAINS: tuple[ModuleType, ...] = (
    health,
    dashboards,
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
    reports,
    registry,
)
