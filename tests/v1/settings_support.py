"""Tier 2 settings in tests: set the way an admin would, through the settings service."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind, SettingKind

ADMIN = Principal(
    identity="admin@example.com",
    kind=ActorKind.HUMAN,
    display="admin",
    verified_by=IdentitySource.OIDC,
    roles=frozenset({Role.ADMIN}),
)


def configure(ctx: Context, kind: str, document: Mapping[str, Any]) -> None:
    ctx.settings().set(SettingKind(kind), document, "test setup", ADMIN)
