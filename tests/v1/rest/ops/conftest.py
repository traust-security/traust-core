"""Ops endpoints over a real Context on SQLite: a runner (machine) acts; a person only reads."""

from __future__ import annotations

from traust_core.v1.context import Context


def runner(context: Context, identity: str = "runner-7") -> dict[str, str]:
    """A verified machine token: the only identity that may claim, heartbeat and complete."""
    token = context.local_issuer.mint(identity, machine=True).token.get_secret_value()
    return {"Authorization": f"Bearer {token}"}
