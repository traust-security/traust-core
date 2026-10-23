from __future__ import annotations

from uuid import uuid4

import pytest

from traust_core.v1.models.identity import IdentitySource, Principal, Role
from traust_core.v1.models.vocabulary import ActorKind


def principal(
    kind: str = "human", verified: bool = True, roles: tuple[Role, ...] = ()
) -> Principal:
    return Principal(
        identity=f"{uuid4()}@example.com",
        kind=ActorKind(kind),
        display="someone",
        verified_by=IdentitySource.OIDC if verified else None,
        roles=frozenset(roles),
    )


@pytest.mark.parametrize(
    ("kind", "verified", "expected"),
    [("human", True, True), ("human", False, False), ("machine", True, False)],
)
def test_a_verified_human_is_a_person_a_trusted_source_proved(
    kind: str, verified: bool, expected: bool
) -> None:
    assert principal(kind, verified).is_verified_human() is expected


def test_a_role_counts_only_for_a_verified_human() -> None:
    assert principal(roles=(Role.RESTATE,)).has_role(Role.RESTATE)
    assert not principal(roles=(Role.RESTATE,)).has_role(Role.ADMIN)
    assert not principal(verified=False, roles=(Role.RESTATE,)).has_role(Role.RESTATE)
    assert not principal("machine", roles=(Role.ADMIN,)).has_role(Role.ADMIN)
