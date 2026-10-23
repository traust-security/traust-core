from __future__ import annotations

import pytest

from traust_core.v1.errors import AuthenticationError
from traust_core.v1.models.identity import (
    Credential,
    DirectoryStatus,
    IdentitySource,
    Principal,
    Role,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.base import Readiness
from traust_core.v1.services.identity import IdentityService

ALICE = Principal(
    identity="alice@example.com",
    kind=ActorKind.HUMAN,
    display="Alice",
    verified_by=IdentitySource.OIDC,
)
RUNNER = Principal(identity="runner-7", kind=ActorKind.MACHINE, display="runner-7")


class Provider:
    def __init__(self, principal: Principal) -> None:
        self.principal = principal

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def authenticate(self, credential: Credential) -> Principal:
        return self.principal


class Directory:
    def __init__(self, status: str) -> None:
        self.answer, self.asked = status, []

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def status(self, principal: Principal) -> DirectoryStatus:
        self.asked.append(principal.identity)
        return DirectoryStatus(identity=principal.identity, status=self.answer)


TOKEN = Credential(token="t")


def test_without_a_directory_the_token_stands() -> None:
    assert IdentityService(Provider(ALICE)).authenticate(TOKEN) == ALICE


@pytest.mark.parametrize("status", ["terminated", "contingent", "not_found", "unavailable"])
def test_the_directory_refuses_anyone_not_active(status: str) -> None:
    with pytest.raises(AuthenticationError, match=status):
        IdentityService(Provider(ALICE), Directory(status)).authenticate(TOKEN)


def test_the_directory_is_about_people() -> None:
    directory = Directory("terminated")
    assert IdentityService(Provider(RUNNER), directory).authenticate(TOKEN) == RUNNER
    assert directory.asked == []
    assert IdentityService(Provider(ALICE), Directory("active")).authenticate(TOKEN) == ALICE


def test_a_verified_admin_may_administer_and_restate() -> None:
    service = IdentityService(Provider(ALICE), admins=[" Alice@Example.com ", ""])
    principal = service.authenticate(TOKEN)
    assert principal.has_role(Role.ADMIN) and principal.has_role(Role.RESTATE)


def test_no_admins_means_nobody_and_unverified_admins_get_nothing() -> None:
    assert not IdentityService(Provider(ALICE)).authenticate(TOKEN).roles
    unverified = ALICE.model_copy(update={"verified_by": None})
    service = IdentityService(Provider(unverified), admins=["alice@example.com"])
    assert not service.authenticate(TOKEN).roles


def test_a_service_account_can_be_an_admin() -> None:
    rotation = RUNNER.model_copy(
        update={"identity": "key-rotation", "verified_by": IdentitySource.OIDC}
    )
    principal = IdentityService(Provider(rotation), admins=["Key-Rotation"]).authenticate(TOKEN)
    assert principal.has_role(Role.ADMIN) and not principal.is_verified_human()
