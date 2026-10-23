from __future__ import annotations

import logging
from collections.abc import Iterable

from traust_core.v1.errors import AuthenticationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.identity import Credential, Principal, Role, TrustedIssuer
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.identity import Directory, IdentityProvider

log = logging.getLogger(__name__)

ADMIN_ROLES = frozenset({Role.ADMIN, Role.RESTATE})


class LoginConfig(Model):
    """Where people log in from the CLI (device code) and service accounts get tokens."""

    issuer: str
    client_id: str
    scope: str = "openid"


class IdentityConfig(Model):
    """The `identity:` config section: whose tokens are accepted, the directory, the admins."""

    issuers: tuple[TrustedIssuer, ...] = ()
    identity_claim: str = "email"
    machine_claim: str = "azp"
    trust_local: bool = False
    directory_command: tuple[str, ...] = ()
    directory_timeout_seconds: float = 60.0
    admins: tuple[str, ...] = ()  # people or service accounts; restating stays human-only
    restatement_approvers: int = 0  # independent approvers a restatement must name
    login: LoginConfig | None = None


class IdentityService:
    """Who is calling: a verified token, cross-checked against the directory, with its roles."""

    def __init__(
        self,
        provider: IdentityProvider,
        directory: Directory | None = None,
        admins: Iterable[str] = (),
    ) -> None:
        self._provider, self._directory = provider, directory
        self._admins = frozenset(a.strip().lower() for a in admins if a.strip())

    def authenticate(self, credential: Credential) -> Principal:
        principal = self._provider.authenticate(credential)
        if self._directory is not None and principal.kind == ActorKind.HUMAN:
            status = self._directory.status(principal)
            if not status.active:
                log.warning("directory refused %s: %s", principal.identity, status.status)
                raise AuthenticationError(f"{principal.identity}: directory says {status.status}")
        if principal.verified_by is not None and principal.identity.lower() in self._admins:
            return principal.model_copy(update={"roles": principal.roles | ADMIN_ROLES})
        return principal
