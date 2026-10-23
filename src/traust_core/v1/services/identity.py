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


class IdentityConfig(Model):
    """The `identity:` config section: whose tokens are accepted, the directory, the admins."""

    issuers: tuple[TrustedIssuer, ...] = ()
    identity_claim: str = "email"
    machine_claim: str = "azp"
    trust_local: bool = False
    directory_command: tuple[str, ...] = ()
    directory_timeout_seconds: float = 60.0
    admins: tuple[str, ...] = ()
    restatement_approvers: int = 0  # independent approvers a restatement must name


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
        if principal.is_verified_human() and principal.identity in self._admins:
            return principal.model_copy(update={"roles": principal.roles | ADMIN_ROLES})
        return principal
