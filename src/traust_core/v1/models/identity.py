"""Who is acting: principals, the sources that verify them, their roles."""

from __future__ import annotations

from enum import StrEnum

import pydantic

from traust_core.v1.models.base import Model
from traust_core.v1.models.vocabulary import ActorKind


class Role(StrEnum):
    ADMIN = "admin"
    RESTATE = "restate"


class IdentitySource(StrEnum):
    LOCAL_USER = "local-user"
    DATABASE = "database"
    OIDC = "oidc"


class Principal(Model):
    identity: str
    kind: ActorKind
    display: str
    verified_by: IdentitySource | None = None
    roles: frozenset[Role] = frozenset()

    @property
    def ref(self) -> str:
        """What rows store as the actor (`requested_by`, `actor`): `<kind>:<verified identity>`."""
        return f"{self.kind}:{self.identity}"

    def is_verified_human(self) -> bool:
        """A person whose identity a trusted source proved (verified_by is set only then)."""
        return self.kind == ActorKind.HUMAN and self.verified_by is not None

    def has_role(self, role: Role) -> bool:
        return self.is_verified_human() and role in self.roles


LOCAL_ISSUER = "local"


class TrustedIssuer(Model):
    """An OIDC issuer whose tokens the deployment accepts; audience pins tokens to traust."""

    issuer: str
    jwks_url: str
    audience: str | None = None


class Credential(Model):
    token: pydantic.SecretStr


class DirectoryStatus(Model):
    identity: str
    status: str

    @property
    def active(self) -> bool:
        return self.status == "active"
