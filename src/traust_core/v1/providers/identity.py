from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

import jwt

from traust_core.v1.errors import AuthenticationError, ServiceError
from traust_core.v1.models.identity import (
    LOCAL_ISSUER,
    Credential,
    DirectoryStatus,
    IdentitySource,
    Principal,
    TrustedIssuer,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.process import ProcessRunner

log = logging.getLogger(__name__)

_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
_RESULT = re.compile(r"^RESULT uid=(?P<uid>\S+) status=(?P<status>\S+)(?: auth=\S+)?$", re.M)
UNAVAILABLE = "unavailable"


class IdentityProvider(Protocol):
    def check(self) -> Readiness: ...

    def authenticate(self, credential: Credential) -> Principal: ...


class Directory(Protocol):
    def check(self) -> Readiness: ...

    def status(self, principal: Principal) -> DirectoryStatus: ...


class TokenIdentityProvider:
    """Verifies a bearer JWT against the trusted issuer its `iss` names, then maps its claims.

    A `local` token proves only that its holder can read this machine's key: trust_local decides.
    """

    def __init__(
        self,
        issuers: Sequence[TrustedIssuer],
        *,
        local_jwks: Path | None = None,
        trust_local: bool = False,
        identity_claim: str = "email",
        machine_claim: str = "azp",
    ) -> None:
        self._issuers: Mapping[str, TrustedIssuer] = {i.issuer: i for i in issuers}
        self._remote = {i.issuer: jwt.PyJWKClient(i.jwks_url, cache_keys=True) for i in issuers}
        self._local_jwks, self._trust_local = local_jwks, trust_local
        self._identity_claim, self._machine_claim = identity_claim, machine_claim
        for i in issuers:
            if i.audience is None and i.issuer != LOCAL_ISSUER:
                log.warning(
                    "issuer %s has no audience: its tokens for other services pass", i.issuer
                )

    def check(self) -> Readiness:
        trusted = sorted(self._issuers) + ([LOCAL_ISSUER] if self._local_jwks else [])
        return Readiness(ready=bool(trusted), detail=", ".join(trusted) or "no trusted issuers")

    def authenticate(self, credential: Credential) -> Principal:
        token = credential.token.get_secret_value()
        try:
            issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
        except jwt.InvalidTokenError as e:
            raise self._refuse("undecodable token") from e
        local = issuer == LOCAL_ISSUER and self._local_jwks is not None
        trusted = self._issuers.get(issuer) if isinstance(issuer, str) else None
        if trusted is None and not local:
            raise self._refuse(f"untrusted issuer {issuer!r}")
        audience = trusted.audience if trusted else None
        try:
            claims = jwt.decode(
                token,
                self._local_key(token) if local else self._remote_key(issuer, token),
                algorithms=_ALGORITHMS,
                issuer=issuer,
                audience=audience,
                options={"verify_aud": audience is not None},
            )
        except jwt.ExpiredSignatureError as e:
            raise self._refuse("token expired") from e
        except (jwt.PyJWTError, OSError, ValueError) as e:
            raise self._refuse(f"invalid token: {e}") from e
        return self._principal(claims, issuer)

    def _remote_key(self, issuer: str, token: str) -> object:
        return self._remote[issuer].get_signing_key_from_jwt(token).key

    def _local_key(self, token: str) -> object:
        keys = jwt.PyJWKSet.from_json(Path(str(self._local_jwks)).read_text(encoding="utf-8"))
        kid = jwt.get_unverified_header(token).get("kid")
        return next((k for k in keys.keys if k.key_id == kid), keys.keys[0]).key

    def _principal(self, claims: Mapping[str, object], issuer: str) -> Principal:
        machine, person = claims.get(self._machine_claim), claims.get(self._identity_claim)
        if person:
            kind, identity = ActorKind.HUMAN, str(person).lower().strip()
        elif machine or claims.get("sub"):
            kind, identity = ActorKind.MACHINE, str(machine or claims["sub"])
        else:
            raise self._refuse("no identity claims in token")
        if not identity:
            raise self._refuse(f"empty identity claim {self._identity_claim}")
        local = issuer == LOCAL_ISSUER
        source = IdentitySource.LOCAL_USER if local else IdentitySource.OIDC
        verified = self._trust_local or not local
        return Principal(
            identity=identity,
            kind=kind,
            display=identity,
            verified_by=source if verified else None,
        )

    @staticmethod
    def _refuse(reason: str) -> AuthenticationError:
        log.warning("authentication refused: %s", reason)
        return AuthenticationError(reason)


class CommandDirectory:
    """The deployment's directory: `<command> <identity>` prints `RESULT uid=<id> status=<s>`.

    Only `active` passes; a command that can't run, fails or prints no RESULT line is `unavailable`.
    """

    def __init__(self, command: Sequence[str], runner: ProcessRunner) -> None:
        self._command, self._runner = tuple(command), runner

    def check(self) -> Readiness:
        return Readiness(ready=True, detail=" ".join(self._command))

    def status(self, principal: Principal) -> DirectoryStatus:
        identity = principal.identity.strip()
        if not identity or any(c.isspace() for c in identity):
            return DirectoryStatus(identity=identity, status="not_found")
        try:
            result = self._runner.run([*self._command, identity], check=False)
        except ServiceError as e:
            log.warning("directory command failed to run: %s", e)
            return DirectoryStatus(identity=identity, status=UNAVAILABLE)
        if result.returncode != 0:
            log.warning("directory command exited %d for %s", result.returncode, identity)
            return DirectoryStatus(identity=identity, status=UNAVAILABLE)
        for m in _RESULT.finditer(result.stdout.decode(errors="replace")):
            if m["uid"] == identity:
                return DirectoryStatus(identity=identity, status=m["status"])
        log.warning("directory command printed no RESULT line for %s", identity)
        return DirectoryStatus(identity=identity, status=UNAVAILABLE)
