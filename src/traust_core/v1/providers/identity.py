from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from functools import cached_property
from pathlib import Path
from typing import Protocol

import jwt
import pydantic
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from traust_core.v1.errors import AuthenticationError, ConfigError, ServiceError, ValidationError
from traust_core.v1.models.identity import (
    LOCAL_ISSUER,
    Credential,
    DirectoryStatus,
    IdentitySource,
    Login,
    Principal,
    TokenGrant,
    TrustedIssuer,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.http import HttpFetcher
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


DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
LOCAL_TOKEN_LIFETIME = timedelta(days=7)
_LOCAL_KID = "local-1"


class OidcLogin:
    """Gets tokens from one identity provider: a person by device code (RFC 8628), a service
    account by its client secret; renews either with a refresh token."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        http: HttpFetcher,
        clock: Clock,
        *,
        scope: str = "openid",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.issuer, self.client_id = issuer, client_id
        self._http, self._clock, self._scope, self._sleep = http, clock, scope, sleep

    @cached_property
    def _endpoints(self) -> Mapping[str, str]:
        url = f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"
        found = json.loads(self._http.get(url))
        if not found.get("token_endpoint"):
            raise ServiceError(f"{self.issuer} publishes no token_endpoint")
        return found

    def device_code(self, show: Callable[[str, str], None]) -> TokenGrant:
        """`show(uri, user_code)` tells the person where to approve; this then waits for it."""
        device_url = self._endpoints.get("device_authorization_endpoint")
        if not device_url:
            raise ServiceError(f"{self.issuer} publishes no device_authorization_endpoint")
        status, body = self._http.post_form(
            device_url, {"client_id": self.client_id, "scope": self._scope}
        )
        if status != 200:
            raise AuthenticationError(f"device authorization refused: {_oauth_error(body)}")
        device = json.loads(body)
        show(device.get("verification_uri") or device["verification_url"], device["user_code"])
        interval = float(device.get("interval", 5))
        while True:
            self._sleep(interval)
            form = {
                "grant_type": DEVICE_CODE_GRANT,
                "device_code": device["device_code"],
                "client_id": self.client_id,
            }
            status, body = self._http.post_form(self._endpoints["token_endpoint"], form)
            if status == 200:
                return self._grant(body)
            error = _oauth_error(body)
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval += 5
                continue
            raise AuthenticationError(f"device login failed: {error}")

    def client_credentials(self, secret: pydantic.SecretStr) -> TokenGrant:
        """A service account's machine token; the secret is never logged or put on argv."""
        if not secret.get_secret_value():
            raise ValidationError("client secret must not be empty")
        return self._exchange(
            "client_credentials",
            {"client_secret": secret.get_secret_value(), "scope": self._scope},
        )

    def refresh(self, token: pydantic.SecretStr) -> TokenGrant:
        return self._exchange("refresh_token", {"refresh_token": token.get_secret_value()})

    def _exchange(self, grant: str, form: Mapping[str, str]) -> TokenGrant:
        status, body = self._http.post_form(
            self._endpoints["token_endpoint"],
            {"grant_type": grant, "client_id": self.client_id, **form},
        )
        if status != 200:
            raise AuthenticationError(f"{grant} refused for {self.client_id}: {_oauth_error(body)}")
        return self._grant(body)

    def _grant(self, body: bytes) -> TokenGrant:
        token = json.loads(body)
        expires = token.get("expires_in")
        return TokenGrant(
            access_token=token["access_token"],
            refresh_token=token.get("refresh_token"),
            expires_at=None if expires is None else self._clock.now() + timedelta(seconds=expires),
        )


def _oauth_error(body: bytes) -> str:
    try:
        found = json.loads(body)
    except ValueError:
        return body.decode(errors="replace")[:200]
    if not isinstance(found, dict):
        return ""
    return str(found.get("error_description") or found.get("error") or "")


class LocalIssuer:
    """traust's own `local` issuer: this machine's key mints tokens for a solo deployment."""

    def __init__(self, home: Path, clock: Clock) -> None:
        self._key, self.jwks = home / "local-key.pem", home / "local-jwks.json"
        self._clock = clock

    def mint(self, identity: str, *, machine: bool = False) -> Credential:
        """A person's token carries `email`, a machine's only `azp`; never both."""
        if not identity.strip():
            raise ValidationError("a local token names someone")
        now = self._clock.now()
        claims = {
            "iss": LOCAL_ISSUER,
            "sub": identity,
            "azp" if machine else "email": identity,
            "iat": int(now.timestamp()),
            "exp": int((now + LOCAL_TOKEN_LIFETIME).timestamp()),
        }
        token = jwt.encode(claims, self._signing_key(), "ES256", headers={"kid": _LOCAL_KID})
        return Credential(token=pydantic.SecretStr(token))

    def _signing_key(self) -> ec.EllipticCurvePrivateKey:
        if self._key.is_file():
            key = serialization.load_pem_private_key(self._key.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise ConfigError(f"{self._key} is not an EC key")
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            _write_private(self._key, pem)
        if not self.jwks.is_file():
            jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
            keys = {"keys": [{**jwk, "use": "sig", "kid": _LOCAL_KID}]}
            _write_private(self.jwks, json.dumps(keys).encode())
        return key


class CredentialStore:
    """The local user's login under the traust home, readable only by them."""

    def __init__(self, home: Path) -> None:
        self._path = home / "credentials.json"

    def load(self) -> Login | None:
        if not self._path.is_file():
            return None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        return Login.model_validate(raw)

    def save(self, login: Login) -> None:
        data = login.model_dump(mode="json")
        data["grant"]["access_token"] = login.grant.access_token.get_secret_value()
        if login.grant.refresh_token is not None:
            data["grant"]["refresh_token"] = login.grant.refresh_token.get_secret_value()
        _write_private(self._path, json.dumps(data).encode())

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
