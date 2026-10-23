"""Token verification and the employee directory, ported from traust-ledger's auth tests."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr

from traust_core.v1.errors import AuthenticationError, ConfigError, ServiceError, ValidationError
from traust_core.v1.models.identity import (
    Credential,
    IdentitySource,
    Login,
    Principal,
    TokenGrant,
    TrustedIssuer,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.clock import FixedClock, SystemClock
from traust_core.v1.providers.http import HttpFetcher, RetryPolicy
from traust_core.v1.providers.identity import (
    CommandDirectory,
    CredentialStore,
    LocalIssuer,
    OidcLogin,
    TokenIdentityProvider,
    _oauth_error,
)
from traust_core.v1.providers.process import ProcessRunner

IDP_A, IDP_B, AUDIENCE = "https://idp-a.example", "https://idp-b.example", "traust"


class Keys:
    """A signing key and its public JWKS entry."""

    def __init__(self, kid: str, curve: bool = False) -> None:
        self.kid = kid
        if curve:
            self.private: Any = ec.generate_private_key(ec.SECP256R1())
            self.algorithm, public = "ES256", jwt.algorithms.ECAlgorithm.to_jwk
        else:
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.algorithm, public = "RS256", jwt.algorithms.RSAAlgorithm.to_jwk
        self.jwk = {**json.loads(public(self.private.public_key())), "kid": kid}

    def token(self, claims: dict[str, Any], **headers: Any) -> Credential:
        now = int(time.time())
        body = {"iat": now, "exp": now + 300, **claims}
        raw = jwt.encode(body, self.private, self.algorithm, headers={"kid": self.kid, **headers})
        return Credential(token=SecretStr(raw))


KEY_A, KEY_B, LOCAL = Keys("a"), Keys("b"), Keys("local-1", curve=True)


@pytest.fixture(scope="module")
def jwks() -> Iterator[str]:
    """Each issuer's JWKS served over HTTP, as an IdP publishes it."""
    sets = {"/a": [KEY_A.jwk], "/b": [KEY_B.jwk]}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps({"keys": sets.get(self.path, [])}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def local_jwks(tmp_path: Path) -> Path:
    path = tmp_path / "local-jwks.json"
    path.write_text(json.dumps({"keys": [LOCAL.jwk]}))
    return path


def provider(jwks: str, local: Path | None = None, **kw: Any) -> TokenIdentityProvider:
    issuers = [
        TrustedIssuer(issuer=IDP_A, jwks_url=f"{jwks}/a", audience=AUDIENCE),
        TrustedIssuer(issuer=IDP_B, jwks_url=f"{jwks}/b"),
    ]
    return TokenIdentityProvider(issuers, local_jwks=local, **kw)


def person(issuer: str = IDP_A, **claims: Any) -> dict[str, Any]:
    return {"iss": issuer, "aud": AUDIENCE, "sub": "u1", "email": " Alice@Example.COM ", **claims}


def test_a_person_from_a_trusted_issuer_is_verified(jwks: str) -> None:
    principal = provider(jwks).authenticate(KEY_A.token(person()))
    assert principal == Principal(
        identity="alice@example.com",
        kind=ActorKind.HUMAN,
        display="alice@example.com",
        verified_by=IdentitySource.OIDC,
    )
    assert principal.ref == "human:alice@example.com"
    assert principal.is_verified_human()


@pytest.mark.parametrize(
    ("claims", "identity"),
    [({"azp": "runner-7"}, "runner-7"), ({}, "svc-sub")],
    ids=["client id", "subject only"],
)
def test_a_token_without_a_person_is_a_machine(
    jwks: str, claims: dict[str, str], identity: str
) -> None:
    token = KEY_B.token({"iss": IDP_B, "sub": "svc-sub", **claims})
    principal = provider(jwks).authenticate(token)
    assert (principal.kind, principal.identity) == (ActorKind.MACHINE, identity)
    assert not principal.is_verified_human()


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        (KEY_A.token(person(exp=int(time.time()) - 10)), "expired"),
        (KEY_A.token(person(issuer="https://evil.example")), "untrusted issuer"),
        (KEY_B.token(person()), "invalid token"),
        (KEY_A.token(person(aud="another-service")), "invalid token"),
        (KEY_A.token(person(nbf=int(time.time()) + 600)), "invalid token"),
        (KEY_A.token({"iss": IDP_A, "aud": AUDIENCE}), "no identity claims"),
        (KEY_A.token(person(email="   ")), "empty identity"),
        (Credential(token=SecretStr("not.a.jwt")), "undecodable"),
    ],
    ids=[
        "expired",
        "untrusted issuer",
        "signed by another issuer's key",
        "wrong audience",
        "not yet valid",
        "no identity claims",
        "blank identity",
        "malformed",
    ],
)
def test_a_bad_token_is_refused(jwks: str, token: Credential, reason: str) -> None:
    with pytest.raises(AuthenticationError, match=reason):
        provider(jwks).authenticate(token)


def test_an_unsigned_token_is_refused(jwks: str) -> None:
    raw = jwt.encode(person(), key=None, algorithm="none")
    with pytest.raises(AuthenticationError):
        provider(jwks).authenticate(Credential(token=SecretStr(raw)))


def test_an_issuer_without_an_audience_accepts_any(jwks: str) -> None:
    token = KEY_B.token(person(issuer=IDP_B, aud="whatever"))
    assert provider(jwks).authenticate(token).verified_by == IdentitySource.OIDC


def test_the_identity_claim_is_the_deployments(jwks: str) -> None:
    token = KEY_A.token(person(email=None, upn="Bob@Example.com"))
    assert provider(jwks, identity_claim="upn").authenticate(token).identity == "bob@example.com"


@pytest.mark.parametrize(
    ("trust", "verified_by"), [(True, IdentitySource.LOCAL_USER), (False, None)]
)
def test_a_local_token_verifies_a_person_only_when_trusted(
    jwks: str, local_jwks: Path, trust: bool, verified_by: IdentitySource | None
) -> None:
    token = LOCAL.token({"iss": "local", "sub": "me@example.com", "email": "me@example.com"})
    principal = provider(jwks, local_jwks, trust_local=trust).authenticate(token)
    assert (principal.identity, principal.verified_by) == ("me@example.com", verified_by)


def test_local_tokens_need_this_machines_keys(jwks: str, tmp_path: Path) -> None:
    token = LOCAL.token({"iss": "local", "email": "me@example.com"})
    with pytest.raises(AuthenticationError, match="untrusted issuer"):
        provider(jwks).authenticate(token)
    with pytest.raises(AuthenticationError, match="invalid token"):
        provider(jwks, tmp_path / "missing.json").authenticate(token)
    forged = Keys("local-1", curve=True).token({"iss": "local", "email": "me@example.com"})
    (tmp_path / "jwks.json").write_text(json.dumps({"keys": [LOCAL.jwk]}))
    with pytest.raises(AuthenticationError, match="invalid token"):
        provider(jwks, tmp_path / "jwks.json").authenticate(forged)


def test_check_names_the_trusted_issuers(jwks: str, local_jwks: Path) -> None:
    assert provider(jwks, local_jwks).check().detail == f"{IDP_A}, {IDP_B}, local"
    assert not TokenIdentityProvider([]).check().ready


# The employee directory: `<command> <identity>` prints `RESULT uid=<identity> status=<status>`
SCRIPT = """
import sys, time
uid = sys.argv[1]
if uid == "slow@example.com":
    time.sleep(5)
if uid == "broken@example.com":
    sys.exit(3)
if uid == "silent@example.com":
    print("nothing to say")
print("RESULT uid=alice@example.com.au status=terminated")
print(f"RESULT uid={uid} status={'active' if uid.startswith('alice') else 'terminated'}")
"""


@pytest.fixture
def directory(tmp_path: Path) -> CommandDirectory:
    script = tmp_path / "directory.py"
    script.write_text(SCRIPT)
    runner = ProcessRunner([Path(sys.executable).name], timeout_seconds=1)
    return CommandDirectory([sys.executable, str(script)], runner)


def who(identity: str) -> Principal:
    return Principal(identity=identity, kind=ActorKind.HUMAN, display=identity)


@pytest.mark.parametrize(
    ("identity", "status"),
    [
        ("alice@example.com", "active"),
        ("mallory@example.com", "terminated"),
        ("broken@example.com", "unavailable"),
        ("slow@example.com", "unavailable"),
        ("has space@example.com", "not_found"),
    ],
    ids=["active", "terminated", "command fails", "times out", "whitespace"],
)
def test_the_directory_answers_from_its_result_line(
    directory: CommandDirectory, identity: str, status: str
) -> None:
    assert directory.status(who(identity)).status == status


def test_only_the_exact_uid_counts(directory: CommandDirectory, tmp_path: Path) -> None:
    script = tmp_path / "other.py"
    script.write_text('print("RESULT uid=alice@example.com.au status=active")\n')
    runner = ProcessRunner([Path(sys.executable).name])
    other = CommandDirectory([sys.executable, str(script)], runner)
    assert other.status(who("alice@example.com")).status == "unavailable"
    assert directory.status(who("silent@example.com")).active is False
    assert directory.check().ready


# Getting a token: a fake identity provider over HTTP
class Idp:
    """Discovery, device authorization and token endpoints; token replies come off a queue."""

    def __init__(self, base: str, replies: list[tuple[int, dict[str, Any]]]) -> None:
        self.base, self.replies, self.forms = base, replies, []
        self.device_endpoint, self.device_reply = True, (200, {})


@pytest.fixture
def idp() -> Iterator[Idp]:
    state: dict[str, Idp] = {}

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            base = state["idp"].base
            found = {"token_endpoint": f"{base}/token"}
            if state["idp"].device_endpoint:
                found["device_authorization_endpoint"] = f"{base}/device"
            self._reply(200, found)

        def do_POST(self) -> None:
            server = state["idp"]
            form = self.rfile.read(int(self.headers["Content-Length"])).decode()
            server.forms.append(dict(p.split("=", 1) for p in form.split("&")))
            if self.path == "/device" and server.device_reply[0] != 200:
                self._reply(*server.device_reply)
            elif self.path == "/device":
                self._reply(
                    200,
                    {
                        "device_code": "dc",
                        "user_code": "ABCD",
                        "interval": 0,
                        "verification_uri": f"{server.base}/activate",
                    },
                )
            else:
                self._reply(*server.replies.pop(0))

        def log_message(self, *args: object) -> None:
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    state["idp"] = Idp(f"http://127.0.0.1:{httpd.server_port}", [])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state["idp"]
    httpd.shutdown()


NOW = datetime(2026, 10, 23, 9, tzinfo=UTC)
GRANT = {"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600}


def login(idp: Idp, slept: list[float] | None = None) -> OidcLogin:
    http = HttpFetcher("test", RetryPolicy(max_attempts=1))
    return OidcLogin(
        idp.base, "traust-cli", http, FixedClock(NOW), sleep=([] if slept is None else slept).append
    )


def test_a_person_logs_in_by_device_code(idp: Idp) -> None:
    idp.replies += [
        (400, {"error": "authorization_pending"}),
        (400, {"error": "slow_down"}),
        (200, GRANT),
    ]
    shown, slept = [], []
    grant = login(idp, slept).device_code(lambda uri, code: shown.append((uri, code)))
    assert shown == [(f"{idp.base}/activate", "ABCD")]
    assert slept == [0, 0, 5]
    assert grant.access_token.get_secret_value() == "at-1"
    assert grant.expires_at == NOW + timedelta(hours=1)
    assert idp.forms[-1]["grant_type"] == "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"


@pytest.mark.parametrize("error", ["access_denied", "expired_token"])
def test_a_device_login_that_is_denied_or_expires_fails(idp: Idp, error: str) -> None:
    idp.replies.append((400, {"error": error}))
    with pytest.raises(AuthenticationError, match=error):
        login(idp).device_code(lambda uri, code: None)


def test_a_service_account_gets_a_machine_token(idp: Idp) -> None:
    idp.replies += [
        (200, {"access_token": "svc"}),
        (401, {"error": "invalid_client", "error_description": "bad secret"}),
    ]
    grant = login(idp).client_credentials(SecretStr("s3cret"))
    assert (grant.access_token.get_secret_value(), grant.refresh_token, grant.expires_at) == (
        "svc",
        None,
        None,
    )
    assert idp.forms[-1]["client_secret"] == "s3cret"
    with pytest.raises(AuthenticationError, match="bad secret"):
        login(idp).client_credentials(SecretStr("wrong"))
    with pytest.raises(ValidationError):
        login(idp).client_credentials(SecretStr(""))


def test_a_refresh_renews_or_is_refused(idp: Idp) -> None:
    idp.replies += [(200, GRANT), (400, {"error": "invalid_grant"})]
    assert login(idp).refresh(SecretStr("rt-0")).refresh_token == SecretStr("rt-1")
    with pytest.raises(AuthenticationError, match="invalid_grant"):
        login(idp).refresh(SecretStr("rt-0"))


def test_a_device_login_needs_the_providers_device_endpoint(idp: Idp) -> None:
    idp.device_endpoint = False
    with pytest.raises(ServiceError, match="device_authorization_endpoint"):
        login(idp).device_code(lambda uri, code: None)


def test_a_refused_device_authorization_fails(idp: Idp) -> None:
    idp.device_reply = (400, {"error": "unauthorized_client"})
    with pytest.raises(AuthenticationError, match="unauthorized_client"):
        login(idp).device_code(lambda uri, code: None)


@pytest.mark.parametrize(("body", "said"), [(b"gateway says no", "gateway says no"), (b"[1]", "")])
def test_an_error_body_that_is_not_an_oauth_error_is_reported_as_is(body: bytes, said: str) -> None:
    assert _oauth_error(body) == said


def test_a_provider_without_the_endpoints_is_a_service_error() -> None:
    http = HttpFetcher("test", RetryPolicy(max_attempts=1))
    with pytest.raises(ServiceError):
        OidcLogin("http://127.0.0.1:9", "c", http, FixedClock(NOW)).refresh(SecretStr("x"))


# Local identity: this machine's key, for a solo deployment
def test_a_local_token_verifies_against_its_own_keys(tmp_path: Path) -> None:
    issuer = LocalIssuer(tmp_path, SystemClock())
    verify = TokenIdentityProvider([], local_jwks=issuer.jwks, trust_local=True)
    person = verify.authenticate(issuer.mint("Me@Example.com"))
    machine = verify.authenticate(issuer.mint("triage/1.0", machine=True))
    assert (person.kind, person.identity, person.verified_by) == (
        ActorKind.HUMAN,
        "me@example.com",
        IdentitySource.LOCAL_USER,
    )
    assert (machine.kind, machine.identity) == (ActorKind.MACHINE, "triage/1.0")
    assert oct((tmp_path / "local-key.pem").stat().st_mode & 0o777) == "0o600"
    again = LocalIssuer(tmp_path, SystemClock()).mint("me@example.com")
    assert verify.authenticate(again).identity == "me@example.com"


def test_a_local_token_lasts_a_week_and_names_someone(tmp_path: Path) -> None:
    raw = LocalIssuer(tmp_path, FixedClock(NOW)).mint("me@example.com").token.get_secret_value()
    claims = jwt.decode(raw, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 7 * 24 * 3600
    assert "azp" not in claims
    with pytest.raises(ValidationError):
        LocalIssuer(tmp_path, FixedClock(NOW)).mint("  ")


def test_a_local_key_that_is_not_ec_is_a_config_error(tmp_path: Path) -> None:
    pem = KEY_A.private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (tmp_path / "local-key.pem").write_bytes(pem)
    with pytest.raises(ConfigError):
        LocalIssuer(tmp_path, SystemClock()).mint("me@example.com")


def test_the_credential_store_keeps_a_login_for_its_owner_only(tmp_path: Path) -> None:
    store = CredentialStore(tmp_path / "home")
    assert store.load() is None
    saved = Login(
        issuer="https://idp.example",
        client_id="traust-cli",
        grant=TokenGrant(access_token="at", refresh_token="rt", expires_at=NOW),
    )
    store.save(saved)
    assert store.load() == saved
    assert oct((tmp_path / "home" / "credentials.json").stat().st_mode & 0o777) == "0o600"
    store.clear()
    assert store.load() is None
