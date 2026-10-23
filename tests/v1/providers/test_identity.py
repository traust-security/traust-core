"""Token verification and the employee directory, ported from traust-ledger's auth tests."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr

from traust_core.v1.errors import AuthenticationError
from traust_core.v1.models.identity import (
    Credential,
    IdentitySource,
    Principal,
    TrustedIssuer,
)
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.identity import CommandDirectory, TokenIdentityProvider
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
