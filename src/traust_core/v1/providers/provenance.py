"""Cryptographic verification of external build/release provenance envelopes (DSSE / in-toto)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pydantic
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from pydantic import Field

from traust_core.v1.errors import ConfigError, UnresolvedTargetError
from traust_core.v1.models.base import Model
from traust_core.v1.models.component_target import (
    IN_TOTO_PAYLOAD_TYPE,
    DsseEnvelope,
    UnresolvedTargetReason,
    VerifiedProvenanceClaim,
)

MAX_PROVENANCE_PAYLOAD_BYTES = 65_536


class TrustedProvenanceKey(Model):
    key_id: str = Field(min_length=1)
    public_key_pem: str = Field(min_length=1)
    issuer: str | None = Field(default=None, min_length=1)


class ProvenanceTrustPolicy(Model):
    trusted_keys: tuple[TrustedProvenanceKey, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    allowed_issuers: tuple[str, ...] = ()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Standard DSSE v1.0 Pre-Authentication Encoding."""
    pt_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt_bytes)).encode("ascii")
        + b" "
        + pt_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _verify_signature(public_key: object, signature: bytes, data: bytes) -> bool:
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
# the one predicate family that states a build's provenance; a trusted key's other signed
# statements (test results, vulnerability scans, SBOMs) are no release evidence
SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/"


def _extract_statement_fields(statement: Mapping[str, Any]) -> dict[str, Any]:
    """The release claims of an in-toto v1 SLSA-provenance Statement; anything else is not
    provenance."""
    stmt_type = statement.get("_type")
    if stmt_type != IN_TOTO_STATEMENT_V1:
        raise UnresolvedTargetError(
            UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
            f"provenance payload is not an in-toto v1 Statement (_type {stmt_type!r})",
        )
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type.startswith(SLSA_PROVENANCE_PREFIX):
        raise UnresolvedTargetError(
            UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
            f"provenance predicateType {predicate_type!r} is not SLSA provenance",
        )
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        raise UnresolvedTargetError(
            UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
            "in-toto statement predicate must be an object",
        )
    purl = predicate.get("purl")
    subjects = statement.get("subject")
    if not purl and isinstance(subjects, list) and subjects:
        first_subj = subjects[0]
        if isinstance(first_subj, Mapping):
            cand = first_subj.get("uri") or first_subj.get("name")
            if isinstance(cand, str) and cand.startswith("pkg:"):
                purl = cand
    return {
        "purl": purl,
        "repository": predicate.get("repository"),
        "commit": predicate.get("commit"),
        "source": predicate_type,
        "ref": predicate.get("ref"),
        "manifest_version": predicate.get("manifest_version"),
    }


class DsseProvenanceVerifier:
    """Verifies DSSE-signed provenance records against a configured trust policy."""

    def __init__(self, policy: ProvenanceTrustPolicy) -> None:
        self._policy = policy
        self._keys: dict[str, tuple[TrustedProvenanceKey, object]] = {}
        for entry in policy.trusted_keys:
            try:
                pub = serialization.load_pem_public_key(entry.public_key_pem.encode("utf-8"))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    f"invalid public key PEM for provenance key {entry.key_id!r}"
                ) from exc
            self._keys[entry.key_id] = (entry, pub)

    @classmethod
    def from_file(cls, path: Path) -> DsseProvenanceVerifier:
        try:
            raw = path.read_text(encoding="utf-8")
            policy = ProvenanceTrustPolicy.model_validate_json(raw)
        except (OSError, pydantic.ValidationError) as exc:
            raise ConfigError(f"invalid provenance trust policy at {path}: {exc}") from exc
        return cls(policy)

    def verify(self, envelope: DsseEnvelope) -> VerifiedProvenanceClaim:
        if not self._keys:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "no trusted provenance keys configured in trust policy",
            )
        # DSSE's payload type is how signers keep one protocol's payloads from another's: a
        # trusted key's signature over any other type is not release provenance.
        payload_type = envelope.payload_type
        if payload_type != IN_TOTO_PAYLOAD_TYPE:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"provenance payloadType must be {IN_TOTO_PAYLOAD_TYPE!r}, not {payload_type!r}",
            )
        payload_b64 = envelope.payload
        try:
            payload_bytes = base64.b64decode(payload_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is not valid base64",
            ) from exc
        if not payload_bytes or len(payload_bytes) > MAX_PROVENANCE_PAYLOAD_BYTES:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is empty or exceeds size limit",
            )

        pae = dsse_pae(payload_type, payload_bytes)
        matched_key: TrustedProvenanceKey | None = None
        for sig_entry in envelope.signatures:
            trusted = self._keys.get(sig_entry.keyid)
            if trusted is None:
                continue
            try:
                sig_bytes = base64.b64decode(sig_entry.sig, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _verify_signature(trusted[1], sig_bytes, pae):
                matched_key = trusted[0]
                break

        if matched_key is None:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "no trusted signature verified on provenance envelope",
            )

        try:
            statement = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance payload is not valid UTF-8 JSON",
            ) from exc
        if not isinstance(statement, Mapping):
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                "provenance statement must be a JSON object",
            )

        issuer = matched_key.issuer or (
            statement.get("issuer") if isinstance(statement.get("issuer"), str) else None
        )
        if self._policy.allowed_issuers and issuer not in self._policy.allowed_issuers:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"untrusted provenance issuer {issuer!r}",
            )

        extracted = _extract_statement_fields(statement)
        source = extracted.get("source")
        if self._policy.allowed_sources and source not in self._policy.allowed_sources:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"untrusted provenance source {source!r}",
            )

        digest = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
        try:
            return VerifiedProvenanceClaim(
                purl=extracted["purl"],
                repository=extracted["repository"],
                commit=extracted["commit"],
                source=extracted["source"],
                ref=extracted["ref"],
                digest=digest,
                manifest_version=extracted.get("manifest_version"),
            )
        except (KeyError, pydantic.ValidationError) as exc:
            raise UnresolvedTargetError(
                UnresolvedTargetReason.PROVENANCE_UNVERIFIED,
                f"incomplete verified provenance claims: {exc}",
            ) from exc
