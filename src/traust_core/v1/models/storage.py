from __future__ import annotations

import hashlib
from datetime import datetime

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model

BINDING_DOMAIN = b"traust-binding-v1\x00"


class BindingContext(Model):
    scope_id: str = "local"
    subject_id: str | None = None
    run_id: str | None = None
    layer_id: str | None = None
    role: str | None = None
    supersedes_binding_id: str | None = None


class Evidence(Model):
    digest: str
    byte_size: int
    first_ingested_at: datetime


class ArtifactBinding(Model):
    binding_id: str
    artifact_digest: str
    artifact_name: str
    context: BindingContext
    bound_at: datetime
    references: tuple[str, ...] = ()
    byte_size: int | None = None


def identifier_bytes(field: str, value: str) -> bytes:
    if "\x00" in value:
        raise ValidationError(f"{field}: NUL is not allowed")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValidationError(f"{field}: invalid Unicode") from None


def binding_id(artifact_digest: str, artifact_name: str, context: BindingContext) -> str:
    encoded = bytearray(BINDING_DOMAIN)
    for field, value in (
        ("artifact_digest", artifact_digest),
        ("artifact_name", artifact_name),
        ("scope_id", context.scope_id),
    ):
        encoded += identifier_bytes(field, value) + b"\x00"
    for field, optional in (
        ("subject_id", context.subject_id),
        ("run_id", context.run_id),
        ("layer_id", context.layer_id),
    ):
        encoded += (
            b"\x00" if optional is None else b"\x01" + identifier_bytes(field, optional) + b"\x00"
        )
    if context.role is not None:
        encoded += b"\x01" + identifier_bytes("role", context.role) + b"\x00"
    return hashlib.sha256(encoded).hexdigest()
