"""Versioned component PURL target models and strict PURL parsing."""

from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
from urllib.parse import unquote

from pydantic import (
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from traust_core.v1.errors import UnresolvedTargetError, ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.purl import Purl
from traust_core.v1.models.values import GitSha
from traust_core.v1.models.vocabulary import ComponentTargetStrategy, Ecosystem, RefKind


class UnresolvedTargetReason(StrEnum):
    INVALID_PURL = "invalid_purl"
    MISSING_VERSION = "missing_version"
    MISSING_PIN = "missing_pin"
    DEFAULT_BRANCH_DISALLOWED = "default_branch_disallowed"
    TAG_COMMIT_MISMATCH = "tag_commit_mismatch"
    NO_MANIFEST_MATCH = "no_manifest_match"
    VERSION_MISMATCH = "version_mismatch"
    PRIVATE_ROOT_ONLY = "private_root_only"
    SUPPLIED_PATH_CONFLICT = "supplied_path_conflict"
    AMBIGUOUS_MODULE_MATCH = "ambiguous_module_match"
    PROVENANCE_UNVERIFIED = "provenance_unverified"
    PROVENANCE_MISMATCH = "provenance_mismatch"


def normalize_module_path(path: str) -> str:
    """Normalize a repo-relative module directory path ('.' for repo root); rejects traversal."""
    cleaned = path.strip().replace("\\", "/")
    if not cleaned or cleaned.startswith("/"):
        raise UnresolvedTargetError(
            UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT,
            f"invalid module path {path!r}",
        )
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = cleaned.strip("/")
    if not cleaned or cleaned == ".":
        return "."
    parts = [p for p in cleaned.split("/") if p]
    if not parts or any(p in (".", "..") or not p.strip() for p in parts):
        raise UnresolvedTargetError(
            UnresolvedTargetReason.SUPPLIED_PATH_CONFLICT,
            f"invalid module path {path!r}",
        )
    return "/".join(parts)


def normalize_component_commit(raw: str) -> str:
    """Normalize and enforce a 40- or 64-char lowercase git commit SHA."""
    return str(GitSha.parse(raw.strip().lower()))


def parse_component_purl(raw: str) -> Purl:
    """Strictly parse a component target's versioned PURL
    (`pkg:<type>/[<ns>/]<name>@<version>[?...][#...]`): `Purl.parse` plus the target rules (an
    explicit version, Maven's groupId, a normalized repo-relative subpath)."""
    text = raw.strip()
    raw_subpath: str | None = None
    if "#" in text:
        _, raw_sub = text.split("#", 1)
        raw_subpath = normalize_module_path(unquote(raw_sub)) if raw_sub.strip() else None
    try:
        parsed = Purl.parse(text)
    except ValueError as exc:
        raise UnresolvedTargetError(UnresolvedTargetReason.INVALID_PURL, str(exc)) from exc
    if not parsed.version:
        raise UnresolvedTargetError(
            UnresolvedTargetReason.MISSING_VERSION,
            f"PURL must carry an explicit @version pin: {raw!r}",
        )
    if parsed.type == "maven" and not parsed.namespace:
        raise UnresolvedTargetError(
            UnresolvedTargetReason.INVALID_PURL,
            f"Maven PURL requires groupId namespace: {raw!r}",
        )
    subpath = (
        raw_subpath
        if raw_subpath is not None
        else (normalize_module_path(parsed.subpath) if parsed.subpath else None)
    )
    return replace(parsed, subpath=subpath)


def canonical_component_purl(raw: str) -> str:
    """Return the canonical versioned PURL string used as the dedup/lookup/binding key."""
    return parse_component_purl(raw).canonical


class ComponentTargetProvenance(Model):
    source: str = Field(min_length=1)
    ref: str = Field(min_length=1)
    digest: str = Field(min_length=1)
    manifest_version: str | None = Field(default=None, min_length=1)

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        document = handler(self)
        if self.manifest_version is None:
            document.pop("manifest_version", None)
        return document


class VerifiedProvenanceClaim(Model):
    purl: str = Field(min_length=1)
    repository: str = Field(min_length=1)
    commit: str = Field(min_length=1)
    source: str = Field(min_length=1)
    ref: str = Field(min_length=1)
    digest: str = Field(min_length=1)
    manifest_version: str | None = Field(default=None, min_length=1)


class ComponentTargetVerification(Model):
    strategy: ComponentTargetStrategy
    manifest_paths: tuple[str, ...] = Field(min_length=1)
    provenance: ComponentTargetProvenance | None = None

    @model_validator(mode="after")
    def _check_provenance_strategy_consistency(self) -> ComponentTargetVerification:
        is_external = self.strategy == ComponentTargetStrategy.EXTERNAL_PROVENANCE
        has_provenance = self.provenance is not None
        if is_external and not has_provenance:
            raise ValueError(
                "verification.provenance is required when strategy is 'external_provenance'"
            )
        if not is_external and has_provenance:
            raise ValueError(
                f"verification.provenance must be omitted when strategy is '{self.strategy}'"
            )
        return self

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        document = handler(self)
        if self.provenance is None:
            document.pop("provenance", None)
        return document


class ComponentTarget(Model):
    purl: str
    repository: str
    commit: str
    module_path: str
    release_ref: str | None = None
    verification: ComponentTargetVerification

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, object]:
        document = handler(self)
        if self.release_ref is None:
            document.pop("release_ref", None)
        return document

    @field_validator("commit")
    @classmethod
    def _check_commit(cls, value: str) -> str:
        try:
            return normalize_component_commit(value)
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc


IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class DsseSignature(Model):
    """One DSSE signature: the signing key's id and the base64 signature over the PAE."""

    keyid: str = Field(min_length=1)
    sig: str = Field(min_length=1)


class DsseEnvelope(Model):
    """A DSSE v1 envelope carrying a signed provenance statement (structure only: the
    verifier checks the payload type, the encoding and the signatures)."""

    # the wire form is DSSE's own field names, whatever the caller dumps with
    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )

    payload_type: str = Field(alias="payloadType", min_length=1)
    payload: str = Field(min_length=1)
    signatures: tuple[DsseSignature, ...] = Field(min_length=1)


class ComponentTargetRequest(Model):
    purl: str
    repository: str
    commit: str | None = None
    release_ref: str | None = None
    module_path: str | None = None
    ref_kind: RefKind | None = None
    provenance_record: DsseEnvelope | None = None


class PackageManifestCandidate(Model):
    ecosystem: Ecosystem
    package_id: str
    version: str | None = None
    module_path: str
    manifest_paths: tuple[str, ...]
    project_name: str | None = None
    is_private: bool = False
    is_workspace_root: bool = False
    is_workspace_member: bool = False
    inherits_root_version: bool = False
    is_dynamic_version: bool = False
