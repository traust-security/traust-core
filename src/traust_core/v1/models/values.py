from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema

from traust_core.v1.contracts import TimestampError as TimestampError
from traust_core.v1.contracts import risk_rating as risk_rating  # OWASP arithmetic, one owner
from traust_core.v1.contracts import to_rfc3339 as to_rfc3339
from traust_core.v1.errors import ValidationError

# NEED(validation): the str NewTypes elsewhere (RefName, Cwe, ...) only label meaning;
# each that needs a rule (git URI, CWE id, semver) becomes a value object here with parse().
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def require_nonblank(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be nonblank text")


def require_slug(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SLUG.fullmatch(value):
        raise ValidationError(f"{field} must be letters, digits, . _ - and start alphanumeric")


def require_uuid(value: UUID, field: str) -> None:
    if not isinstance(value, UUID):
        raise ValidationError(f"{field} must be a UUID")


def require_aware_datetime(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValidationError(f"{field} must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class ProductSlug:
    value: str

    def __post_init__(self) -> None:
        require_slug(self.value, "product.slug")

    @classmethod
    def parse(cls, raw: str) -> ProductSlug:
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class GitSha:
    value: str

    @classmethod
    def parse(cls, raw: str) -> GitSha:
        if not _SHA.fullmatch(raw):
            raise ValidationError(f"not a full lowercase git sha: {raw!r}")
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RepoPath:
    """A file path inside a repository: relative segments of the characters a repo URL allows."""

    value: str

    def __post_init__(self) -> None:
        segments = self.value.split("/") if isinstance(self.value, str) else [""]
        if any(
            s in {".", ".."} or s.startswith("-") or not _PATH_SEGMENT.fullmatch(s)
            for s in segments
        ):
            raise ValidationError(f"not a relative repository file path: {self.value!r}")

    @classmethod
    def parse(cls, raw: str) -> RepoPath:
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CveId:
    value: str

    @classmethod
    def parse(cls, raw: str) -> CveId:
        if not _CVE.fullmatch(raw):
            raise ValidationError(f"not a CVE id: {raw!r}")
        return cls(raw)

    @classmethod
    def find_all(cls, text: str) -> list[CveId]:
        """Every CVE id named in `text`, once each, sorted."""
        return [cls(c) for c in sorted(set(_CVE.findall(text)))]

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class HttpsRepoUrl:
    host: str
    path: str

    @classmethod
    def _parse(cls, raw: str) -> HttpsRepoUrl:
        """Structural validation only (scheme, no credentials, owner/repo path); host-agnostic."""
        if not raw.isascii() or raw != raw.strip() or raw.startswith("-"):
            raise ValidationError(f"repo url has unsafe characters: {raw!r}")
        parts = urlsplit(raw)
        if parts.scheme != "https":
            raise ValidationError(f"repo url must be https: {raw!r}")
        if parts.username or parts.password or parts.port or parts.query or parts.fragment:
            raise ValidationError(f"repo url must be host and path only: {raw!r}")
        segments = parts.path.strip("/").removesuffix(".git").split("/")
        if len(segments) < 2 or any(
            s in {".", ".."} or s.startswith("-") or not _PATH_SEGMENT.fullmatch(s)
            for s in segments
        ):
            raise ValidationError(f"repo url path is invalid: {raw!r}")
        host = (parts.hostname or "").lower()
        # the host becomes a directory under the mirror cache root: it must be a
        # plain hostname, never "..", a leading dash or anything path-like
        if not _HOST.fullmatch(host) or ".." in host:
            raise ValidationError(f"repo url host is invalid: {raw!r}")
        return cls(host, "/".join(segments))

    @classmethod
    def parse(cls, raw: str, allowed_hosts: Iterable[str]) -> HttpsRepoUrl:
        url = cls._parse(raw)
        if url.host not in {h.lower() for h in allowed_hosts}:
            raise ValidationError(f"repo host not allowed: {url.host!r}")
        return url

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: object, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        # On the wire a repo URL is a string (parsed structurally; the host allowlist is a
        # deployment check, not here); an instance passes through; JSON out is the string.
        from_str = core_schema.chain_schema(
            [core_schema.str_schema(), core_schema.no_info_plain_validator_function(cls._parse)]
        )
        return core_schema.json_or_python_schema(
            json_schema=from_str,
            python_schema=core_schema.union_schema([core_schema.is_instance_schema(cls), from_str]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                str, when_used="json", return_schema=core_schema.str_schema()
            ),
        )

    def __str__(self) -> str:
        return f"https://{self.host}/{self.path}"
