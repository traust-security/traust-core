from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from traust_core.v1.errors import ValidationError

_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")


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
class CveId:
    value: str

    @classmethod
    def parse(cls, raw: str) -> CveId:
        if not _CVE.fullmatch(raw):
            raise ValidationError(f"not a CVE id: {raw!r}")
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class HttpsRepoUrl:
    host: str
    path: str

    @classmethod
    def parse(cls, raw: str, allowed_hosts: Iterable[str]) -> HttpsRepoUrl:
        if not raw.isascii() or raw != raw.strip() or raw.startswith("-"):
            raise ValidationError(f"repo url has unsafe characters: {raw!r}")
        parts = urlsplit(raw)
        if parts.scheme != "https":
            raise ValidationError(f"repo url must be https: {raw!r}")
        if parts.username or parts.password or parts.port or parts.query or parts.fragment:
            raise ValidationError(f"repo url must be host and path only: {raw!r}")
        host = (parts.hostname or "").lower()
        if host not in {h.lower() for h in allowed_hosts}:
            raise ValidationError(f"repo host not allowed: {host!r}")
        segments = parts.path.strip("/").removesuffix(".git").split("/")
        if len(segments) < 2 or any(
            s in {".", ".."} or s.startswith("-") or not _PATH_SEGMENT.fullmatch(s)
            for s in segments
        ):
            raise ValidationError(f"repo url path is invalid: {raw!r}")
        return cls(host, "/".join(segments))

    def __str__(self) -> str:
        return f"https://{self.host}/{self.path}"
