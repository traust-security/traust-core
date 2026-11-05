from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar
from urllib.parse import quote

import pydantic
from pydantic import AwareDatetime, Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.tools.toolchain import ToolUpstream, UpstreamKind

__all__ = ["ToolRelease", "ToolReleases"]

T = TypeVar("T", bound=Dto)

_VERSION = re.compile(r"v?(\d+\.\d+\.\d+)")
_GITHUB_REF = re.compile(r"[\w.-]+/[\w.-]+")


@dataclass(frozen=True, slots=True)
class ToolRelease:
    version: str
    published_at: datetime


class _GithubRelease(Dto):
    tag_name: str
    published_at: AwareDatetime
    draft: bool = False
    prerelease: bool = False


class _GoRelease(Dto):
    version: str = Field(alias="Version")
    published_at: AwareDatetime = Field(alias="Time")


class _PypiInfo(Dto):
    version: str


class _Upload(Dto):
    upload_time_iso_8601: AwareDatetime
    yanked: bool = False


class _PypiRelease(Dto):
    info: _PypiInfo
    urls: tuple[_Upload, ...]


class ToolReleases:
    """Release versions and publication times from the manifest's upstream registries."""

    def __init__(self, http: HttpFetcher, *, github_token: str | None = None) -> None:
        self._http = http
        self._github_headers = {
            "Accept": "application/vnd.github+json",
            **({"Authorization": f"Bearer {github_token}"} if github_token else {}),
        }

    def latest(self, upstream: ToolUpstream) -> ToolRelease:
        kind, ref = upstream.kind, upstream.ref
        if not ref:
            raise ValidationError("tool upstream: empty reference")
        if kind is UpstreamKind.GITHUB:
            if not _GITHUB_REF.fullmatch(ref):
                raise ValidationError(f"GitHub release reference {ref!r}: expected owner/repo")
            url = f"https://api.github.com/repos/{ref}/releases/latest"
            doc = self._parse(_GithubRelease, url, self._github_headers)
            if doc.draft or doc.prerelease:
                raise ValidationError(f"{url}: latest release is not a stable published release")
            return ToolRelease(_version(doc.tag_name, url), doc.published_at)
        if kind is UpstreamKind.PYPI:
            return self._pypi(ref)
        escaped = "".join(f"!{c.lower()}" if c.isupper() else c for c in ref)
        url = f"https://proxy.golang.org/{quote(escaped, safe='/!')}/@latest"
        doc = self._parse(_GoRelease, url)
        return ToolRelease(_version(doc.version, url), doc.published_at)

    def pinned(self, package: str, version: str) -> ToolRelease:
        """The first non-yanked PyPI publication of the exact approved pin."""
        return self._pypi(package, version)

    def _pypi(self, package: str, version: str | None = None) -> ToolRelease:
        suffix = f"/{quote(version, safe='')}" if version is not None else ""
        url = f"https://pypi.org/pypi/{quote(package, safe='')}{suffix}/json"
        doc = self._parse(_PypiRelease, url)
        released = _version(doc.info.version, url)
        if version is not None and released != _version(version, url):
            raise ValidationError(f"{url}: response version does not match requested pin {version}")
        publications = [u.upload_time_iso_8601 for u in doc.urls if not u.yanked]
        if not publications:
            raise ValidationError(f"{url}: release has no non-yanked publication timestamp")
        return ToolRelease(released, min(publications))

    def _parse(self, model: type[T], url: str, headers: dict[str, str] | None = None) -> T:
        body = self._http.get(url, headers=headers)
        try:
            return model.model_validate_json(body)
        except pydantic.ValidationError as e:
            raise ValidationError(f"{url}: invalid release metadata: {e}") from e


def _version(raw: str, source: str) -> str:
    if found := _VERSION.fullmatch(raw):
        return found.group(1)
    raise ValidationError(f"{source}: {raw!r} is not a stable release version")
