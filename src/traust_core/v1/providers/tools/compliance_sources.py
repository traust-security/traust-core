"""ADR register files at their pin and official product docs, read for the compliance doors;
what the files mean is `models.compliance`'s."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import quote
from uuid import UUID

from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.compliance import OFFICIAL_DOCS, is_decision_record
from traust_core.v1.providers.base import Acquisition, Readiness, Result, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.collaboration import ProductDocument, RegisterFile
from traust_core.v1.providers.forge_api import ForgeApi
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.providers.process import ProcessRunner

CURL_TIMEOUT = 90.0  # curl's own --max-time is 60 s
_ADR_READ_CAP = 262_144  # bytes per register file, as legacy read them
_GITHUB_REPO = re.compile(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git|/|$)")
_PIN = re.compile(r"[0-9a-f]{40}")
_SLUG = re.compile(r"[A-Za-z0-9._-]+")


class GithubAdrSource:
    """ADR register files read at the register's pinned commit from GitHub; never a checkout."""

    name = "github-adr"

    def __init__(self, api: ForgeApi, http: HttpFetcher, clock: Clock) -> None:
        self._api = api
        self._http = http
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def files(self, repo: str, pin: str, paths: Sequence[str]) -> Result[list[RegisterFile]]:
        slug = github_slug(repo)
        if not _PIN.fullmatch(pin):
            raise ValidationError(f"ADR register {repo}: pin {pin!r} is not a 40-hex commit")
        found = [
            RegisterFile(
                path=path,
                text=self._raw(slug, pin, path),
                url=f"https://github.com/{slug}/blob/{pin}/{path}",
            )
            for path in self._tree(slug, pin)
            if is_decision_record(path, paths)
        ]
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), version=pin, source=repo
        )
        return Result(found, acquisition)

    def _tree(self, slug: str, pin: str) -> list[str]:
        try:
            tree = self._api.get("github.com", f"repos/{slug}/git/trees/{pin}?recursive=1")
        except ServiceError as e:
            raise ServiceError(f"ADR register {slug}@{pin}: tree unreadable: {e}") from e
        if tree.get("truncated"):
            raise ServiceError(f"ADR register {slug}@{pin}: GitHub truncated the tree listing")
        return sorted(e["path"] for e in tree["tree"] if e.get("type") == "blob")

    def _raw(self, slug: str, pin: str, path: str) -> str:
        url = f"https://raw.githubusercontent.com/{slug}/{pin}/{quote(path)}"
        try:
            body = self._http.get(url)
        except ServiceError as e:
            raise ServiceError(f"ADR register {slug}@{pin}: {path} unreadable: {e}") from e
        return body[:_ADR_READ_CAP].decode("utf-8", "replace")


def github_slug(repo: str) -> str:
    """`org/name` of a GitHub repository URL; any other forge has no register reader yet."""
    if found := _GITHUB_REPO.search(repo):
        return found.group(1)
    raise ValidationError(f"ADR register {repo}: not a GitHub repository (no reader for its forge)")


@dataclass(frozen=True, slots=True)
class DocsTarget:
    """One product's docs.redhat.com slug and version; no guides means every guide listed."""

    product_slug: str
    version: str
    guides: tuple[str, ...] = ()


class RedHatDocSource:
    """docs.redhat.com guides as single-page html, fetched with stock curl (the CDN refuses
    python-urllib and custom user agents); nothing is cached or stored."""

    name = "docs.redhat.com"

    def __init__(
        self, curl: ProcessRunner, clock: Clock, targets: Mapping[UUID, DocsTarget]
    ) -> None:
        self._curl = curl
        self._clock = clock
        self._targets = dict(targets)

    def check(self) -> Readiness:
        return on_path("curl")

    def fetch(self, product_id: UUID) -> Result[list[ProductDocument]]:
        target = self._targets.get(product_id)
        if target is None:
            raise NotFoundError(f"product {product_id}: no docs.redhat.com slug/version declared")
        slug, version = _segment(target.product_slug), _segment(target.version)
        base = f"{OFFICIAL_DOCS}en/documentation/{slug}/{version}"
        pages = [
            ProductDocument(
                product_slug=slug, version=version, guide=guide, url=url, html=self._get(url)
            )
            for guide in map(_segment, target.guides or self._guides(base, slug, version))
            for url in (f"{base}/html-single/{guide}/index",)
        ]
        acquisition = Acquisition(
            provider=self.name, acquired_at=self._clock.now(), version=version, source=base
        )
        return Result(pages, acquisition)

    def _guides(self, landing: str, slug: str, version: str) -> list[str]:
        pattern = rf'href="/en/documentation/{re.escape(slug)}/{re.escape(version)}/html/([^"/]+)"'
        if guides := sorted(set(re.findall(pattern, self._get(landing)))):
            return guides
        raise NotFoundError(
            f"no guides found at {landing}: wrong slug/version, or the page layout changed"
        )

    def _get(self, url: str) -> str:
        argv = ["curl", "-sSL", "--fail", "--proto", "=https", "--max-time", "60", url]
        try:
            return self._curl.run(argv).stdout.decode("utf-8", "replace")
        except ServiceError as e:
            raise ServiceError(f"fetch failed for {url}: {e}") from e


def _segment(value: str) -> str:
    if not _SLUG.fullmatch(value):
        raise ValidationError(f"docs.redhat.com path segment {value!r} is not a plain slug")
    return value
