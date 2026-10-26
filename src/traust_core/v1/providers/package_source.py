"""Fix patches and installed package source, fetched only from the hosts the feeds registry names
(`role: fix-patches` / `role: package-source`), and read from the extracted tree.

Advisory data names the upstream repository, so a URL taken from it is attacker-influenced:
nothing is fetched off the allow-list, a redirect must stay on it, sizes are capped, archives
are extracted with path and link checks, and nothing fetched is ever executed.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.parse
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import quote

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.below_range import (
    DeclaredSource,
    FileChange,
    FilePresence,
    HunkPresence,
)
from traust_core.v1.models.dependencies import Version
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.http import HttpFetcher

MAX_BYTES = 200 * 1024 * 1024
MAX_STRIP = 6  # a Maven module's sources sit under <module>/src/main/java/ in the repository
NUGET_REGISTRATION = "https://api.nuget.org/v3/registration5-semver1/"
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")


class FetchRefused(ServiceError):
    """A URL or redirect off the allow-list, a body over the cap, or a package with no source."""


@dataclass(frozen=True, slots=True)
class SourceHosts:
    """The allow-list: forge hosts for patches, registry hosts for source, and where a fetch
    from each host may be redirected; `sources` names the registry entries they came from."""

    forges: frozenset[str]
    registries: frozenset[str]
    redirects: Mapping[str, frozenset[str]] = field(default_factory=dict)
    sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FetchedSource:
    url: str
    sha256: str
    files: int
    tree: Path  # the package root inside the extracted archive
    declared_by: DeclaredSource | None = None


class PackageSources:
    """Allow-listed fetches of fix patches and installed package source."""

    name = "package-sources"

    def __init__(self, hosts: SourceHosts, *, http: HttpFetcher) -> None:
        self.hosts = hosts
        self._http = http
        self._npm_times: dict[str, Mapping[str, Any]] = {}
        self._gem_times: dict[str, dict[str, str | None]] = {}
        self._nuspecs: dict[tuple[str, str], tuple[str, str]] = {}

    def check(self) -> Readiness:
        if not self.hosts.forges or not self.hosts.registries:
            return Readiness(
                ready=False,
                detail="the feeds registry names no enabled fix-patches or package-source source",
            )
        return Readiness(ready=True, detail=f"hosts from {', '.join(self.hosts.sources)}")

    def patch(self, url: str) -> str:
        return self._get(url, self.hosts.forges).decode("utf-8", errors="replace")

    def source(self, ecosystem: Ecosystem, name: str, version: str, dest: Path) -> FetchedSource:
        """The installed version's source, extracted under `dest`."""
        declared = self.nuget_declared(name, version) if ecosystem == Ecosystem.NUGET else None
        url, kind = self._source_url(ecosystem, name, version, declared)
        blob = self._get(url, self.hosts.registries)
        files = extract(blob, kind, dest)
        return FetchedSource(url, sha256(blob).hexdigest(), files, root_of(dest), declared)

    def nuget_id(self, name: str, version: str) -> str:
        """The id as its publisher cased it (nuspec): NuGet ids are case-insensitive, OSV's
        NuGet lookup is not, and manifests carry whatever casing the project wrote."""
        _url, text = self._nuspec(name, version)
        m = re.search(r"<id>\s*([A-Za-z0-9_.-]+)\s*</id>", text)
        if not m or m.group(1).lower() != name.lower():
            raise FetchRefused(f"nuspec id does not match {name}")
        return m.group(1)

    def nuget_published(self, name: str) -> str | None:
        """The id as nuget.org's registration index publishes it; None when nuget.org doesn't
        know it (an internal package keeps its written id)."""
        index_url = f"{NUGET_REGISTRATION}{quote(name.lower(), safe='')}/index.json"
        try:
            index = _json(self._get(index_url, self.hosts.registries))
        except ServiceError as e:
            if e.status == 404:
                return None
            raise
        pages = index.get("items") or []
        if not pages:
            return None
        items = pages[0].get("items")
        if not items:  # large packages link their pages instead of inlining them
            page = str(pages[0].get("@id") or "")
            if not page.startswith(NUGET_REGISTRATION):
                raise FetchRefused(f"registration page off nuget.org: {page}")
            items = _json(self._get(page, self.hosts.registries)).get("items") or []
        found = ((items[0] if items else {}).get("catalogEntry") or {}).get("id")
        return found if isinstance(found, str) and found.lower() == name.lower() else None

    def nuget_declared(self, name: str, version: str) -> DeclaredSource:
        """The repository and commit a NuGet package's nuspec says it was built from: the package
        holds compiled assemblies, so this claim is how its source is found."""
        url, text = self._nuspec(name, version)
        tag = re.search(r"<repository\b[^>]*>", text)
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', tag.group(0))) if tag else {}
        repo, commit = attrs.get("url", ""), attrs.get("commit", "").lower()
        if not repo or not _COMMIT.fullmatch(commit):
            raise FetchRefused(f"nuspec declares no source repository and commit: {url}")
        return DeclaredSource(nuspec=url, repository=repo, commit=commit)

    def release_time(self, ecosystem: Ecosystem, name: str, version: str) -> str | None:
        """When the registry published this version (ISO 8601). None when the registry doesn't
        say (Maven Central, crates.io's CDN, NuGet's flat container) or didn't answer: a fact
        for review, so a missing date never stops a packet."""
        try:
            return self._release_time(ecosystem, name, version)
        except (ServiceError, ValueError, KeyError, TypeError, AttributeError):
            return None

    def _release_time(self, ecosystem: Ecosystem, name: str, version: str) -> str | None:
        reg = self.hosts.registries
        if ecosystem == Ecosystem.GO:
            v = version if version.startswith("v") else "v" + version
            url = f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(v)}.info"
            return _json(self._get(url, reg)).get("Time")
        if ecosystem == Ecosystem.PYPI:
            meta = _json(self._get(f"https://pypi.org/pypi/{name}/{version}/json", reg))
            times = sorted(
                u["upload_time_iso_8601"]
                for u in meta.get("urls") or []
                if u.get("upload_time_iso_8601")
            )
            return times[0] if times else None
        if ecosystem == Ecosystem.RUBY:
            if name not in self._gem_times:
                url = f"https://rubygems.org/api/v1/versions/{name}.json"
                rows = json.loads(self._get(url, reg))
                self._gem_times[name] = {
                    r["number"]: r.get("created_at")
                    for r in rows
                    if r.get("platform", "ruby") == "ruby"
                }
            return self._gem_times[name].get(version)
        if ecosystem == Ecosystem.NPM:
            if name not in self._npm_times:
                doc = _json(self._get(f"https://registry.npmjs.org/{name}", reg))
                self._npm_times[name] = doc.get("time") or {}
            return self._npm_times[name].get(version)
        return None

    def _nuspec(self, name: str, version: str) -> tuple[str, str]:
        ident, ver = name.lower(), nuget_version(version)
        if (ident, ver) not in self._nuspecs:
            url = f"https://api.nuget.org/v3-flatcontainer/{ident}/{ver}/{ident}.nuspec"
            text = self._get(url, self.hosts.registries).decode("utf-8", errors="replace")
            self._nuspecs[(ident, ver)] = (url, text)
        return self._nuspecs[(ident, ver)]

    def _source_url(
        self, ecosystem: Ecosystem, name: str, version: str, declared: DeclaredSource | None
    ) -> tuple[str, str]:
        if ecosystem == Ecosystem.GO:
            v = version if version.startswith("v") else "v" + version
            return f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(v)}.zip", "zip"
        if ecosystem == Ecosystem.PYPI:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
            urls = _json(self._get(url, self.hosts.registries)).get("urls") or []
            pick = next((u for u in urls if u.get("packagetype") == "sdist"), None) or next(
                (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
            )
            if not pick:
                raise FetchRefused(f"no sdist or wheel for {name} {version}")
            return pick["url"], "zip" if pick["filename"].endswith((".zip", ".whl")) else "tar"
        if ecosystem == Ecosystem.NPM:
            base = name.rsplit("/", 1)[-1]
            return f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz", "tar"
        if ecosystem == Ecosystem.CARGO:
            return f"https://static.crates.io/crates/{name}/{name}-{version}.crate", "tar"
        if ecosystem == Ecosystem.MAVEN:
            group, _, artifact = name.partition(":")
            if not group or not artifact:
                raise FetchRefused(f"not a Maven group:artifact: {name}")
            base = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/{version}"
            return f"{base}/{artifact}-{version}-sources.jar", "zip"
        if ecosystem == Ecosystem.RUBY:
            return f"https://rubygems.org/downloads/{name}-{version}.gem", "gem"
        if ecosystem == Ecosystem.NUGET and declared is not None:
            return archive_url(declared.repository, declared.commit), "tar"
        raise FetchRefused(f"no package source for {ecosystem} yet")

    def _get(self, url: str, allowed: frozenset[str]) -> bytes:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme != "https" or host not in allowed:
            raise FetchRefused(f"host not allowed: {host or url}")
        body, final = self._http.fetch(url, MAX_BYTES)
        final_host = urllib.parse.urlsplit(final).hostname or ""
        if final_host != host and final_host not in self.hosts.redirects.get(host, frozenset()):
            raise FetchRefused(f"redirected off the allow-list: {host} -> {final_host}")
        if len(body) > MAX_BYTES:
            raise FetchRefused(f"{url}: body over the size cap")
        return body


def _json(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise FetchRefused(f"unparseable JSON: {e}") from e
    if not isinstance(doc, dict):
        raise FetchRefused("expected a JSON object")
    return doc


def nuget_version(version: str) -> str:
    """NuGet's normalized form, as its flat container names files: lower case, no build metadata,
    no leading zeros, and no fourth part when it is 0."""
    core, _, pre = version.lower().split("+", 1)[0].partition("-")
    parts = [str(int(p)) if p.isdigit() else p for p in core.split(".")]
    if len(parts) == 4 and parts[3] == "0":
        parts = parts[:3]
    return ".".join(parts) + (f"-{pre}" if pre else "")


def archive_url(repository: str, commit: str) -> str:
    """The archive of `repository` at `commit` on GitHub or GitLab; the repository URL comes from
    the package, so only plain path segments pass and the host is always one of the two."""
    parts = urllib.parse.urlsplit(repository.strip())
    path = parts.path.strip("/").removesuffix(".git")
    if not _COMMIT.fullmatch(commit) or not all(_SEGMENT.fullmatch(x) for x in path.split("/")):
        raise FetchRefused(f"not a plain repository path: {repository}")
    if parts.scheme in ("https", "http", "git") and parts.hostname == "github.com":
        owner_repo = "/".join(path.split("/")[:2])
        if owner_repo.count("/") == 1:
            return f"https://github.com/{owner_repo}/archive/{commit}.tar.gz"
    if parts.scheme in ("https", "http") and parts.hostname == "gitlab.com" and "/" in path:
        name = path.rsplit("/", 1)[-1]
        return f"https://gitlab.com/{path}/-/archive/{commit}/{name}-{commit}.tar.gz"
    raise FetchRefused(f"source repository not on a supported forge: {repository}")


def go_escape(path: str) -> str:
    """The module proxy's case encoding: an upper-case letter becomes '!' + lower."""
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in path)


def extract(blob: bytes, kind: str, dest: Path) -> int:
    """Regular files only, each kept inside `dest`; links and escapes are skipped. A `.gem` is a
    tar holding the gem's files as `data.tar.gz`; that inner archive is what is extracted."""
    try:
        return _extract(blob, kind, dest)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as e:
        raise FetchRefused(f"unreadable {kind} archive: {e}") from e


def _extract(blob: bytes, kind: str, dest: Path) -> int:
    if kind == "gem":
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
            member = next(
                (m for m in tf.getmembers() if m.name == "data.tar.gz" and m.isfile()), None
            )
            inner = tf.extractfile(member) if member else None
            if inner is None:
                raise FetchRefused("gem has no data.tar.gz")
            return _extract(inner.read(MAX_BYTES + 1), "tar", dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()

    def target(name: str) -> Path | None:
        p = (dest / name).resolve()
        return p if p.is_relative_to(root) and p != root else None

    n = 0
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                if (t := target(info.filename)) is not None:
                    t.parent.mkdir(parents=True, exist_ok=True)
                    t.write_bytes(z.read(info))
                    n += 1
        return n
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf.getmembers():
            t = target(m.name) if m.isfile() else None
            f = tf.extractfile(m) if t is not None else None
            if t is not None and f is not None:
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(f.read())
                n += 1
    return n


def root_of(tree: Path) -> Path:
    """The package root of an extracted archive: descend while a directory holds one
    sub-directory and no files (a Go module zip nests `example.com/lib@v1.4.0/`)."""
    while True:
        entries = [p for p in tree.iterdir() if not p.name.startswith(".")]
        if len(entries) != 1 or not entries[0].is_dir():
            return tree
        tree = entries[0]


def anchor(files: Sequence[FileChange], root: Path) -> dict[str, Path]:
    """{patch path: installed file} for the leading-component strip that matches most files. A
    file is never matched by base name alone, so a same-named unrelated file isn't the target."""
    best: dict[str, Path] = {}
    for strip in range(MAX_STRIP + 1):
        found = {
            f.path: p
            for f in files
            if len(parts := f.path.split("/")) > strip
            and (p := root.joinpath(*parts[strip:])).is_file()
        }
        if len(found) > len(best):
            best = found
    return best


def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()


def presence(files: Sequence[FileChange], root: Path) -> list[FilePresence]:
    """Per file: where it is installed, and per hunk how many removed and added lines appear
    there (whitespace-normalized, blank lines ignored)."""
    found = anchor(files, root)
    out = []
    for f in files:
        installed = found.get(f.path)
        hunks: list[HunkPresence] = []
        if installed is not None:
            text = {_norm(x) for x in installed.read_text(errors="replace").splitlines()}
            for h in f.hunks:
                rem = [n for x in h.removed if (n := _norm(x))]
                add = [n for x in h.added if (n := _norm(x))]
                hunks.append(
                    HunkPresence(
                        removed_lines=len(rem),
                        removed_present=sum(x in text for x in rem),
                        added_lines=len(add),
                        added_present=sum(x in text for x in add),
                    )
                )
        out.append(
            FilePresence(
                patch_path=f.path,
                installed_path=str(installed.relative_to(root)) if installed else None,
                hunks=tuple(hunks),
            )
        )
    return out


def go_requires(root: Path) -> list[tuple[str, Version]]:
    """(module, version) for every require in a module zip's go.mod."""
    gomod = root / "go.mod"
    if not gomod.is_file():
        return []
    text = gomod.read_text(errors="replace")
    found: list[tuple[str, str]] = []
    for block in re.findall(r"(?ms)^require\s*\((.*?)^\)", text):
        found += re.findall(r"(?m)^\s*(\S+)\s+(v\S+)", block)
    found += re.findall(r"(?m)^require\s+(\S+)\s+(v\S+)", text)
    return [(m, Version(v.removeprefix("v"))) for m, v in found]


def importers(
    ecosystem: Ecosystem, dependency: str, files: Sequence[Path], root: Path
) -> list[str]:
    """The files (relative to `root`) whose text imports the dependency: a lead, not a proof."""
    d = re.escape(dependency)
    flags = 0
    if ecosystem == Ecosystem.NPM:
        pattern = rf"""(?:require\(\s*|from\s+|import\s+)['"]{d}(?:['"/])"""
    elif ecosystem == Ecosystem.PYPI:
        module = re.escape(re.sub(r"[-.]", "_", dependency.lower()))
        pattern, flags = rf"(?m)^\s*(?:from|import)\s+{module}\b", re.IGNORECASE
    elif ecosystem == Ecosystem.MAVEN:
        group = re.escape(dependency.split(":", 1)[0])
        pattern = rf"(?m)^\s*import\s+(?:static\s+)?{group}\."
    elif ecosystem == Ecosystem.CARGO:
        crate = re.escape(dependency.replace("-", "_"))
        pattern = rf"\b(?:use|extern crate)\s+{crate}\b|\b{crate}::"
    elif ecosystem == Ecosystem.GO:
        pattern = rf'"{d}(?:/[^"]*)?"'
    else:
        return []
    return [
        str(p.relative_to(root))
        for p in files
        if re.search(pattern, p.read_text(errors="replace"), flags)
    ]
