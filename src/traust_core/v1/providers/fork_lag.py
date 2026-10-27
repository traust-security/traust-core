"""Fork detection: whether a checkout forks or vendors an upstream project, and which upstream
version it tracks, each signal with file:line evidence. Pure-local: go.mod module path against the
checkout's origin, replace directives to fork orgs, version constants, git remotes on another
org, and whole projects under vendor/ or third_party/."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    ForkEvidence,
    ForkLagFact,
    ForkSignal,
    ForkSignalKind,
    ForkUpstream,
)
from traust_core.v1.models.common import RepoPath
from traust_core.v1.models.dependencies import Version
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest

# Vanity import prefixes -> code-host identity: k8s.io/kubernetes checked out from
# github.com/kubernetes/kubernetes is not a fork.
VANITY_PREFIXES = {
    "k8s.io/": "github.com/kubernetes/",
    "sigs.k8s.io/": "github.com/kubernetes-sigs/",
    "golang.org/x/": "github.com/golang/",
    "go.etcd.io/": "github.com/etcd-io/",
    "go.uber.org/": "github.com/uber-go/",
    "google.golang.org/grpc": "github.com/grpc/grpc-go",
    "google.golang.org/protobuf": "github.com/protobuf/protobuf-go",
}
# Version-constant names that never name the tracked upstream release.
_VERSION_NAME_SKIP = {"goversion", "apiversion", "schemaversion", "schemeversion",
                      "protocolversion", "minversion", "maxversion", "tlsversion"}  # fmt: skip
_VERSION_CONST = re.compile(
    r"^\s*(?:const\s+|var\s+)?([A-Za-z_]\w*)\s*"
    r'(?::?=|\s+string\s*=)\s*"v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)"'
)
_SEMVERISH = re.compile(r"^v?\d+\.\d+\.\d+[0-9A-Za-z.+-]*$")
_WALK_SKIP = {".git", "node_modules", ".venv", "__pycache__", "testdata"}
_VENDOR_HOLDERS = ("vendor", "third_party")
_MAX_DEPTH = 4
# Checkout containers, not fork orgs: no directory-identity fallback for a plain clone in them.
_CONTAINER_DIRS = {"tmp", "temp", "src", "repos", "clones", "checkouts", "work", "builds", "go",
                   "github.com", "gitlab.com"}  # fmt: skip
_MODULE = re.compile(r"^module\s+(\S+)")
_REQUIRE = re.compile(r"^\s*([A-Za-z0-9._/\-~]+)\s+(v\d\S*)\s*(?://.*)?$", re.M)
_REPLACE = re.compile(r"^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$")
_REMOTE = re.compile(r'^\[remote "([^"]+)"\]')
_URL = re.compile(r"^\s*url\s*=\s*(\S+)")

Identity = tuple[str, str, str]


def parse_remote_url(url: str) -> Identity | None:
    """A git remote URL as (host, org, name)."""
    m = re.match(
        r"(?:ssh://)?(?:[\w.-]+@)?([\w.-]+)[:/]([^/\s]+)/(\S+)",
        re.sub(r"^https?://", "", url.strip()),
    )
    if not m:
        return None
    host, org, name = m.groups()
    return host.lower(), org, re.sub(r"\.git$", "", name.rstrip("/"))


def module_identity(module: str) -> Identity | None:
    """A Go module path as (host, org, name), vanity prefixes mapped to their code host."""
    for prefix, canonical in VANITY_PREFIXES.items():
        if module == prefix.rstrip("/") or module.startswith(prefix):
            module = canonical + module[len(prefix) :] if prefix.endswith("/") else canonical
            break
    parts = module.split("/")
    if len(parts) < 3 or "." not in parts[0]:
        return None
    return parts[0].lower(), parts[1], parts[2]


def _same_repo(a: Identity, b: Identity) -> bool:
    return (a[1].lower(), a[2].lower()) == (b[1].lower(), b[2].lower())


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise ServiceError(f"fork detection: cannot read {path}: {e}") from e


@dataclass(frozen=True)
class _Checkout:
    root: Path

    def evidence(self, path: Path, line: int, quote: str) -> ForkEvidence:
        try:
            rel = path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            rel = str(path)
        return ForkEvidence(file=RepoPath(rel), line=line, quote=quote.strip()[:200])

    def git_config(self) -> Path | None:
        """The checkout's git config; a worktree's `.git` file names its gitdir, whose
        `commondir` holds the shared config."""
        dot_git = self.root / ".git"
        if dot_git.is_file():
            gitdir_line = _read(dot_git).partition("gitdir:")[2].strip()
            if not gitdir_line:
                return None
            gitdir = (self.root / gitdir_line).resolve()
            common = gitdir / "commondir"
            if common.is_file():
                gitdir = (gitdir / _read(common).strip()).resolve()
            dot_git = gitdir
        config = dot_git / "config"
        return config if config.is_file() else None

    def remotes(self) -> list[tuple[str, str, int, str]]:
        """(remote, url, line, line text) for each remote url in the git config."""
        config = self.git_config()
        if config is None:
            return []
        found, remote = [], None
        for i, line in enumerate(_read(config).splitlines(), 1):
            if m := _REMOTE.match(line.strip()):
                remote = m.group(1)
            elif (m := _URL.match(line)) and remote is not None:
                found.append((remote, m.group(1), i, line))
        return found

    def origin(self) -> Identity | None:
        url = next((url for remote, url, _, _ in self.remotes() if remote == "origin"), None)
        return parse_remote_url(url) if url else None


def _walk(base: Path, skip: set[str]) -> list[tuple[Path, list[str]]]:
    """(directory, file names) to depth four below `base`, in order; never follows a symlink."""
    found = []
    base_depth = len(base.resolve().parts)
    for top, dirs, names in os.walk(base, followlinks=False):
        depth = len(Path(top).resolve().parts) - base_depth
        dirs[:] = sorted(d for d in dirs if d not in skip and depth < _MAX_DEPTH)
        found.append((Path(top), sorted(names)))
    return found


def _gomod_fork(co: _Checkout) -> list[ForkSignal]:
    gomod = co.root / "go.mod"
    if not gomod.is_file():
        return []
    text = _read(gomod)
    lines = text.splitlines()
    signals = []
    found = next(
        ((i, m.group(1)) for i, ln in enumerate(lines, 1) if (m := _MODULE.match(ln))), None
    )
    if found and (mod_id := module_identity(found[1])):
        line_no, module = found
        actual = co.origin()
        detail = None
        if actual and not _same_repo(mod_id, actual):
            detail = f"checkout is {actual[0]}/{actual[1]}/{actual[2]}"
        elif not actual:
            parent = co.root.resolve().parent.name
            if (
                co.root.name.lower() == mod_id[2].lower()
                and parent
                and not parent.startswith(".")
                and parent.lower() not in _CONTAINER_DIRS
                and parent.lower() != mod_id[1].lower()
            ):
                detail = f"checkout directory is {parent}/{co.root.name}"
        if detail:
            signals.append(
                ForkSignal(
                    type=ForkSignalKind.GO_MOD_MODULE_PATH,
                    identity="/".join(mod_id),
                    package=module,
                    ecosystem=Ecosystem.GO,
                    evidence=(co.evidence(gomod, line_no, lines[line_no - 1]),),
                    detail=f"module declares upstream identity but {detail}",
                )
            )
    requires: dict[str, str] = {}
    for m in _REQUIRE.finditer(text):
        requires.setdefault(m.group(1), m.group(2))
    in_block = False
    for i, line in enumerate(lines, 1):
        stripped = line.split("//")[0].strip()
        if re.match(r"^replace\s*\($", stripped):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        body = stripped if in_block and "=>" in stripped else None
        if body is None and (m := re.match(r"^replace\s+(.*)$", stripped)) and "=>" in m.group(1):
            body = m.group(1)
        if not body or not (m := _REPLACE.match(body)):
            continue
        old, _, new, new_ver = m.groups()
        if new.startswith((".", "/")):
            continue  # a local-path replace names no fork
        old_id, new_id = module_identity(old), module_identity(new)
        if not old_id or not new_id or old_id == new_id:
            continue
        version = new_ver or requires.get(old)
        signals.append(
            ForkSignal(
                type=ForkSignalKind.GO_MOD_REPLACE,
                identity="/".join(old_id),
                package=old,
                ecosystem=Ecosystem.GO,
                version=Version(version.lstrip("v")) if version else None,
                evidence=(co.evidence(gomod, i, line),),
                detail=f"replace routes {old} to fork {new}",
            )
        )
    return signals


def _version_constants(co: _Checkout, base: Path) -> list[ForkSignal]:
    """VERSION files and version.go X.Y.Z constants: no identity of their own, they resolve the
    tracked version of one that has it."""
    scope = "" if base == co.root else base.relative_to(co.root).as_posix()
    signals = []
    for top, names in _walk(base, _WALK_SKIP | set(_VENDOR_HOLDERS)):
        for name in names:
            path = top / name
            if name.lower() in ("version", "version.txt"):
                first = _read(path).strip().splitlines()
                if first and _SEMVERISH.match(first[0].strip()):
                    signals.append(
                        ForkSignal(
                            type=ForkSignalKind.VERSION_CONSTANT,
                            version=Version(first[0].strip().lstrip("v")),
                            scope=scope,
                            evidence=(co.evidence(path, 1, first[0]),),
                        )
                    )
            elif name.lower() == "version.go":
                for i, line in enumerate(_read(path).splitlines(), 1):
                    m = _VERSION_CONST.match(line)
                    const = m.group(1).lower() if m else ""
                    if m and const.endswith("version") and const not in _VERSION_NAME_SKIP:
                        signals.append(
                            ForkSignal(
                                type=ForkSignalKind.VERSION_CONSTANT,
                                version=Version(m.group(2)),
                                scope=scope,
                                evidence=(co.evidence(path, i, line),),
                            )
                        )
    return signals


def _git_remotes(co: _Checkout) -> list[ForkSignal]:
    """A non-origin remote on another org than origin: the fork + upstream remote layout."""
    origin = co.origin()
    config = co.git_config()
    if origin is None or config is None:
        return []
    signals = []
    for remote, url, line_no, line in co.remotes():
        ident = parse_remote_url(url)
        if remote == "origin" or ident is None or _same_repo(ident, origin):
            continue
        signals.append(
            ForkSignal(
                type=ForkSignalKind.GIT_REMOTE,
                identity="/".join(ident),
                evidence=(co.evidence(config, line_no, line),),
                detail=f'remote "{remote}" points at a different org than origin '
                f"({'/'.join(origin)})",
            )
        )
    return signals


def _vendored(co: _Checkout) -> list[ForkSignal]:
    """A whole project (its own go.mod or package.json) under vendor/ or third_party/."""
    signals = []
    for holder in _VENDOR_HOLDERS:
        base = co.root / holder
        if not base.is_dir():
            continue
        claimed: list[Path] = []
        for top, names in _walk(base, _WALK_SKIP):
            if any(top.is_relative_to(c) for c in claimed):
                continue  # inside a project root already found
            projects = _project(co, top, names)
            for signal in projects:
                signals.append(
                    signal.model_copy(
                        update={
                            "scope": top.relative_to(co.root).as_posix(),
                            "detail": f"whole project vendored under {holder}/",
                        }
                    )
                )
            if projects:
                claimed.append(top)
    return signals


def _project(co: _Checkout, top: Path, names: list[str]) -> list[ForkSignal]:
    found = []
    if "go.mod" in names:
        gomod = top / "go.mod"
        for i, line in enumerate(_read(gomod).splitlines(), 1):
            if m := _MODULE.match(line):
                found.append(
                    ForkSignal(
                        type=ForkSignalKind.VENDORED_PROJECT,
                        identity=m.group(1),
                        package=m.group(1),
                        ecosystem=Ecosystem.GO,
                        evidence=(co.evidence(gomod, i, line),),
                    )
                )
                break
    if "package.json" in names:
        pj = top / "package.json"
        try:
            doc = json.loads(_read(pj))
        except json.JSONDecodeError:
            return found
        if isinstance(doc, dict) and isinstance(doc.get("name"), str) and doc["name"]:
            name, version = doc["name"], doc.get("version")
            if version is None or isinstance(version, str):
                found.append(
                    ForkSignal(
                        type=ForkSignalKind.VENDORED_PROJECT,
                        identity=name,
                        package=name,
                        ecosystem=Ecosystem.NPM,
                        version=Version(v) if (v := (version or "").lstrip("v")) else None,
                        evidence=(co.evidence(pj, 1, f'"name": "{name}", "version": "{version}"'),),
                    )
                )
    return found


def detect(root: Path) -> ForkLagFact:
    """Every detector's signals and the upstreams they name, each with its tracked version
    (its own, else the shallowest version constant in its scope); no network."""
    if not root.is_dir():
        raise ValidationError(f"fork detection: workspace is not a directory: {root}")
    co = _Checkout(root)
    signals = _gomod_fork(co) + _git_remotes(co) + _vendored(co)
    if not any(s.identity for s in signals):
        return ForkLagFact(signals=tuple(signals))
    versions = _version_constants(co, root)
    for i, s in enumerate(signals):
        if s.type is ForkSignalKind.VENDORED_PROJECT and not s.version:
            inner = _version_constants(co, root / s.scope)
            if inner:
                signals[i] = s.model_copy(
                    update={
                        "version": inner[0].version,
                        "evidence": s.evidence + inner[0].evidence,
                    }
                )
                versions += inner
    root_module = None
    if (root / "go.mod").is_file():
        m = re.search(r"^module\s+(\S+)", _read(root / "go.mod"), re.M)
        root_module = m.group(1) if m else None
    return ForkLagFact(
        signals=tuple(signals + versions), upstreams=_upstreams(signals, versions, root_module)
    )


def _upstreams(
    signals: list[ForkSignal], versions: list[ForkSignal], root_module: str | None
) -> tuple[ForkUpstream, ...]:
    """One upstream per package (a root remote's package is the root go.mod's module: the fork
    keeps upstream's identity)."""
    found: dict[str, tuple[ForkUpstream, str]] = {}
    for s in signals:
        if not s.identity:
            continue
        package, ecosystem = s.package, s.ecosystem
        if not package and s.scope == "":
            package, ecosystem = root_module, Ecosystem.GO if root_module else None
        key = (package or s.identity).lower()
        up, scope = found.get(key) or (
            ForkUpstream(
                identity=s.identity,
                package=package or s.identity,
                ecosystem=ecosystem or Ecosystem.GO,
                tracked_version=s.version,
            ),
            s.scope,
        )
        found[key] = (
            up.model_copy(
                update={
                    "tracked_version": up.tracked_version or s.version,
                    "evidence": up.evidence + tuple(e for e in s.evidence if e not in up.evidence),
                }
            ),
            scope,
        )
    resolved = []
    for up, scope in found.values():
        scoped = sorted(
            (v for v in versions if v.scope == scope),
            key=lambda v: (v.evidence[0].file.count("/"), v.evidence[0].file),
        )
        if not up.tracked_version and scoped:
            extra = tuple(e for e in scoped[0].evidence if e not in up.evidence)
            up = up.model_copy(
                update={"tracked_version": scoped[0].version, "evidence": up.evidence + extra}
            )
        resolved.append(up)
    return tuple(resolved)


class ForkDetector:
    kind = CodeFactKind.FORK_LAG
    name = "fork-detector"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = detect(request.checkout())
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
