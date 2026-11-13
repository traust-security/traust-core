"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.common import RepoPath
from traust_core.v1.models.dependencies import UnresolvedManifest
from traust_core.v1.models.vocabulary import Ecosystem, ManifestCoverageReason
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest
from traust_core.v1.providers.tree import MAX_FILE_BYTES, SKIP_DIRS

# npm devDependencies count: without this syft drops them from package-lock (not yarn.lock).
_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}

# The files syft's directory catalogers read (syft 1.51): an archive checkout keeps only these.
# In a sample of 60 repositories, 53,881 of 53,884 packages were found; the rest came from
# checked-in binaries. Re-measure after a syft upgrade.
MANIFESTS: tuple[str, ...] = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "action.yml",
    "action.yaml",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "modules.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "requirements*.txt",
    "*requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "METADATA",
    "PKG-INFO",
    "RECORD",
    "top_level.txt",
    "direct_url.json",
    "pom.xml",
    "*.pom",
    "gradle.lockfile*",
    "*.gradle",
    "*.gradle.kts",
    "pom.properties",
    "*.jar",
    "*.war",
    "*.ear",
    "*.par",
    "*.sar",
    "*.nar",
    "*.jpi",
    "*.hpi",
    "*.lpkg",
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile",
    "Gemfile.lock",
    "*.gemspec",
    "packages.lock.json",
    "*.deps.json",
    "*.csproj",
    "*.fsproj",  # read by no cataloger: kept so coverage can name it unresolved
    "*.vbproj",
    "packages.config",
    "composer.lock",
    "installed.json",
    "composer.json",
    "pubspec.lock",
    "pubspec.yaml",
    "mix.lock",
    "rebar.lock",
    "stack.yaml",
    "stack.yaml.lock",
    "cabal.project.freeze",
    "Package.resolved",
    "Podfile.lock",
    "conanfile.txt",
    "conanfile.py",
    "conan.lock",
    "*.rockspec",
    "DESCRIPTION",
    "*.opam",
    ".terraform.lock.hcl",
    "Chart.yaml",
    "Chart.lock",
)


class SyftSbom:
    name = "syft"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return self._process.readiness(self.name)

    def acquire(self, request: ToolRequest) -> Result[bytes]:
        workspace = request.checkout()
        run = self._process.run(
            [self.name, "-q", f"dir:{workspace}", "-o", "cyclonedx-json"], check=False, env=_ENV
        )
        if run.returncode != 0:
            tail = run.stderr.decode(errors="replace").strip()[-300:] or "no stderr"
            raise ServiceError(f"syft exited {run.returncode}: {tail}")
        version = _tool_version(run.stdout)
        return Result(
            run.stdout,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                source=str(workspace),
                version=version,
                argv_sha256=argv_digest(run.argv),
            ),
        )

    def version(self) -> str | None:
        run = self._process.run([self.name, "version", "-o", "json"])
        try:
            return str(json.loads(run.stdout)["version"])
        except (ValueError, KeyError, TypeError) as e:
            raise ServiceError(f"syft version wrote no version: {e}") from e

    def database(self) -> DatabaseStatus | None:
        return None

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(f"{self.name} keeps no database to update")


def _tool_version(raw: bytes) -> str | None:
    try:
        tools = json.loads(raw)["metadata"]["tools"]
    except (ValueError, KeyError, TypeError) as e:
        raise ServiceError(f"syft wrote no CycloneDX metadata: {e}") from e
    listed = tools.get("components", []) if isinstance(tools, dict) else tools
    return next((str(t["version"]) for t in listed if t.get("name") == "syft"), None)


def _table(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _any_group(groups: object) -> bool:
    return any(bool(g) for g in _table(groups).values())


def _json_deps(text: str) -> bool:
    doc = _table(json.loads(text))
    keys = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    return any(doc.get(k) for k in keys)


def _pyproject_deps(text: str) -> bool:
    doc = tomllib.loads(text)
    project = _table(doc.get("project"))
    poetry = _table(_table(doc.get("tool")).get("poetry"))
    return (
        bool(project.get("dependencies"))
        or _any_group(project.get("optional-dependencies"))
        or _any_group(doc.get("dependency-groups"))
        or bool(set(_table(poetry.get("dependencies"))) - {"python"})
        or bool(poetry.get("dev-dependencies"))
        or any(_table(g).get("dependencies") for g in _table(poetry.get("group")).values())
    )


_CARGO_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _cargo_deps(text: str) -> bool:
    doc = tomllib.loads(text)
    targets = [_table(t) for t in _table(doc.get("target")).values()]
    return any(t.get(k) for t in (doc, *targets) for k in _CARGO_TABLES) or bool(
        _table(doc.get("workspace")).get("dependencies")
    )


def _pipfile_deps(text: str) -> bool:
    doc = tomllib.loads(text)
    return bool(doc.get("packages")) or bool(doc.get("dev-packages"))


_GEM = re.compile(r"^\s*(?:gem|gemspec)\b", re.MULTILINE)
_EXACT = re.compile(r"===?")
_RANGE = re.compile(r"[<>!~]|,")


def _unpinned_requirements(text: str) -> bool:
    """A requirement without one exact version (a range, or a bare name): syft drops it."""
    for line in text.replace("\\\n", " ").splitlines():
        spec = line.split("#", 1)[0].split(" --", 1)[0].split(";", 1)[0].strip()
        if spec and not spec.startswith("-") and (_RANGE.search(spec) or not _EXACT.search(spec)):
            return True
    return False


def _requirements(name: str) -> bool:
    return name.endswith(".txt") and "requirements" in name


@dataclass(frozen=True)
class _Rule:
    """A manifest syft can't fully resolve (syft 1.51) unless `locks` pin it, beside it or, with
    `above`, higher in the tree (npm, Python and Cargo workspaces lock at their root; a Gemfile,
    Pipfile or project file locks beside itself). No locks: syft reads it directly and drops what
    `declares` finds."""

    ecosystem: Ecosystem
    manifest: Callable[[str], bool]
    declares: Callable[[str], bool]
    locks: frozenset[str] = frozenset()
    above: bool = True
    reason: ManifestCoverageReason = ManifestCoverageReason.NO_LOCKFILE


_RULES = (
    _Rule(Ecosystem.NPM, lambda n: n == "package.json", _json_deps,
          frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                     "bun.lock"})),
    _Rule(Ecosystem.PYPI, lambda n: n == "pyproject.toml", _pyproject_deps,
          frozenset({"poetry.lock", "uv.lock", "pdm.lock"})),
    _Rule(Ecosystem.PYPI, lambda n: n == "Pipfile", _pipfile_deps, frozenset({"Pipfile.lock"}),
          above=False),
    _Rule(Ecosystem.PYPI, _requirements, _unpinned_requirements,
          reason=ManifestCoverageReason.UNPINNED),
    _Rule(Ecosystem.CARGO, lambda n: n == "Cargo.toml", _cargo_deps, frozenset({"Cargo.lock"})),
    _Rule(Ecosystem.RUBY, lambda n: n == "Gemfile", lambda text: bool(_GEM.search(text)),
          frozenset({"Gemfile.lock"}), above=False),
    _Rule(Ecosystem.NUGET, lambda n: n.endswith((".csproj", ".fsproj", ".vbproj")),
          lambda text: "<PackageReference" in text, frozenset({"packages.lock.json"}),
          above=False),
)  # fmt: skip


def _declares(rule: _Rule, path: Path) -> bool:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return True  # too large to read here; whatever it declares is unknown
        return rule.declares(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return True  # syft can't read it either: whatever it declares is unknown
    except OSError as e:
        raise ServiceError(f"cannot read manifest {path.name}: {e}") from e


def _filled(path: Path) -> bool:
    """A lockfile with something in it: an empty one pins nothing."""
    try:
        with path.open("rb") as f:
            head = f.read(64)
    except OSError:
        return False
    return "".join(head.decode("utf-8", errors="replace").split()) not in {"", "{}", "[]"}


def unresolved_manifests(workspace: Path) -> tuple[UnresolvedManifest, ...]:
    """The checkout's dependency manifests whose declarations syft can't all pin: a manifest
    with no lockfile, or a requirements file with ranges. Their packages may be missing from
    the SBOM. Vendored and generated trees are skipped, as the profilers skip them."""
    if not workspace.is_dir():
        raise ValidationError(f"workspace is not a directory: {workspace}")
    held: dict[PurePosixPath, set[str]] = {}
    for top, dirs, names in os.walk(workspace, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        held[PurePosixPath(Path(top).relative_to(workspace).as_posix())] = set(names)

    def locked(rule: _Rule, directory: PurePosixPath) -> bool:
        scope = [directory, *directory.parents] if rule.above else [directory]
        return any(
            _filled(workspace / d / n) for d in scope for n in rule.locks & held.get(d, set())
        )

    found = []
    for directory, names in sorted(held.items()):
        for name in sorted(names):
            path = workspace / directory / name
            if path.is_symlink() or not path.is_file():
                continue
            for rule in _RULES:
                if rule.manifest(name) and not locked(rule, directory) and _declares(rule, path):
                    found.append(
                        UnresolvedManifest(
                            ecosystem=rule.ecosystem,
                            path=RepoPath((directory / name).as_posix()),
                            reason=rule.reason,
                        )
                    )
    return tuple(found)
