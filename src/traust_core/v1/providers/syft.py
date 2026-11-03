"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import json
from fnmatch import fnmatchcase

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.sbom_formats import PURL_ECOSYSTEMS
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest, on_path
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest

# npm devDependencies count, as the retired portfolio graph counted them: without this syft
# drops them from package-lock (not from yarn.lock), measured 2026-10-28 (dependencies log).
_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}

# The files syft's directory catalogers read (syft 1.51): an archive checkout keeps only these.
# Measured 2026-10-28 on 60 repositories: 53,881 of 53,884 packages, the rest from checked-in
# binaries (continuous-ops evidence 19). Re-measure after a syft upgrade.
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

LANGUAGE_MANIFESTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "Go": ("golang", ("go.mod",)),
    "JavaScript": ("npm", ("package.json", "package-lock.json", "yarn.lock")),
    "TypeScript": ("npm", ("package.json", "package-lock.json", "yarn.lock")),
    "Python": ("pypi", ("pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock")),
    "Java": ("maven", ("pom.xml", "build.gradle", "gradle.lockfile")),
    "Kotlin": ("maven", ("build.gradle.kts", "pom.xml")),
    "Scala": ("maven", ("pom.xml", "build.gradle")),
    "Groovy": ("maven", ("build.gradle", "pom.xml")),
    "Rust": ("cargo", ("Cargo.toml", "Cargo.lock")),
    "Ruby": ("gem", ("Gemfile", "Gemfile.lock")),
    "C#": ("nuget", ("packages.lock.json", "project.csproj")),
    "F#": ("nuget", ("packages.lock.json",)),
    "Visual Basic": ("nuget", ("packages.lock.json",)),
    "PHP": ("composer", ("composer.json", "composer.lock")),
    "Swift": ("swift", ("Package.resolved",)),
    "Objective-C": ("cocoapods", ("Podfile.lock",)),
    "Dart": ("pub", ("pubspec.lock", "pubspec.yaml")),
    "Elixir": ("hex", ("mix.lock",)),
    "Erlang": ("hex", ("rebar.lock",)),
    "Haskell": ("hackage", ("stack.yaml.lock", "cabal.project.freeze")),
    "C": ("conan", ("conan.lock", "conanfile.txt")),
    "C++": ("conan", ("conan.lock", "conanfile.txt")),
    "Lua": ("luarocks", ("package.rockspec",)),
    "R": ("cran", ("DESCRIPTION",)),
    "OCaml": ("opam", ("package.opam",)),
}


def dependency_ecosystem(language: str) -> Ecosystem | None:
    """A retained Syft manifest whose packages Core can actually ingest, not just scan."""
    supported = LANGUAGE_MANIFESTS.get(language)
    if supported is None:
        return None
    package_type, manifests = supported
    if not any(fnmatchcase(manifest, pattern) for manifest in manifests for pattern in MANIFESTS):
        return None
    return PURL_ECOSYSTEMS.get(package_type)


class SyftSbom:
    name = "syft"

    def __init__(self, process: ProcessRunner, clock: Clock) -> None:
        self._process = process
        self._clock = clock

    def check(self) -> Readiness:
        return on_path(self.name, missing=" not on PATH")

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
