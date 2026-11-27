"""A checkout's manifest SBOM from syft (CycloneDX JSON): the standard tool, never a custom
manifest parser."""

from __future__ import annotations

import ast
import configparser
import json
import os
import re
import shlex
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.common import RepoPath
from traust_core.v1.models.dependencies import UnresolvedManifest
from traust_core.v1.models.vocabulary import Ecosystem, ManifestCoverageReason
from traust_core.v1.providers.base import Acquisition, Readiness, Result, argv_digest
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolRequest
from traust_core.v1.providers.tree import MAX_FILE_BYTES, SKIP_DIRS

# npm devDependencies count, as the retired portfolio graph counted them: without this syft
# drops them from package-lock (not from yarn.lock), measured 2026-10-28 (dependencies log).
_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"}

_CONTAINERFILES = ("Dockerfile", "Dockerfile.*", "Containerfile", "Containerfile.*")


# Keep Syft's inputs and containerfiles, which the coverage probe needs even when Syft skips them.
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
    *_CONTAINERFILES,
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


_SETUP_KEYS = ("install_requires", "extras_require", "setup_requires", "tests_require")


def _setup_py_unpinned(text: str) -> bool:
    """A setup.py whose requirements syft can't read whole: syft keeps only exact (`==`) pins
    listed literally in the setup() call; a range, or any requirement built at run time (a
    variable, a call), is dropped. Parsed with `ast`, never executed; unparsable is unknown."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg not in _SETUP_KEYS:
                continue
            value = keyword.value
            groups = value.values if isinstance(value, ast.Dict) else [value]
            for group in groups:
                if not isinstance(group, (ast.List, ast.Tuple)):
                    return True  # built at run time: syft can't see it
                for item in group.elts:
                    if not (isinstance(item, ast.Constant) and isinstance(item.value, str)):
                        return True
                    if _unpinned_requirements(item.value):
                        return True
    return False


def _setup_cfg_deps(text: str) -> bool:
    """A setup.cfg declaring requirements: syft catalogs none of them, pinned or not."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return True
    return any(
        value.strip()
        for section, keys in (
            ("options", ("install_requires", "setup_requires", "tests_require")),
            (
                "options.extras_require",
                tuple(parser["options.extras_require"])
                if parser.has_section("options.extras_require")
                else (),
            ),
        )
        if parser.has_section(section)
        for key in keys
        if (value := parser.get(section, key, fallback=""))
    )


def _requirements(name: str) -> bool:
    return name.endswith(".txt") and "requirements" in name


def _containerfile(name: str) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in _CONTAINERFILES)


_DIRECTIVE = re.compile(r"#\s*(syntax|escape|check)\s*=\s*(.+)", re.I)
_WORD = re.compile(r"""(?:[^\s'"\\]++|\\.|'[^']*'|"(?:[^"\\]++|\\.)*")++""")
_HEREDOC = re.compile(r"[0-9]*<<(-?)([^<]+)")


def _builder_flags(args: str, escape: str) -> tuple[list[str], str]:
    flags = []
    pos = 0
    while args.startswith("--", pos):
        word: list[str] = []
        quote = ""
        while pos < len(args):
            char = args[pos]
            if not quote and char.isspace():
                break
            pos += 1
            if char == escape:
                if pos == len(args):
                    raise ValueError("incomplete Dockerfile flag escape")
                word.append(args[pos])
                pos += 1
            elif char == quote:
                quote = ""
            elif not quote and char in "'\"":
                quote = char
            else:
                word.append(char)
        if quote:
            raise ValueError("unterminated Dockerfile flag quote")
        while pos < len(args) and args[pos].isspace():
            pos += 1
        flag = "".join(word)
        if flag == "--":
            break
        flags.append(flag)
    return flags, args[pos:]


def _unquoted_heredoc(word: str) -> bool:
    quote, pos = "", 0
    while pos < len(word):
        char = word[pos]
        if quote == "'":
            if char == quote:
                quote = ""
        elif char == "\\":
            pos += 1
        elif quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif word.startswith("<<", pos):
            return True
        pos += 1
    return False


def _heredocs(args: str, *, shell: bool) -> Iterator[tuple[str, bool]]:
    # BuildKit recognizes heredocs as complete whitespace-delimited words, not shell tokens:
    # cat<<EOF is ambiguous and must not cause us to skip possible Docker instructions.
    end = 0
    for word in _WORD.finditer(args):
        if args[end : word.start()].strip():
            raise ValueError("invalid Dockerfile word")
        end = word.end()
        if match := _HEREDOC.fullmatch(word[0]):
            [delimiter] = shlex.split(match[2])
            yield delimiter, bool(match[1])
        elif shell and _unquoted_heredoc(word[0]):
            raise ValueError("ambiguous Dockerfile heredoc")
    if args[end:].strip():
        raise ValueError("invalid Dockerfile word")


def _docker_instructions(text: str) -> Iterator[tuple[str, list[str], str]]:
    lines = iter(text.removeprefix("\ufeff").split("\n"))
    escape, directives = "\\", True
    for line in lines:
        line = line.strip()
        if directives and (directive := _DIRECTIVE.fullmatch(line)):
            if directive[1].lower() == "escape":
                escape = directive[2]
                if escape not in ("\\", "`"):
                    raise ValueError("invalid Dockerfile escape directive")
            continue
        directives = False
        if not line or line.startswith("#"):
            continue
        parts = []
        while line.endswith(escape) and not line.endswith(escape * 2):
            parts.append(line[:-1])
            for line in lines:
                if line.strip() and not line.lstrip().startswith("#"):
                    line = line.rstrip(" \t\r")
                    break
            else:
                raise ValueError("unterminated Dockerfile continuation")
        command = "".join([*parts, line]).split(None, 1)
        if command[0].lower() == "onbuild" and len(command) == 2:
            command = command[1].split(None, 1)
        op, args = command[0].lower(), command[1] if len(command) == 2 else ""
        if op not in {"from", "add", "copy", "run"}:
            continue
        flags, args = _builder_flags(args, escape)
        yield op, flags, args
        if op == "from" or "<<" not in args:
            continue
        if args.startswith("["):
            try:
                if isinstance(json.loads(args), list):
                    continue
            except ValueError:
                pass  # e.g. a shell test: RUN [ -f file ] && cat <<EOF
        for delimiter, chomp in _heredocs(args, shell=op == "run"):
            for body in lines:
                if (body.lstrip("\t") if chomp else body) == delimiter:
                    break
            else:
                raise ValueError("unterminated Dockerfile heredoc")


def _external_base(text: str) -> bool:
    stages: set[str] = set()
    stage_count = 0
    for op, flags, args in _docker_instructions(text):
        if op == "from":
            words = args.lower().split()
            if not words or (words[0] != "scratch" and words[0] not in stages):
                return True
            if len(words) == 3 and words[1] == "as":
                stages.add(words[2])
            stage_count += 1
        if op == "copy":
            for flag in flags:
                key, _, source = flag.lower().partition("=")
                if (
                    key == "--from"
                    and source not in stages
                    and not (source.isascii() and source.isdecimal() and int(source) < stage_count)
                ):
                    return True
    return False


@dataclass(frozen=True)
class _Rule:
    """A manifest syft can't fully resolve (syft 1.51) unless `locks` pin it, beside it or, with
    `above`, higher in the tree (npm, Python and Cargo workspaces lock at their root; a Gemfile,
    Pipfile or project file locks beside itself). No locks: syft reads it directly and drops what
    `declares` finds. Measured gaps: dependencies log 2026-10-28."""

    ecosystem: Ecosystem
    manifest: Callable[[str], bool]
    declares: Callable[[str], bool]
    locks: frozenset[str] = frozenset()
    above: bool = True
    reason: str = ManifestCoverageReason.NO_LOCKFILE

    def gap(self, path: PurePosixPath) -> UnresolvedManifest:
        try:
            reason = ManifestCoverageReason(self.reason)
        except ValueError as e:
            raise ConfigError(
                f"installed manifest coverage contract lacks reason {self.reason!r}"
            ) from e
        return UnresolvedManifest(
            ecosystem=self.ecosystem, path=RepoPath(path.as_posix()), reason=reason
        )


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
    _Rule(Ecosystem.PYPI, lambda n: n == "setup.py", _setup_py_unpinned,
          frozenset({"poetry.lock", "uv.lock", "pdm.lock"}),
          reason=ManifestCoverageReason.UNPINNED),
    _Rule(Ecosystem.PYPI, lambda n: n == "setup.cfg", _setup_cfg_deps,
          frozenset({"poetry.lock", "uv.lock", "pdm.lock"}), reason="unsupported-manifest"),
    _Rule(Ecosystem.CARGO, lambda n: n == "Cargo.toml", _cargo_deps, frozenset({"Cargo.lock"})),
    _Rule(Ecosystem.RUBY, lambda n: n == "Gemfile", lambda text: bool(_GEM.search(text)),
          frozenset({"Gemfile.lock"}), above=False),
    _Rule(Ecosystem.NUGET, lambda n: n.endswith((".csproj", ".fsproj", ".vbproj")),
          lambda text: "<PackageReference" in text, frozenset({"packages.lock.json"}),
          above=False),
    _Rule(Ecosystem.DOCKER, _containerfile, _external_base, reason="unsupported-manifest"),
)  # fmt: skip

# Ecosystems whose absence a manifest scan can prove: a rule knows the manifests that declare
# membership and the lockfiles (or pins) that resolve it. Elsewhere syft's silence proves
# nothing, and the impact read must not assert `not_imported` off it.
PROTECTED_ECOSYSTEMS = frozenset({rule.ecosystem for rule in _RULES})


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
    """Find unresolved declarations; beneath build directories, inspecting only containerfiles."""
    if not workspace.is_dir():
        raise ValidationError(f"workspace is not a directory: {workspace}")
    held: dict[PurePosixPath, set[str]] = {}
    for top, dirs, names in os.walk(workspace, followlinks=False):
        directory = PurePosixPath(Path(top).relative_to(workspace).as_posix())
        dirs[:] = sorted(d for d in dirs if d == "build" or d not in SKIP_DIRS)
        held[directory] = (
            {name for name in names if _containerfile(name)}
            if "build" in directory.parts
            else set(names)
        )

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
                    found.append(rule.gap(directory / name))
    return tuple(found)
