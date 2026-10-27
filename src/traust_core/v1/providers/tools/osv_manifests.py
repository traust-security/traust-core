"""The osv scanner's manifest and lockfile readers: each returns (declared name or None,
[(dependency, version, indirect)]) and never raises; malformed input reads as (None, [])."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

Dep = tuple[str, str, bool]
Parsed = tuple[str | None, list[Dep]]
Parser = Callable[[str], Parsed]


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


def _localname(tag: str) -> str:
    return tag.rpartition("}")[2]


def _child(elem: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in elem if _localname(c.tag) == name), None)


def _children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if _localname(c.tag) == name]


def _eltext(elem: ET.Element | None) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def _toml(text: str) -> dict[str, Any] | None:
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return None


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _resolve_npm_alias(spec: object) -> tuple[str, str] | None:
    """`npm:<real package>@<version>` as (real package, version): an alias is never reported
    under its alias name."""
    if not isinstance(spec, str) or not spec.startswith("npm:"):
        return None
    body = spec[len("npm:") :]
    idx = body.find("@", 1) if body.startswith("@") else body.find("@")
    if idx == -1:
        return (body, "") if body else None
    name = body[:idx]
    version = body[idx + 1 :].lstrip("^~=")
    return (name, version) if name else None


def parse_package_lock(text: str) -> Parsed:
    """package-lock.json v2/v3: direct when the root lists it; an aliased install under the real
    name npm records in `name`."""
    data = _json_object(text)
    packages = data.get("packages") if data else None
    if not isinstance(packages, dict):
        return None, []
    declared = None
    directs: set[str] = set()
    root = packages.get("")
    if isinstance(root, dict):
        declared = root.get("name") or None
        for sect in ("dependencies", "devDependencies"):
            if isinstance(m := root.get(sect), dict):
                directs.update(m.keys())
    declared = declared or data.get("name") or None
    deps: list[Dep] = []
    for path, spec in packages.items():
        if path == "" or not isinstance(spec, dict):
            continue
        alias_key = path.rpartition("node_modules/")[2]
        real_name = spec.get("name") or alias_key
        version = spec.get("version")
        if not real_name or not isinstance(version, str) or not version:
            continue
        deps.append((real_name, version, alias_key not in directs))
    return declared, deps


def parse_package_json(text: str) -> Parsed:
    data = _json_object(text)
    if data is None:
        return None, []
    deps: list[Dep] = []
    for sect in ("dependencies", "devDependencies"):
        m = data.get(sect)
        if not isinstance(m, dict):
            continue
        for name, rng in m.items():
            if not isinstance(name, str):
                continue
            if alias := _resolve_npm_alias(rng):
                deps.append((alias[0], alias[1], False))
            else:
                deps.append((name, rng.lstrip("^~") if isinstance(rng, str) else "", False))
    return data.get("name") or None, deps


def parse_npm_shrinkwrap(text: str) -> Parsed:
    return parse_package_lock(text)


_PNPM_DEP_HEADERS = ("dependencies:", "devDependencies:", "optionalDependencies:")


def _pnpm_split_key(key: str) -> tuple[str, str] | None:
    """`name@version` (v6+, optional `(peer@x)` suffix); the legacy v5 `name/version` key is
    skipped rather than mis-split."""
    name, sep, version = key.split("(", 1)[0].rpartition("@")
    if not sep or not name or not version:
        return None
    return name, version


def parse_pnpm_lock(text: str) -> Parsed:
    """pnpm-lock.yaml by a minimal line scan: `packages:` keys, direct when a dependencies block
    names them."""
    directs: set[str] = set()
    entries: list[tuple[str, str]] = []
    in_packages = False
    pkg_indent: int | None = None
    sect_indent: int | None = None
    child_indent: int | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if indent == 0:
            in_packages = content == "packages:"
            pkg_indent = None
            child_indent = None
            sect_indent = indent if content in _PNPM_DEP_HEADERS else None
            continue
        if in_packages:
            if pkg_indent is None:
                pkg_indent = indent
            if indent != pkg_indent or not content.endswith(":"):
                continue
            key = content[:-1].strip().strip("'\"").removeprefix("/")
            if split := _pnpm_split_key(key):
                entries.append(split)
            continue
        if content in _PNPM_DEP_HEADERS:
            sect_indent = indent
            child_indent = None
            continue
        if sect_indent is not None:
            if indent <= sect_indent:
                sect_indent = None
                child_indent = None
                continue
            if child_indent is None:
                child_indent = indent
            if indent == child_indent and (name := content.split(":", 1)[0].strip().strip("'\"")):
                directs.add(name)
    return None, [(n, v, n not in directs) for n, v in entries]


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"(?:===|==|>=|<=|~=|!=|<|>)\s*([^\s;,]+)"
)
_YARN_VERSION_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_name(spec: str) -> str | None:
    """The package of one yarn.lock key specifier; workspace, link, portal, file and exec
    protocols are local packages, not registry ones."""
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    if at <= 0:
        return None
    name, rng = spec[:at], spec[at + 1 :]
    if rng.startswith(("workspace:", "link:", "portal:", "file:", "exec:")):
        return None
    if rng.startswith("npm:") and "@" in rng[4:].lstrip("@"):
        real = rng[4:]
        at = real.find("@", 1)
        return real[:at] if at > 0 else None
    return name


def parse_yarn_lock(text: str) -> Parsed:
    """yarn.lock, classic and Berry: one transitive entry per resolved (name, version)."""
    deps: list[Dep] = []
    seen: set[tuple[str, str]] = set()
    names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            key = line.rstrip().rstrip(":")
            names = (
                []
                if key == "__metadata"
                else [n for n in (_yarn_name(s) for s in key.split(",")) if n]
            )
            continue
        if not names:
            continue
        m = _YARN_VERSION_RE.match(line)
        if m and line.startswith("  ") and not line.startswith("   "):
            version = m.group(1)
            for name in dict.fromkeys(names):
                if (name, version) not in seen:
                    seen.add((name, version))
                    deps.append((name, version, True))
            names = []
    return None, deps


_UV_LOCAL_SOURCES = {"editable", "virtual", "directory", "path"}


def parse_uv_lock(text: str) -> Parsed:
    """uv.lock packages; workspace members (local sources) are the project, not dependencies."""
    data = _toml(text)
    deps: list[Dep] = []
    for pkg in (data or {}).get("package") or []:
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source") or {}
        if isinstance(source, dict) and source.keys() & _UV_LOCAL_SOURCES:
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            deps.append((_pep503(name), version, True))
    return None, deps


def parse_requirements_txt(text: str) -> Parsed:
    deps: list[Dep] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line and (m := _REQ_LINE_RE.match(line)):
            deps.append((_pep503(m.group(1)), m.group(2).strip(), False))
    return None, deps


_PEP508_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def _parse_pep508(req: object) -> tuple[str, str] | None:
    if not isinstance(req, str):
        return None
    m = _PEP508_RE.match(req.split(";", 1)[0].strip())
    if not m:
        return None
    return _pep503(m.group(1)), m.group(2).strip().strip("()").strip()


def _spec_version(spec: object) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and isinstance(spec.get("version"), str):
        return spec["version"]
    return ""


def parse_pyproject_deps(text: str) -> Parsed:
    """pyproject.toml: PEP 621 dependencies and optional groups, and Poetry's dependency,
    dev-dependency and group sections."""
    data = _toml(text)
    if data is None:
        return None, []
    declared: str | None = None
    deps: list[Dep] = []
    project = data.get("project")
    if isinstance(project, dict):
        declared = project.get("name") or None
        groups = [project.get("dependencies")]
        if isinstance(opt := project.get("optional-dependencies"), dict):
            groups += list(opt.values())
        deps += [
            (p[0], p[1], False)
            for group in groups
            if isinstance(group, list)
            for r in group
            if (p := _parse_pep508(r))
        ]
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        declared = declared or poetry.get("name") or None
        sections = [
            poetry[s]
            for s in ("dependencies", "dev-dependencies")
            if isinstance(poetry.get(s), dict)
        ]
        if isinstance(grp := poetry.get("group"), dict):
            sections += [
                g["dependencies"]
                for g in grp.values()
                if isinstance(g, dict) and isinstance(g.get("dependencies"), dict)
            ]
        deps += [
            (_pep503(name), _spec_version(spec), False)
            for m in sections
            for name, spec in m.items()
            if isinstance(name, str) and name.lower() != "python"
        ]
    return declared, deps


def _toml_packages(text: str, name: Callable[[str], str]) -> Parsed:
    pkgs = (_toml(text) or {}).get("package")
    if not isinstance(pkgs, list):
        return None, []
    return None, [
        (name(p["name"]), p["version"], True)
        for p in pkgs
        if isinstance(p, dict)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("version"), str)
    ]


def parse_poetry_lock(text: str) -> Parsed:
    return _toml_packages(text, _pep503)


def parse_pipfile_lock(text: str) -> Parsed:
    data = _json_object(text)
    if data is None:
        return None, []
    deps: list[Dep] = []
    for sect in ("default", "develop"):
        m = data.get(sect)
        if not isinstance(m, dict):
            continue
        for name, spec in m.items():
            if isinstance(name, str):
                ver = spec.get("version") if isinstance(spec, dict) else None
                deps.append((_pep503(name), ver.lstrip("=") if isinstance(ver, str) else "", True))
    return None, deps


_SETUP_NAME_RE = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""")
_INSTALL_REQUIRES_RE = re.compile(r"install_requires\s*=\s*\[(.*?)\]", re.S)
_STR_LITERAL_RE = re.compile(r"""['"]([^'"]+)['"]""")


def parse_setup_py(text: str) -> Parsed:
    """setup.py's literal `install_requires=[...]`; a computed list reads as no dependencies."""
    m = _SETUP_NAME_RE.search(text)
    deps: list[Dep] = []
    if im := _INSTALL_REQUIRES_RE.search(text):
        deps = [
            (p[0], p[1], False)
            for sm in _STR_LITERAL_RE.finditer(im.group(1))
            if (p := _parse_pep508(sm.group(1)))
        ]
    return (m.group(1) if m else None), deps


def parse_constraints_txt(text: str) -> Parsed:
    return parse_requirements_txt(text)


_CONDA_SPEC_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:(?:==|>=|<=|!=|~=|=)\s*([^\s=]+))?"
)


def _parse_conda_spec(item: str) -> tuple[str, str] | None:
    item = item.split("::", 1)[-1].split("#", 1)[0].strip()
    if not item or not (m := _CONDA_SPEC_RE.match(item)):
        return None
    return _pep503(m.group(1)), (m.group(2) or "").strip()


def parse_environment_yml(text: str) -> Parsed:
    """environment.yml by a minimal line scan: conda specs and the nested `pip:` list, read as
    PyPI names (conda names approximate them)."""
    deps: list[Dep] = []
    in_deps = False
    deps_header_indent = 0
    pip_marker_indent: int | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = raw.strip()
        if content == "dependencies:":
            in_deps = True
            deps_header_indent = indent
            pip_marker_indent = None
            continue
        if not in_deps:
            continue
        if not content.startswith("-"):
            if indent <= deps_header_indent:
                in_deps = False
            continue
        item = content[1:].strip()
        if pip_marker_indent is not None and indent <= pip_marker_indent:
            pip_marker_indent = None
        if pip_marker_indent is None and item.startswith("pip:"):
            pip_marker_indent = indent
            continue
        parsed = _parse_pep508(item) if pip_marker_indent is not None else _parse_conda_spec(item)
        if parsed:
            deps.append((parsed[0], parsed[1], False))
    return None, deps


_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_prop(value: str, props: dict[str, str]) -> str:
    """`${prop}` references resolved; "" when any stays unresolved, so the dependency is skipped
    rather than given a bogus version."""
    cur = value
    for _ in range(10):
        if "${" not in cur:
            break
        nxt = _PROP_RE.sub(lambda m: props.get(m.group(1), ""), cur)
        if nxt == cur:
            break
        cur = nxt
    return "" if "${" in cur else cur


def parse_pom_xml(text: str) -> Parsed:
    """pom.xml, namespace-agnostic: `<dependencies>` and `<dependencyManagement>`, properties
    resolved; a dependency without a resolvable version is omitted."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, []
    proj_group = _eltext(_child(root, "groupId"))
    proj_art = _eltext(_child(root, "artifactId"))
    proj_ver = _eltext(_child(root, "version"))
    if (parent := _child(root, "parent")) is not None:
        proj_group = proj_group or _eltext(_child(parent, "groupId"))
        proj_ver = proj_ver or _eltext(_child(parent, "version"))
    declared = f"{proj_group}:{proj_art}" if proj_group and proj_art else None
    props: dict[str, str] = {}
    if (pel := _child(root, "properties")) is not None:
        props = {_localname(c.tag): (c.text or "").strip() for c in pel}
    if proj_ver:
        props.setdefault("project.version", proj_ver)
    dm = _child(root, "dependencyManagement")
    containers = [
        _child(root, "dependencies"),
        _child(dm, "dependencies") if dm is not None else None,
    ]
    deps: dict[Dep, None] = {}
    for container in (c for c in containers if c is not None):
        for dep in _children(container, "dependency"):
            g = _eltext(_child(dep, "groupId"))
            a = _eltext(_child(dep, "artifactId"))
            v = _resolve_prop(_eltext(_child(dep, "version")), props)
            if g and a and v:
                deps[(f"{g}:{a}", v, False)] = None
    return declared, list(deps)


def parse_gradle_lockfile(text: str) -> Parsed:
    deps: list[Dep] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        parts = line.split("=", 1)[0].strip().split(":")
        if len(parts) >= 3 and parts[0] and parts[1] and parts[2]:
            deps.append((f"{parts[0]}:{parts[1]}", parts[2], True))
    return None, deps


_GRADLE_DEP_RE = re.compile(
    r"\b(?:implementation|api|compile|compileOnly|runtimeOnly|"
    r"testImplementation|testCompile|testRuntimeOnly|annotationProcessor|"
    r"kapt|classpath)\b[^\n'\"]*['\"]"
    r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+)['\"]"
)


def parse_build_gradle(text: str) -> Parsed:
    """build.gradle[.kts]: string-literal `group:artifact:version` dependencies."""
    return None, [
        (f"{m.group(1)}:{m.group(2)}", m.group(3), False) for m in _GRADLE_DEP_RE.finditer(text)
    ]


def parse_cargo_lock(text: str) -> Parsed:
    return _toml_packages(text, str)


def parse_cargo_toml(text: str) -> Parsed:
    data = _toml(text)
    if data is None:
        return None, []
    pkg = data.get("package")
    deps = [
        (name, _spec_version(spec), False)
        for sect in ("dependencies", "dev-dependencies")
        if isinstance(m := data.get(sect), dict)
        for name, spec in m.items()
        if isinstance(name, str)
    ]
    return (pkg.get("name") or None) if isinstance(pkg, dict) else None, deps


_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9._-]+) \(([0-9][A-Za-z0-9._+-]*)\)\s*$")


def parse_gemfile_lock(text: str) -> Parsed:
    """Gemfile.lock: the 4-space `name (x.y.z)` specs; deeper lines are constraints, skipped."""
    deps: list[Dep] = []
    in_specs = False
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            in_specs = False
        elif raw.strip() == "specs:":
            in_specs = True
        elif in_specs and (m := _GEM_SPEC_RE.match(raw)):
            deps.append((m.group(1), m.group(2), True))
    return None, deps


_GEMSPEC_DEP_RE = re.compile(
    r"\.add(?:_runtime|_development)?_dependency\s*\(?\s*"
    r"['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?"
)
_GEMSPEC_NAME_RE = re.compile(r"\.name\s*=\s*['\"]([^'\"]+)['\"]")
_GEMFILE_RE = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", re.M)


def parse_gemspec(text: str) -> Parsed:
    m = _GEMSPEC_NAME_RE.search(text)
    deps = [(d.group(1), d.group(2) or "", False) for d in _GEMSPEC_DEP_RE.finditer(text)]
    return (m.group(1) if m else None), deps


def parse_gemfile(text: str) -> Parsed:
    return None, [(m.group(1), m.group(2) or "", False) for m in _GEMFILE_RE.finditer(text)]


def parse_packages_lock_json(text: str) -> Parsed:
    """NuGet packages.lock.json: `Direct` entries are direct; names lowercased."""
    data = _json_object(text)
    frameworks = data.get("dependencies") if data else None
    if not isinstance(frameworks, dict):
        return None, []
    return None, [
        (name.lower(), spec["resolved"], str(spec.get("type") or "").lower() != "direct")
        for pkgs in frameworks.values()
        if isinstance(pkgs, dict)
        for name, spec in pkgs.items()
        if isinstance(name, str)
        and isinstance(spec, dict)
        and isinstance(spec.get("resolved"), str)
        and spec["resolved"]
    ]


def parse_csproj(text: str) -> Parsed:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None, []
    deps: list[Dep] = []
    for el in root.iter():
        if _localname(el.tag) != "PackageReference":
            continue
        if name := el.get("Include") or el.get("Update"):
            ver = el.get("Version")
            if ver is None:
                ver = _eltext(_child(el, "Version"))
            deps.append((name, ver or "", False))
    return None, deps


_USES_RE = re.compile(r"""(?m)^\s*(?:-\s*)?uses\s*:\s*['"]?([^\s'"#]+)""")


def parse_github_workflow(text: str) -> Parsed:
    """A workflow's `uses: owner/repo[/path]@ref` as (owner/repo, ref); local and docker://
    references are skipped."""
    deps: dict[Dep, None] = {}
    for m in _USES_RE.finditer(text):
        ref = m.group(1)
        if ref.startswith((".", "/", "docker://")) or "@" not in ref:
            continue
        path, _, version = ref.rpartition("@")
        parts = path.split("/")
        if version and len(parts) >= 2 and parts[0] and parts[1]:
            deps[(f"{parts[0]}/{parts[1]}", version, False)] = None
    return None, list(deps)


_REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9._~\-/]+)\s+(v[^\s/]+)(\s*//\s*indirect)?\s*$")
_MODULE_RE = re.compile(r"^\s*module\s+(\S+)\s*$", re.MULTILINE)


def parse_gomod(text: str) -> tuple[str | None, list[Dep]]:
    """go.mod: the module path and every require (path, version, indirect)."""
    m = _MODULE_RE.search(text)
    requires: list[Dep] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        candidate = stripped if in_block else stripped.removeprefix("require ")
        if (in_block or stripped.startswith("require ")) and (rm := _REQUIRE_RE.match(candidate)):
            requires.append((rm.group(1), rm.group(2), bool(rm.group(3))))
    return (m.group(1) if m else None), requires


PARSER_BY_FILENAME: dict[str, tuple[str, Parser]] = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_npm_shrinkwrap),
    "pnpm-lock.yaml": ("npm", parse_pnpm_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
    "package.json": ("npm", parse_package_json),
    "poetry.lock": ("pypi", parse_poetry_lock),
    "Pipfile.lock": ("pypi", parse_pipfile_lock),
    "uv.lock": ("pypi", parse_uv_lock),
    "requirements.txt": ("pypi", parse_requirements_txt),
    "pyproject.toml": ("pypi", parse_pyproject_deps),
    "setup.py": ("pypi", parse_setup_py),
    "constraints.txt": ("pypi", parse_constraints_txt),
    "environment.yml": ("pypi", parse_environment_yml),
    "environment.yaml": ("pypi", parse_environment_yml),
    "gradle.lockfile": ("maven", parse_gradle_lockfile),
    "pom.xml": ("maven", parse_pom_xml),
    "build.gradle": ("maven", parse_build_gradle),
    "build.gradle.kts": ("maven", parse_build_gradle),
    "Cargo.lock": ("cargo", parse_cargo_lock),
    "Cargo.toml": ("cargo", parse_cargo_toml),
    "Gemfile.lock": ("ruby", parse_gemfile_lock),
    "Gemfile": ("ruby", parse_gemfile),
    "packages.lock.json": ("nuget", parse_packages_lock_json),
}


def parser_for(filename: str) -> tuple[str, Parser] | None:
    """(ecosystem, parser) for a manifest's basename, globs included (*.gemspec, *.csproj,
    *requirements*.txt)."""
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if hit := PARSER_BY_FILENAME.get(base):
        return hit
    if base.endswith(".gemspec"):
        return "ruby", parse_gemspec
    if base.endswith(".csproj"):
        return "nuget", parse_csproj
    if base.endswith(".txt") and "requirements" in base.lower():
        return "pypi", parse_requirements_txt
    return None


def is_workflow_path(path: str) -> bool:
    p = path.replace("\\", "/")
    return p.endswith((".yml", ".yaml")) and (
        "/.github/workflows/" in p or p.startswith(".github/workflows/")
    )


def parser_for_path(path: str) -> tuple[str, Parser] | None:
    """`parser_for`, with GitHub Actions workflows routed by their directory first."""
    if is_workflow_path(path):
        return "actions", parse_github_workflow
    return parser_for(path)
