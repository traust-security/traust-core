"""Deterministic declarative manifest extraction from a pinned repository tree.

Reads declarative Maven (`pom.xml`), Gradle (`settings.gradle[.kts]` + `gradle.properties` + static
module build files), Python (`pyproject.toml`, `setup.cfg`), and npm/pnpm/yarn workspace
(`package.json`, `pnpm-workspace.yaml`) metadata without executing repository code or following
symlinks outside the checkout root. Dynamic/scripted build expressions fail closed.
"""

from __future__ import annotations

import configparser
import fnmatch
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.component_target import PackageManifestCandidate
from traust_core.v1.models.purl import canonical_package_id
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.tree import SKIP_DIRS as TREE_SKIP_DIRS
from traust_core.v1.providers.tree import TreeFile, tree_files

YamlLoader = Callable[[str], list[object]]

SKIP_DIRS = TREE_SKIP_DIRS | frozenset(
    {
        "target",
        "tests",
        "test",
        "testing",
        "examples",
        "example",
        "samples",
        "sample",
        "docs",
        "doc",
        "benchmarks",
        "it",
    }
)

_MAX_POM_ANCESTORS = 16
_XML_PROP = re.compile(r"\$\{([^}]+)\}")
_GRADLE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_GRADLE_LINE_COMMENT = re.compile(r"(?m)//[^\n]*$")
_GRADLE_ROOT_NAME = re.compile(r"""rootProject\.name\s*=\s*(['"])([^'"$\r\n]+)\1""")
_GRADLE_INCLUDE_CALL = re.compile(r"""(?m)^\s*include\s*\(([^)]*)\)""")
_GRADLE_INCLUDE_STMT = re.compile(r"""(?m)^\s*include\s+([^\r\n(][^\r\n]*)""")
_GRADLE_QUOTED = re.compile(r"""(['"])([^'"$\r\n]+)\1""")
_GRADLE_PROJECT_DIR = re.compile(
    r"""project\s*\(\s*(['"])([^'"$\r\n]+)\1\s*\)\s*\.projectDir\s*=\s*"""
    r"""(?:file|File)\s*\(\s*(?:(?:rootDir|settingsDir)\s*,\s*)?(['"])([^'"$\r\n]+)\3\s*\)"""
)
_GRADLE_STATIC_ASSIGN = re.compile(
    r"""(?m)^[ \t]*(group|version|archivesBaseName|artifactId)"""
    r"""\s*(?:=|\s+)\s*(['"])([^'"$\r\n]+)\2[ \t]*$"""
)
_GRADLE_ARCHIVES_NAME = re.compile(
    r"""(?m)^[ \t]*base\.archivesName\.set\s*\(\s*(['"])([^'"$\r\n]+)\1\s*\)[ \t]*$"""
)
_GRADLE_ANY_ASSIGN = re.compile(r"""(?m)^[ \t]*(group|version)\s*=""")


def _read_text(entry: TreeFile) -> str | None:
    try:
        return entry.text
    except ServiceError:
        return None


def _rel_dir(rel: str) -> str:
    parent, sep, _ = rel.rpartition("/")
    return parent if sep and parent else "."


def _xml_tag(elem: ET.Element) -> str:
    return elem.tag.rsplit("}", 1)[-1]


def _xml_child_text(parent: ET.Element, name: str) -> str | None:
    for child in parent:
        if _xml_tag(child) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _xml_properties(root_el: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for child in root_el:
        if _xml_tag(child) == "properties":
            for prop in child:
                if prop.text and prop.text.strip():
                    props[_xml_tag(prop)] = prop.text.strip()
    return props


_MAX_PROP_PASSES = 10
# a coordinate is short; the repository is untrusted, so a property chain that multiplies
# (`<a>${b}${b}</a>`, `<b>${c}${c}</b>`, ...) stops at this bound instead of exhausting memory
_MAX_PROP_LENGTH = 1024


def _resolve_maven_prop(value: str | None, props: dict[str, str]) -> str | None:
    """Substitute `${...}` until nothing changes, so a property defined through another
    (`${revision}` → `${release.version}` → `7.1.0`) resolves; a cycle, an unknown key or an
    expansion past `_MAX_PROP_LENGTH` stays unresolved (None), never guessed."""
    if value is None:
        return None
    resolved = value
    for _ in range(_MAX_PROP_PASSES):
        substituted = _XML_PROP.sub(lambda m: props.get(m.group(1), m.group(0)), resolved)
        if len(substituted) > _MAX_PROP_LENGTH:
            return None
        if substituted == resolved:
            break
        resolved = substituted
    return None if "${" in resolved else resolved


def _maven_builtin_props(
    parent_group: str | None,
    parent_artifact: str | None,
    parent_version: str | None,
    group_id: str | None = None,
) -> dict[str, str]:
    """Maven's model properties a POM may reference: the parent's coordinates, and the
    project's own groupId once known (`${project.version}` is the value being resolved)."""
    props: dict[str, str] = {}
    if parent_version is not None:
        props["project.parent.version"] = props["parent.version"] = parent_version
    if parent_group is not None:
        props["project.parent.groupId"] = props["parent.groupId"] = parent_group
    if parent_artifact is not None:
        props["project.parent.artifactId"] = props["parent.artifactId"] = parent_artifact
    if group_id is not None:
        props["project.groupId"] = group_id
    return props


def _resolve_maven_parent_rel(mod_dir: str, relative_path: str) -> str | None:
    """Resolve a Maven `<relativePath>` against `mod_dir` without escaping the checkout root."""
    parts = [] if mod_dir == "." else mod_dir.split("/")
    for seg in relative_path.replace("\\", "/").split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    if not parts:
        return "pom.xml"
    if parts[-1].endswith(".xml"):
        return "/".join(parts)
    return "/".join((*parts, "pom.xml"))


def _maven_declared_modules(
    parsed_by_rel: dict[str, tuple[str, ET.Element, dict[str, str]]],
) -> set[str]:
    declared: set[str] = set()
    for mod_dir, el, _ in parsed_by_rel.values():
        module_containers = [c for c in el if _xml_tag(c) == "modules"]
        for profiles in (c for c in el if _xml_tag(c) == "profiles"):
            for profile in (p for p in profiles if _xml_tag(p) == "profile"):
                module_containers.extend(m for m in profile if _xml_tag(m) == "modules")
        for container in module_containers:
            for mod_el in container:
                if _xml_tag(mod_el) == "module" and mod_el.text and mod_el.text.strip():
                    mod_pom = _resolve_maven_parent_rel(mod_dir, mod_el.text.strip())
                    if mod_pom is not None:
                        declared.add(_rel_dir(mod_pom))
    return declared


def _scan_maven(files: list[TreeFile]) -> list[PackageManifestCandidate]:
    poms = [f for f in files if f.name == "pom.xml"]
    if not poms:
        return []
    parsed_by_rel: dict[str, tuple[str, ET.Element, dict[str, str]]] = {}
    for pom in poms:
        text = _read_text(pom)
        if text is None:
            continue
        try:
            el = ET.fromstring(text)
        except ET.ParseError:
            continue
        parsed_by_rel[pom.rel] = (_rel_dir(pom.rel), el, _xml_properties(el))

    declared_modules = _maven_declared_modules(parsed_by_rel)
    memo: dict[
        str, tuple[str | None, str | None, str | None, dict[str, str], tuple[str, ...], bool]
    ] = {}

    def resolve_pom(
        rel_path: str, stack: frozenset[str] = frozenset()
    ) -> tuple[str | None, str | None, str | None, dict[str, str], tuple[str, ...], bool]:
        if rel_path in memo:
            return memo[rel_path]
        mod_dir, el, local_props = parsed_by_rel[rel_path]
        parent_el = next((c for c in el if _xml_tag(c) == "parent"), None)
        raw_p_group = _xml_child_text(parent_el, "groupId") if parent_el is not None else None
        raw_p_artifact = _xml_child_text(parent_el, "artifactId") if parent_el is not None else None
        raw_p_version = _xml_child_text(parent_el, "version") if parent_el is not None else None

        matched_parent: (
            tuple[str | None, str | None, str | None, dict[str, str], tuple[str, ...], bool] | None
        ) = None
        if (
            parent_el is not None
            and raw_p_group
            and raw_p_artifact
            and raw_p_version
            and len(stack) < _MAX_POM_ANCESTORS
        ):
            rel_el = next((c for c in parent_el if _xml_tag(c) == "relativePath"), None)
            if rel_el is None:
                target_rel = _resolve_maven_parent_rel(mod_dir, "../pom.xml")
            elif rel_el.text and rel_el.text.strip():
                target_rel = _resolve_maven_parent_rel(mod_dir, rel_el.text.strip())
            else:
                target_rel = None
            if (
                target_rel is not None
                and target_rel != rel_path
                and target_rel not in stack
                and target_rel in parsed_by_rel
            ):
                anc = resolve_pom(target_rel, stack | {rel_path})
                cand_props = {**anc[3], **local_props}
                eval_p_group = _resolve_maven_prop(raw_p_group, cand_props)
                eval_p_ver = _resolve_maven_prop(raw_p_version, cand_props)
                if (
                    eval_p_group is not None
                    and eval_p_ver is not None
                    and (anc[0], anc[1], anc[2]) == (eval_p_group, raw_p_artifact, eval_p_ver)
                ):
                    matched_parent = anc

        if matched_parent is not None:
            merged_props = {**matched_parent[3], **local_props}
            parent_group = matched_parent[0]
            parent_version = matched_parent[2]
            manifests = tuple(sorted({rel_path, *matched_parent[4]}))
        else:
            merged_props = dict(local_props)
            parent_group = _resolve_maven_prop(raw_p_group, local_props)
            parent_version = _resolve_maven_prop(raw_p_version, local_props)
            manifests = (rel_path,)

        parent_artifact = (
            matched_parent[1]
            if matched_parent is not None
            else _resolve_maven_prop(raw_p_artifact, local_props)
        )
        model_props = {
            **merged_props,
            **_maven_builtin_props(parent_group, parent_artifact, parent_version),
        }
        raw_group = _xml_child_text(el, "groupId")
        # an inherited groupId only when the POM states none: one it states but that can't
        # resolve fails closed (None), never borrows the parent's
        group_id = (
            _resolve_maven_prop(raw_group, model_props) if raw_group is not None else parent_group
        )
        model_props.update(
            _maven_builtin_props(parent_group, parent_artifact, parent_version, group_id)
        )
        artifact_id = _resolve_maven_prop(_xml_child_text(el, "artifactId"), model_props)
        raw_explicit_ver = _xml_child_text(el, "version")
        if raw_explicit_ver is not None:
            version = _resolve_maven_prop(raw_explicit_ver, model_props)
            inherits = False
        else:
            version = parent_version
            inherits = matched_parent is not None
        res = (group_id, artifact_id, version, merged_props, manifests, inherits)
        if not stack:
            memo[rel_path] = res
        return res

    raw_candidates: list[PackageManifestCandidate] = []
    for rel_path in sorted(parsed_by_rel):
        mod_dir = parsed_by_rel[rel_path][0]
        group_id, artifact_id, version, _, manifests, inherits = resolve_pom(rel_path)
        if not group_id or not artifact_id:
            continue
        raw_candidates.append(
            PackageManifestCandidate(
                ecosystem=Ecosystem.MAVEN,
                package_id=canonical_package_id("maven", group_id, artifact_id),
                version=version,
                module_path=mod_dir,
                manifest_paths=manifests,
                project_name=artifact_id if mod_dir == "." else None,
                is_workspace_root=(mod_dir == "."),
                is_workspace_member=(mod_dir in declared_modules),
                inherits_root_version=inherits,
            )
        )

    declared_pkg_ids = {
        c.package_id for c in raw_candidates if c.is_workspace_root or c.is_workspace_member
    }
    return [
        c
        for c in raw_candidates
        if c.package_id not in declared_pkg_ids or c.is_workspace_root or c.is_workspace_member
    ]


def _parse_gradle_properties(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")) or "=" not in line:
            continue
        key, _, val = line.partition("=")
        k, v = key.strip(), val.strip()
        if k and v and "${" not in v:
            props[k] = v
    return props


def _strip_gradle_comments(text: str) -> str:
    return _GRADLE_LINE_COMMENT.sub("", _GRADLE_BLOCK_COMMENT.sub("", text))


def _normalize_rel_subdir(raw: str) -> str | None:
    cleaned = raw.strip().replace("\\", "/").strip("/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:].strip("/")
    parts = [p for p in cleaned.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        return None
    return "/".join(parts)


def _gradle_script_fields(
    text: str,
) -> tuple[str | None, bool, str | None, bool, str | None]:
    clean = _strip_gradle_comments(text)
    static_vals: dict[str, str] = {}
    for match in _GRADLE_STATIC_ASSIGN.finditer(clean):
        static_vals[match.group(1)] = match.group(3).strip()
    if (
        "artifactId" not in static_vals
        and "archivesBaseName" not in static_vals
        and (arch := _GRADLE_ARCHIVES_NAME.search(clean))
    ):
        static_vals["archivesBaseName"] = arch.group(2).strip()
    assigned_keys = {m.group(1) for m in _GRADLE_ANY_ASSIGN.finditer(clean)}
    group_dyn = "group" in assigned_keys and "group" not in static_vals
    ver_dyn = "version" in assigned_keys and "version" not in static_vals
    artifact_override = static_vals.get("artifactId") or static_vals.get("archivesBaseName")
    return (
        static_vals.get("group"),
        group_dyn,
        static_vals.get("version"),
        ver_dyn,
        artifact_override,
    )


def _scan_gradle(files: list[TreeFile]) -> list[PackageManifestCandidate]:
    by_rel = {f.rel: f for f in files}
    settings_rel = next(
        (name for name in ("settings.gradle.kts", "settings.gradle") if name in by_rel), None
    )
    root_build_rel = next(
        (name for name in ("build.gradle.kts", "build.gradle") if name in by_rel), None
    )
    if settings_rel is None and root_build_rel is None:
        return []

    props: dict[str, str] = {}
    has_gradle_props = False
    if "gradle.properties" in by_rel and (props_text := _read_text(by_rel["gradle.properties"])):
        props = _parse_gradle_properties(props_text)
        has_gradle_props = bool(props)

    root_group = props.get("group")
    root_version = props.get("version")
    used_root_build = False
    if root_build_rel is not None and (rb_text := _read_text(by_rel[root_build_rel])):
        rb_g, rb_g_dyn, rb_v, rb_v_dyn, _ = _gradle_script_fields(rb_text)
        if rb_g_dyn:
            root_group = None
        elif rb_g:
            root_group = rb_g
            used_root_build = True
        if rb_v_dyn:
            root_version = None
        elif rb_v:
            root_version = rb_v
            used_root_build = True

    root_project_name: str | None = None
    subprojects: dict[str, tuple[str, str]] = {}
    if settings_rel is not None and (s_text := _read_text(by_rel[settings_rel])):
        clean_s = _strip_gradle_comments(s_text)
        if rn := _GRADLE_ROOT_NAME.search(clean_s):
            root_project_name = rn.group(2).strip()
        chunks = [m.group(1) for m in _GRADLE_INCLUDE_CALL.finditer(clean_s)]
        chunks.extend(m.group(1) for m in _GRADLE_INCLUDE_STMT.finditer(clean_s))
        for chunk in chunks:
            for q in _GRADLE_QUOTED.finditer(chunk):
                raw_proj = q.group(2).strip()
                norm_proj = ":" + raw_proj.lstrip(":")
                segs = [s for s in norm_proj.split(":") if s]
                if segs and all(s not in (".", "..") for s in segs):
                    subprojects[norm_proj] = ("/".join(segs), segs[-1])
        for ov in _GRADLE_PROJECT_DIR.finditer(clean_s):
            proj_key = ":" + ov.group(2).strip().lstrip(":")
            custom_dir = _normalize_rel_subdir(ov.group(4))
            if proj_key in subprojects and custom_dir is not None:
                subprojects[proj_key] = (custom_dir, subprojects[proj_key][1])

    candidates: list[PackageManifestCandidate] = []
    if root_build_rel is not None and (rb_text := _read_text(by_rel[root_build_rel])):
        rg, rg_dyn, rv, rv_dyn, r_art = _gradle_script_fields(rb_text)
        eff_g = None if rg_dyn else (rg or props.get("group"))
        eff_v = None if rv_dyn else (rv or props.get("version"))
        art = r_art or root_project_name
        if eff_g and art:
            manifests = [root_build_rel]
            if settings_rel is not None:
                manifests.append(settings_rel)
            if has_gradle_props and (not rg or not rv):
                manifests.append("gradle.properties")
            candidates.append(
                PackageManifestCandidate(
                    ecosystem=Ecosystem.MAVEN,
                    package_id=canonical_package_id("maven", eff_g, art),
                    version=eff_v,
                    module_path=".",
                    manifest_paths=tuple(sorted(set(manifests))),
                    project_name=root_project_name or art,
                    is_workspace_root=True,
                    is_workspace_member=False,
                )
            )

    for _, (mod_dir, mod_name) in sorted(subprojects.items()):
        script_candidates = (
            f"{mod_dir}/build.gradle.kts",
            f"{mod_dir}/build.gradle",
            f"{mod_dir}/{mod_name}.gradle.kts",
            f"{mod_dir}/{mod_name}.gradle",
        )
        mod_script = next((s for s in script_candidates if s in by_rel), None)
        if mod_script is None:
            continue
        m_text = _read_text(by_rel[mod_script])
        if m_text is None:
            continue
        mg, mg_dyn, mv, mv_dyn, m_art = _gradle_script_fields(m_text)
        eff_g = None if mg_dyn else (mg or root_group)
        eff_v = None if mv_dyn else (mv or root_version)
        if not eff_g:
            continue
        manifests = [mod_script]
        if settings_rel is not None:
            manifests.append(settings_rel)
        if has_gradle_props and (not mg or not mv):
            manifests.append("gradle.properties")
        if used_root_build and root_build_rel is not None and (not mg or not mv):
            manifests.append(root_build_rel)
        candidates.append(
            PackageManifestCandidate(
                ecosystem=Ecosystem.MAVEN,
                package_id=canonical_package_id("maven", eff_g, m_art or mod_name),
                version=eff_v,
                module_path=mod_dir,
                manifest_paths=tuple(sorted(set(manifests))),
                project_name=root_project_name,
                is_workspace_root=False,
                is_workspace_member=True,
                inherits_root_version=(mv is None and not mv_dyn and eff_v is not None),
            )
        )
    return candidates


def _uv_workspace_patterns(files: list[TreeFile]) -> list[str]:
    by_rel = {f.rel: f for f in files}
    if "pyproject.toml" not in by_rel:
        return []
    text = _read_text(by_rel["pyproject.toml"])
    if not text:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    tool = data.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    ws = uv.get("workspace") if isinstance(uv, dict) else None
    if not isinstance(ws, dict):
        return []
    patterns: list[str] = []
    members = ws.get("members")
    if isinstance(members, list):
        patterns.extend(
            str(m).strip().rstrip("/") for m in members if isinstance(m, str) and m.strip()
        )
    excludes = ws.get("exclude")
    if isinstance(excludes, list):
        patterns.extend(
            "!" + str(e).strip().rstrip("/") for e in excludes if isinstance(e, str) and e.strip()
        )
    return patterns


def _scan_python(files: list[TreeFile]) -> list[PackageManifestCandidate]:
    uv_patterns = _uv_workspace_patterns(files)
    by_key: dict[tuple[str, str], PackageManifestCandidate] = {}
    for entry in files:
        if entry.name != "pyproject.toml":
            continue
        text = _read_text(entry)
        if text is None:
            continue
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        raw_project = data.get("project")
        project: dict[str, Any] = raw_project if isinstance(raw_project, dict) else {}
        raw_tool = data.get("tool")
        raw_poetry = raw_tool.get("poetry") if isinstance(raw_tool, dict) else None
        poetry: dict[str, Any] = raw_poetry if isinstance(raw_poetry, dict) else {}
        name = project.get("name") or poetry.get("name")
        version = project.get("version") or poetry.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        ver_str = version.strip() if isinstance(version, str) and version.strip() else None
        raw_dynamic = project.get("dynamic")
        is_dynamic = ver_str is None and isinstance(raw_dynamic, list) and "version" in raw_dynamic
        mod_dir = _rel_dir(entry.rel)
        is_member = _matches_workspace(mod_dir, uv_patterns)
        manifests = [entry.rel]
        if is_member:
            manifests.append("pyproject.toml")
        pkg_id = canonical_package_id("pypi", None, name.strip())
        by_key[(mod_dir, pkg_id)] = PackageManifestCandidate(
            ecosystem=Ecosystem.PYPI,
            package_id=pkg_id,
            version=ver_str,
            module_path=mod_dir,
            manifest_paths=tuple(sorted(set(manifests))),
            project_name=name.strip() if mod_dir == "." else None,
            is_workspace_root=(mod_dir == "."),
            is_workspace_member=is_member,
            is_dynamic_version=is_dynamic,
        )

    for entry in files:
        if entry.name != "setup.cfg":
            continue
        text = _read_text(entry)
        if text is None:
            continue
        cfg = configparser.ConfigParser(interpolation=None)
        try:
            cfg.read_string(text)
        except configparser.Error:
            continue
        if not cfg.has_section("metadata"):
            continue
        name = cfg.get("metadata", "name", fallback="").strip()
        if not name:
            continue
        raw_ver = cfg.get("metadata", "version", fallback="").strip()
        if not raw_ver:
            ver_str, is_dyn = None, False
        elif raw_ver.startswith(("attr:", "file:")):
            ver_str, is_dyn = None, True
        else:
            ver_str, is_dyn = raw_ver, False
        mod_dir = _rel_dir(entry.rel)
        pkg_id = canonical_package_id("pypi", None, name)
        existing = by_key.get((mod_dir, pkg_id))
        if existing is not None:
            if existing.version is None and ver_str is not None:
                by_key[(mod_dir, pkg_id)] = existing.model_copy(
                    update={
                        "version": ver_str,
                        "is_dynamic_version": False,
                        "manifest_paths": tuple(sorted({*existing.manifest_paths, entry.rel})),
                    }
                )
            continue
        is_member = _matches_workspace(mod_dir, uv_patterns)
        manifests = [entry.rel]
        if is_member:
            manifests.append("pyproject.toml")
        by_key[(mod_dir, pkg_id)] = PackageManifestCandidate(
            ecosystem=Ecosystem.PYPI,
            package_id=pkg_id,
            version=ver_str,
            module_path=mod_dir,
            manifest_paths=tuple(sorted(set(manifests))),
            project_name=name if mod_dir == "." else None,
            is_workspace_root=(mod_dir == "."),
            is_workspace_member=is_member,
            is_dynamic_version=is_dyn,
        )
    return list(by_key.values())


def _workspace_globs(
    files: list[TreeFile], load_yaml: YamlLoader | None
) -> tuple[list[str], list[str]]:
    by_rel = {f.rel: f for f in files}
    patterns: list[str] = []
    manifests: list[str] = []
    if "package.json" in by_rel:
        text = _read_text(by_rel["package.json"])
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            ws = data.get("workspaces") if isinstance(data, dict) else None
            raw_list: list[Any] = (
                ws
                if isinstance(ws, list)
                else (ws.get("packages", []) if isinstance(ws, dict) else [])
            )
            if raw_list:
                manifests.append("package.json")
                patterns.extend(
                    str(p).strip().rstrip("/") for p in raw_list if isinstance(p, str) and p.strip()
                )
    if "pnpm-workspace.yaml" in by_rel:
        if load_yaml is None:
            raise ConfigError(
                "pnpm-workspace.yaml requires a YAML loader "
                "(inject context.documents.yaml_documents)"
            )
        text = _read_text(by_rel["pnpm-workspace.yaml"])
        if text:
            try:
                docs = load_yaml(text)
            except ValidationError:
                docs = []
            first = docs[0] if docs and isinstance(docs[0], dict) else {}
            raw_pkgs = first.get("packages")
            pkgs = (
                [str(p).strip().rstrip("/") for p in raw_pkgs if isinstance(p, str) and p.strip()]
                if isinstance(raw_pkgs, list)
                else []
            )
            if pkgs:
                manifests.append("pnpm-workspace.yaml")
                patterns.extend(pkgs)
    return patterns, manifests


def _match_segments(parts: tuple[str, ...], pats: tuple[str, ...]) -> bool:
    if not pats:
        return not parts
    head, rest = pats[0], pats[1:]
    if head == "**":
        return _match_segments(parts, rest) or (bool(parts) and _match_segments(parts[1:], pats))
    if not parts:
        return False
    return fnmatch.fnmatchcase(parts[0], head) and _match_segments(parts[1:], rest)


def _matches_workspace(mod_dir: str, patterns: list[str]) -> bool:
    if mod_dir == "." or not patterns:
        return False
    mod_parts = tuple(p for p in mod_dir.split("/") if p)
    included = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        pat = pattern[1:] if negated else pattern
        pat_parts = tuple(p for p in pat.strip("/").split("/") if p and p != ".")
        if pat_parts and _match_segments(mod_parts, pat_parts):
            included = not negated
    return included


def _scan_npm(
    files: list[TreeFile], load_yaml: YamlLoader | None
) -> list[PackageManifestCandidate]:
    pkg_files = [f for f in files if f.name == "package.json"]
    if not pkg_files:
        return []
    ws_patterns, ws_manifests = _workspace_globs(files, load_yaml)
    candidates: list[PackageManifestCandidate] = []
    for entry in pkg_files:
        text = _read_text(entry)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        raw_version = data.get("version")
        version = (
            raw_version.strip() if isinstance(raw_version, str) and raw_version.strip() else None
        )
        is_private = bool(data.get("private") is True)
        mod_dir = _rel_dir(entry.rel)
        is_root = mod_dir == "."
        is_member = _matches_workspace(mod_dir, ws_patterns)
        manifests = [entry.rel]
        if is_member:
            manifests.extend(ws_manifests)
        ns, pkg_name = (
            (name.strip().split("/", 1)[0], name.strip().split("/", 1)[1])
            if name.strip().startswith("@") and "/" in name.strip()
            else (None, name.strip())
        )
        candidates.append(
            PackageManifestCandidate(
                ecosystem=Ecosystem.NPM,
                package_id=canonical_package_id("npm", ns, pkg_name),
                version=version,
                module_path=mod_dir,
                manifest_paths=tuple(sorted(set(manifests))),
                project_name=pkg_name if is_root else None,
                is_private=is_private,
                is_workspace_root=is_root,
                is_workspace_member=is_member,
            )
        )
    return candidates


class PackageManifestScanner:
    """Reads build and workspace manifests from a pinned local checkout."""

    def __init__(self, load_yaml: YamlLoader | None = None) -> None:
        self._load_yaml = load_yaml

    def scan(self, checkout: Path) -> list[PackageManifestCandidate]:
        files = tree_files(checkout, skip=SKIP_DIRS)
        return [
            *_scan_maven(files),
            *_scan_gradle(files),
            *_scan_python(files),
            *_scan_npm(files, self._load_yaml),
        ]
