from __future__ import annotations

import ast
import json
import os
import re
import tomllib
from collections import defaultdict
from pathlib import Path

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.code_facts import (
    CoverageGap,
    InterfaceFact,
    PackageExport,
    PackageFacts,
    PackageImport,
    PackageModule,
    SymbolFact,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.models.vocabulary import InterfaceRole
from traust_core.v1.providers.symbols import SKIP_DIRS, _builtin
from traust_core.v1.providers.syntax import js_parsers, walk
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tools.k8s_hardening import Scanner, YamlLoader

_GO_TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|[A-Za-z_]\w*|[^\s]')


def _files(root: Path) -> list[Path]:
    found = []
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(top) / d).is_symlink())
        found.extend(Path(top) / n for n in sorted(names) if not (Path(top) / n).is_symlink())
    return found


def _span(path: Path, root: Path, line: int | None = None) -> CodeSpan:
    return CodeSpan(path=RepoPath(path.relative_to(root).as_posix()), line=line)


def _nearest(path: Path, modules: list[tuple[Path, str]]) -> tuple[Path, str] | None:
    return next(((base, name) for base, name in modules if path.is_relative_to(base)), None)


def _python(path: Path, root: Path) -> PackageFacts:
    rel = path.relative_to(root).as_posix()
    package = rel.removesuffix(".py").removeprefix("src/").replace("/", ".")
    package = package.removesuffix(".__init__")
    try:
        tree = ast.parse(path.read_text(), filename=rel)
    except (SyntaxError, UnicodeError) as exc:
        return PackageFacts(
            gaps=(CoverageGap(system="Python", reason=str(exc), path=RepoPath(rel)),)
        )
    public: set[str] | None = None
    gaps = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            gaps.append(CoverageGap(system="Python", reason="dynamic __all__", path=RepoPath(rel)))
        else:
            if isinstance(value, (list, tuple)) and all(isinstance(n, str) for n in value):
                public = set(value)
    imports = []
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                if path.name != "__init__.py":
                    base = base[:-1]
                base = base[: len(base) - node.level + 1]
                names = [".".join([*base, *([node.module] if node.module else [])])]
            elif node.module:
                names = [node.module]
        imports.extend(
            PackageImport(package=n, language="Python", location=_span(path, root, node.lineno))
            for n in names
            if n
        )
    exports = []
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
        elif public is not None and isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.asname or alias.name.split(".")[0] for alias in node.names]
        exports.extend(
            PackageExport(
                package=package,
                name=n,
                kind=type(node).__name__,
                language="Python",
                location=_span(path, root, node.lineno),
            )
            for n in names
            if (n in public if public is not None else not n.startswith("_"))
        )
    return PackageFacts(imports=tuple(imports), exports=tuple(exports), gaps=tuple(gaps))


def _go(path: Path, root: Path, package: str | None, symbols: list[SymbolFact]) -> PackageFacts:
    tokens = [
        m for m in _GO_TOKEN.finditer(path.read_text()) if not m.group().startswith(("//", "/*"))
    ]
    imports = []
    for i, token in enumerate(tokens):
        if token.group() != "import":
            continue
        tail = tokens[i + 1 :]
        if not tail:
            continue
        end = (
            next((n for n, t in enumerate(tail) if t.group() == ")"), len(tail))
            if tail[0].group() == "("
            else min(2, len(tail))
        )
        for item in tail[:end]:
            if item.group().startswith(('"', "`")):
                imports.append(
                    PackageImport(
                        package=item.group()[1:-1],
                        language="Go",
                        location=_span(path, root, token.string.count("\n", 0, item.start()) + 1),
                    )
                )
    exports = tuple(
        PackageExport(package=package, name=s.name, kind=s.kind, language="Go", location=s.location)
        for s in symbols
        if package is not None and s.name[0].isupper() and s.kind != "type-receiver"
    )
    return PackageFacts(imports=tuple(imports), exports=exports)


class PackageIndex:
    """Declared modules, source imports/exports and Checkov's Kubernetes interface signals."""

    name = "portfolio-code-facts"
    version = "1"

    def __init__(self, load_yaml: YamlLoader) -> None:
        self._load_yaml = load_yaml

    def packages(self, request: ToolRequest) -> PackageFacts:
        root = request.checkout()
        if not root.is_dir():
            raise ValidationError(f"package index: not a directory: {root}")
        files = _files(root)
        modules = self._modules(files, root)
        go = sorted(
            [((root / m.location.path).parent, m.name) for m in modules if m.ecosystem == "go"],
            key=lambda pair: len(pair[0].parts),
            reverse=True,
        )
        npm = sorted(
            [((root / m.location.path).parent, m.name) for m in modules if m.ecosystem == "npm"],
            key=lambda pair: len(pair[0].parts),
            reverse=True,
        )
        symbols: defaultdict[str, list[SymbolFact]] = defaultdict(list)
        for symbol in _builtin(root):
            symbols[symbol.location.path].append(symbol)
        parsed = []
        parsers = js_parsers()
        for path in files:
            if path.suffix == ".py":
                parsed.append(_python(path, root))
            elif path.suffix == ".go":
                owner = _nearest(path, go)
                package = None
                if owner:
                    base, name = owner
                    suffix = path.parent.relative_to(base).as_posix()
                    package = name if suffix == "." else f"{name}/{suffix}"
                parsed.append(_go(path, root, package, symbols[path.relative_to(root).as_posix()]))
            elif path.suffix in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
                owner = _nearest(path, npm)
                package = owner[1] if owner else path.parent.relative_to(root).as_posix()
                if parsers is None:
                    parsed.append(
                        PackageFacts(
                            gaps=(
                                CoverageGap(
                                    system="JS/TS",
                                    reason="tree-sitter grammar unavailable",
                                    path=RepoPath(path.relative_to(root).as_posix()),
                                ),
                            )
                        )
                    )
                    continue
                language = "TypeScript" if path.suffix in {".ts", ".tsx"} else "JavaScript"
                grammar = (
                    "tsx"
                    if path.suffix == ".tsx"
                    else "typescript"
                    if language == "TypeScript"
                    else "javascript"
                )
                data = path.read_bytes()
                tree = parsers[grammar].parse(data)
                imports, exports = [], []
                for node in walk(tree.root_node):
                    if node.type in {"import_statement", "export_statement"}:
                        source = node.child_by_field_name("source")
                        if source:
                            imports.append(
                                PackageImport(
                                    package=data[source.start_byte : source.end_byte].decode()[
                                        1:-1
                                    ],
                                    language=language,
                                    location=_span(path, root, node.start_point[0] + 1),
                                )
                            )
                    if node.type == "call_expression":
                        function = node.child_by_field_name("function")
                        arguments = node.child_by_field_name("arguments")
                        target = data[function.start_byte : function.end_byte] if function else b""
                        if target in {b"require", b"import"} and arguments:
                            first = next(iter(arguments.named_children), None)
                            if first and first.type == "string":
                                imports.append(
                                    PackageImport(
                                        package=data[first.start_byte : first.end_byte].decode()[
                                            1:-1
                                        ],
                                        language=language,
                                        location=_span(path, root, node.start_point[0] + 1),
                                    )
                                )
                    if node.type != "export_statement":
                        continue
                    declaration = node.child_by_field_name("declaration")
                    names = []
                    if declaration:
                        direct = declaration.child_by_field_name("name")
                        if direct:
                            names.append(data[direct.start_byte : direct.end_byte].decode())
                        for child in declaration.named_children:
                            name_node = child.child_by_field_name("name")
                            if child.type == "variable_declarator" and name_node:
                                names.append(
                                    data[name_node.start_byte : name_node.end_byte].decode()
                                )
                    for child in walk(node):
                        if child.type == "export_specifier":
                            name_node = child.child_by_field_name(
                                "alias"
                            ) or child.child_by_field_name("name")
                            if name_node:
                                names.append(
                                    data[name_node.start_byte : name_node.end_byte].decode()
                                )
                    if any(child.type == "default" for child in node.children):
                        names.append("default")
                    exports.extend(
                        PackageExport(
                            package=package,
                            name=name,
                            kind=declaration.type if declaration else "reexport",
                            language=language,
                            location=_span(path, root, node.start_point[0] + 1),
                        )
                        for name in dict.fromkeys(names)
                    )
                parsed.append(
                    PackageFacts(
                        imports=tuple(imports),
                        exports=tuple(exports),
                        gaps=(
                            CoverageGap(
                                system=language,
                                reason="source contains parse errors",
                                path=RepoPath(path.relative_to(root).as_posix()),
                            ),
                        )
                        if tree.root_node.has_error
                        else (),
                    )
                )
        return PackageFacts(
            modules=tuple(modules),
            imports=tuple(i for p in parsed for i in p.imports),
            exports=tuple(e for p in parsed for e in p.exports),
            gaps=tuple(g for p in parsed for g in p.gaps),
        )

    def _modules(self, files: list[Path], root: Path) -> list[PackageModule]:
        modules = []
        for path in files:
            name, ecosystem = None, None
            try:
                if path.name == "go.mod":
                    match = re.search(r"^\s*module\s+(\S+)", path.read_text(), re.MULTILINE)
                    if match:
                        name, ecosystem = match.group(1).strip('"'), "go"
                elif path.name == "package.json":
                    name, ecosystem = json.loads(path.read_bytes()).get("name"), "npm"
                elif path.name == "pyproject.toml":
                    project = tomllib.loads(path.read_text()).get("project", {})
                    name, ecosystem = project.get("name"), "pypi"
            except (ValueError, OSError) as exc:
                raise ValidationError(f"package manifest {path.relative_to(root)}: {exc}") from exc
            if isinstance(name, str) and name and ecosystem:
                modules.append(
                    PackageModule(ecosystem=ecosystem, name=name, location=_span(path, root))
                )
        return modules

    def interfaces(self, request: ToolRequest) -> tuple[InterfaceFact, ...]:
        root = request.checkout()
        if not root.is_dir():
            raise ValidationError(f"interface index: not a directory: {root}")
        scanner = Scanner(root, self._load_yaml)
        scanner.run()
        if scanner.unparseable_files:
            raise ValidationError(
                f"interface manifests could not be parsed: {', '.join(scanner.unparseable_files)}"
            )
        signals, facts = scanner.signals, []
        for key, role in (
            ("crds_defined", InterfaceRole.OWNER),
            ("csv_owned_crds", InterfaceRole.OWNER),
            ("csv_required_crds", InterfaceRole.CONSUMER),
        ):
            for row in signals[key]:
                group = row.get("group") or str(row.get("name") or "").partition(".")[2]
                if group:
                    facts.append(
                        InterfaceFact(
                            api_group=group,
                            role=role,
                            location=CodeSpan(path=RepoPath(row["file"])),
                            kind=row.get("kind"),
                            name=row.get("name"),
                        )
                    )
        for row in signals["api_group_literals"]:
            facts.append(
                InterfaceFact(
                    api_group=row["value"],
                    role=InterfaceRole.CONSUMER,
                    location=CodeSpan(path=RepoPath(row["file"]), line=row["line"]),
                    kind="api-group-literal",
                )
            )
        for row in signals["rbac_grants"]:
            for group in row["api_groups"]:
                facts.append(
                    InterfaceFact(
                        api_group=group,
                        role=InterfaceRole.RBAC,
                        location=CodeSpan(path=RepoPath(row["file"])),
                        kind=row["role_kind"],
                        name=row["role_name"],
                        resources=tuple(row["resources"]),
                        verbs=tuple(row["verbs"]),
                    )
                )
        for row in signals["webhooks"]:
            for rule in row["rules"]:
                for group in rule["groups"] or []:
                    facts.append(
                        InterfaceFact(
                            api_group=group,
                            role=InterfaceRole.WEBHOOK,
                            location=CodeSpan(path=RepoPath(row["file"])),
                            kind=(
                                "MutatingWebhookConfiguration"
                                if row["mutating"]
                                else "ValidatingWebhookConfiguration"
                            ),
                            name=row.get("name"),
                            resources=tuple(rule["resources"] or []),
                            verbs=tuple(rule["operations"] or []),
                        )
                    )
        return tuple(facts)
