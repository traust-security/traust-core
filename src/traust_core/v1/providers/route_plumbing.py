"""The shared plumbing of the route families: the row model every family emits, the
guard-name regexes, and the one-pass Python index (imports, functions, classes, calls).
Lifted out of route_guards so each per-family reader (django, express, java, ruby, rust)
builds on it directly instead of reaching into route_guards' privates — route_guards
itself is the matrix entry point that dispatches to the families, not their base."""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TypeVar

from traust_core.v1.models.code_facts import (
    GuardFamily,
    OwnershipEvidence,
    RouteFamily,
    RouteGuardRow,
    RouteHandler,
    RouteOwnership,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    JUDGED,
    LINK_RX,
    HandlerFacts,
    classify,
)
from traust_core.v1.providers.tree import TreeFile

GUARD_RX = re.compile(
    r"(?i)(auth[nz]?|authenticate|authoriz|login|rbac|permission|"
    r"require|protect|verify|token|jwt|oidc|oauth|session|csrf|"
    r"admin[_A-Z]|acl|scope|role|guard|secure)"
)


# Guard-shaped names that disable guarding: a row carrying one is judged whatever else matched.
UNGUARD_RX = re.compile(
    r"(?i)(allowany|allow_any|anonymous|skipauth|skip_auth|noauth|"
    r"no_auth|unauthenticated|public|insecureskip)"
)


# Words for middleware that loads state or sets headers (sessions, cookies, the identity
# store): they don't make a name a guard, only the words left once they're removed can.
NON_ENFORCING_RX = re.compile(
    r"(?i)(session|cookie|cors|trace|compression|timeout|request_?id|propagate|"
    r"identitymiddleware|logger|normalizepath|defaultheaders)"
)


_TOKEN = re.compile(r"[A-Za-z_][\w.]*")


_FLASK_IMPORT = re.compile(
    r"^\s*(?:from\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest|apiflask)\b"
    r"|import\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest|apiflask)\b)",
    re.M,
)


_CONST = re.compile(
    r"^(?P<name>[A-Z_][A-Z0-9_]*)\s*(?::\s*str\s*)?=\s*[\"'](?P<val>[^\"'\n]*)[\"']\s*$", re.M
)


@dataclass
class _Row:
    family: RouteFamily
    method: str
    pattern: str
    handler: str
    handler_path: str
    handler_line: int
    path: str
    line: int
    guards: list[str]
    scope_guards: list[str]
    unguards: list[str]
    judgement_required: bool = False
    asymmetry: bool = False
    family_gaps: list[GuardFamily] = field(default_factory=list)
    receiver: str | None = None
    view_class: str | None = None
    dynamic: bool = False
    test_path: bool = False
    # Flask's OPTIONS row, which its auth decorators pass by design: no asymmetry
    options_exempt: bool = False
    ownership: RouteOwnership | None = None
    ownership_evidence: OwnershipEvidence | None = None

    def __post_init__(self) -> None:
        self.judge()

    def judge(self) -> None:
        self.judgement_required = not self.guarded or bool(self.unguards)

    @property
    def guarded(self) -> bool:
        return bool(self.guards or self.scope_guards)

    @property
    def label(self) -> str:
        return f"{self.method} {self.pattern}"

    def own(
        self,
        facts: HandlerFacts,
        fields: Mapping[str, Sequence[str]],
        *,
        guards: Sequence[str] | None = None,
        links: re.Pattern[str] = LINK_RX,
    ) -> None:
        """`guards`: the guards that actually authenticate the route, when its enumerator knows
        better than the row (a deploy-time choice of security config)."""
        if guards is None:
            # an unguard marker (a disabled or fail-open guard) leaves the route unauthenticated
            guards = [] if self.unguards else [*self.guards, *self.scope_guards]
        self.ownership, self.ownership_evidence = classify(
            self.method, self.pattern, guards, facts, fields, links=links
        )
        self.judgement_required = self.judgement_required or self.ownership in JUDGED

    def mark(self, family: GuardFamily | None = None) -> None:
        self.judgement_required = self.asymmetry = True
        if family is not None and family not in self.family_gaps:
            self.family_gaps.append(family)

    def model(self) -> RouteGuardRow:
        return RouteGuardRow(
            family=self.family,
            method=self.method,
            pattern=self.pattern,
            handler=RouteHandler(
                expr=self.handler[:200], path=RepoPath(self.handler_path), line=self.handler_line
            ),
            registration=CodeSpan(path=RepoPath(self.path), line=self.line),
            guards=tuple(self.guards),
            scope_guards=tuple(self.scope_guards),
            unguard_markers=tuple(self.unguards),
            judgement_required=self.judgement_required,
            asymmetry=self.asymmetry,
            guard_family_gaps=tuple(self.family_gaps),
            receiver=self.receiver,
            view_class=self.view_class,
            pattern_dynamic=self.dynamic,
            test_path=self.test_path,
            ownership=self.ownership,
            ownership_evidence=self.ownership_evidence,
        )


def _unique(names: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(names))


def _guards_in(expr: str) -> list[str]:
    return _unique(
        t for t in _TOKEN.findall(expr) if GUARD_RX.search(t) and not UNGUARD_RX.search(t)
    )


def _unguards_in(expr: str) -> list[str]:
    return sorted({t for t in _TOKEN.findall(expr) if UNGUARD_RX.search(t)})


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _row(
    family: RouteFamily,
    method: str,
    pattern: str,
    handler: str,
    path: str,
    line: int,
    guards: list[str],
    scope_guards: list[str],
    unguards: list[str],
) -> _Row:
    return _Row(
        family, method, pattern, handler, path, line, path, line, guards, scope_guards, unguards
    )


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _last(dotted: str) -> str:
    return dotted.split(".")[-1]


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _str_list(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [s for s in (_const_str(e) for e in node.elts) if s is not None]
    return []


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _own_nodes(fn: ast.AST):
    """Walk fn's body without descending into nested function/class definitions."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


@dataclass(frozen=True)
class _Source:
    file: TreeFile
    tree: ast.Module

    @property
    def imports_flask(self) -> bool:
        return bool(_FLASK_IMPORT.search(self.file.text))


@dataclass(frozen=True)
class _Function:
    path: str
    line: int
    decos: list[str]
    node: ast.AST | None = None
    owner: str = ""  # the function it is nested in, "" at module level


_T = TypeVar("_T")


def _module_of(rel: str) -> str:
    mod = rel.removesuffix(".py").removesuffix("/__init__")
    return mod.replace("/", ".")


def _resolve_import(rel: str, module: str | None, level: int) -> str:
    if not level:
        return module or ""
    pkg = _module_of(rel).split(".")
    if not rel.endswith("__init__.py"):
        pkg = pkg[:-1]
    pkg = pkg[: len(pkg) - (level - 1)] if level > 1 else pkg
    return ".".join([*pkg, module] if module else pkg)


def _same_module(rel: str, module: str) -> bool:
    """`module` names file `rel` (suffix match, so a src/ layout doesn't defeat it)."""
    mod = _module_of(rel)
    return bool(module) and (mod == module or mod.endswith("." + module))


def _c3(lines: list[list[_T]], key: Callable[[_T], object]) -> list[_T] | None:
    """C3's merge of the bases' linearizations and the bases list; None for an order Python
    would refuse too."""
    out: list[_T] = []
    while any(lines):
        head = next(
            (
                line[0]
                for line in lines
                if line and not any(key(line[0]) in {key(x) for x in other[1:]} for other in lines)
            ),
            None,
        )
        if head is None:
            return None
        out.append(head)
        lines = [[x for x in line if key(x) != key(head)] for line in lines]
    return out


def _string_constants(files: list[TreeFile]) -> dict[str, str]:
    """Module-level UPPER_CASE string constants, so `rule=SOME_PATH` resolves to its path; a
    name several modules give different values is left out (`file_constants` reads it)."""
    values: dict[str, set[str]] = {}
    for consts in file_constants(files).values():
        for name, value in consts.items():
            values.setdefault(name, set()).add(value)
    return {name: next(iter(v)) for name, v in values.items() if len(v) == 1}


def file_constants(files: list[TreeFile]) -> dict[str, dict[str, str]]:
    """Each module's own UPPER_CASE string constants."""
    return {f.rel: {m["name"]: m["val"] for m in _CONST.finditer(f.text)} for f in files}


def constants_for(
    rel: str,
    own: dict[str, dict[str, str]],
    imported: dict[str, str],
    file: Callable[[str], str | None],
    shared: dict[str, str],
) -> dict[str, str]:
    """The constants a module sees: its own, those it imports by name, then the unambiguous."""
    out = dict(shared)
    for name, origin in imported.items():
        module, _, local = origin.rpartition(".")
        where = file(module) if module else None
        if where is not None and local in own.get(where, {}):
            out[name] = own[where][local]
    out.update(own.get(rel, {}))
    return out


def _mark(row: _Row, receiver: str | None, dynamic: bool, reg_path: str) -> _Row:
    row.receiver, row.dynamic = receiver, dynamic
    row.test_path = any(p in _TEST_DIR_PARTS for p in reg_path.split("/")[:-1])
    return row


def _targets(node: ast.Assign | ast.AugAssign | ast.AnnAssign) -> list[ast.AST]:
    return list(node.targets) if isinstance(node, ast.Assign) else [node.target]


_Key = tuple[str, str]


def _parsed(files: list[TreeFile]) -> tuple[list[_Source], list[TreeFile]]:
    """The files this interpreter parses, and those it can't (newer syntax, broken files)."""
    sources, failed = [], []
    for f in files:
        if not f.text:
            continue
        try:
            sources.append(_Source(f, ast.parse(f.text, filename=f.rel)))
        except (SyntaxError, ValueError):
            failed.append(f)
    return sources, failed


def _resolve(functions: dict[str, list[_Function]], name: str, rel: str) -> _Function | None:
    found = functions.get(_last(name), [])
    return next((c for c in found if c.path == rel), found[0] if found else None)


@dataclass
class _Modules:
    """Which file a module name is, and what each file imports under which name."""

    by_module: dict[str, str] = field(default_factory=dict)
    imported: dict[str, dict[str, str]] = field(default_factory=dict)

    suffixes: dict[str, str] = field(default_factory=dict)
    candidates: dict[str, list[str]] = field(default_factory=dict)
    _packages: set[str] | None = None

    def __post_init__(self) -> None:
        for mod, rel in sorted(self.by_module.items()):
            parts = mod.split(".")
            for i in range(len(parts)):
                self.suffixes.setdefault(".".join(parts[i:]), rel)
                self.candidates.setdefault(".".join(parts[i:]), []).append(rel)

    def near(self, module: str, rel: str) -> str | None:
        """The file `module` names from `rel`: of the files it may be (`api.views` in two
        projects), the one sharing the most of `rel`'s path; None when two do equally."""
        if module in self.by_module:
            return self.by_module[module]
        found = self.candidates.get(module, [])
        shared = [len(PurePosixPath(os.path.commonpath([f, rel])).parts) for f in found]
        best = [f for f, n in zip(found, shared, strict=True) if n == max(shared, default=0)]
        return best[0] if len(best) == 1 else None

    def add_import(self, rel: str, node: ast.Import | ast.ImportFrom) -> None:
        names = self.imported.setdefault(rel, {})
        if isinstance(node, ast.ImportFrom):
            base = _resolve_import(rel, node.module, node.level)
            for alias in node.names:
                names[alias.asname or alias.name] = f"{base}.{alias.name}"
            return
        for alias in node.names:
            top = alias.name.split(".")[0]
            names[alias.asname or top] = alias.name if alias.asname else top

    def file(self, module: str) -> str | None:
        return self.by_module.get(module) or self.suffixes.get(module)

    def key(self, expr: str, rel: str, bound: set[_Key]) -> _Key | None:
        """The (file, name) binding `expr` refers to from `rel`: local, imported, or module.attr."""
        parts = expr.split(".")
        if parts[0] == "self" and len(parts) > 1:
            parts = parts[1:]
        if len(parts) == 1:
            if (rel, parts[0]) in bound:
                return rel, parts[0]
            target = self.imported.get(rel, {}).get(parts[0], "")
            mod, _, name = target.rpartition(".")
            where = self.file(mod) if mod else None
            return (where, name) if where and (where, name) in bound else None
        if (rel, parts[-1]) in bound and parts[0] not in self.imported.get(rel, {}):
            return rel, parts[-1]
        target = self.imported.get(rel, {}).get(parts[0])
        if target is None:
            return None
        where = self.file(".".join([target, *parts[1:-1]]))
        return (where, parts[-1]) if where and (where, parts[-1]) in bound else None

    def function(
        self, expr: str, rel: str, functions: dict[str, list[_Function]]
    ) -> _Function | None:
        """The function `expr` calls from `rel`, through an aliased or module import."""
        parts = expr.split(".")
        target = self.imported.get(rel, {}).get(parts[0])
        if target:
            mod, _, name = ".".join([target, *parts[1:]]).rpartition(".")
            where = self.file(mod)
            found = [f for f in functions.get(name, []) if f.path == where]
            if found:
                return found[0]
        return _resolve(functions, expr, rel)

    def origin(self, expr: str, rel: str) -> str:
        return self.imported.get(rel, {}).get(expr.split(".")[0], expr)

    def full(self, expr: str, rel: str) -> str:
        """The full name `expr` is imported as from `rel` (`rest_framework.views.APIView`), "" for
        a name `rel` doesn't import."""
        head, *rest = expr.split(".")
        target = self.imported.get(rel, {}).get(head, "")
        return ".".join([target, *rest]) if target else ""

    def local(self, full: str) -> bool:
        """A full name starts in a checkout module or package (`from .auth import ..` with no
        `auth.py` in the tree is still the checkout's)."""
        if self._packages is None:
            self._packages = {
                ".".join(parts[i:j])
                for parts in (m.split(".") for m in self.by_module)
                for i in range(len(parts))
                for j in range(i + 1, len(parts) + 1)
            }
        parts = full.split(".")
        return any(".".join(parts[:i]) in self._packages for i in range(1, len(parts) + 1))


_Def = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class _PyIndex:
    """One pass over the parsed tree, shared by the python families: imports, functions, classes
    and the calls, definitions and assignments of each file, each with its enclosing function."""

    sources: list[_Source]
    modules: _Modules
    functions: dict[str, list[_Function]] = field(default_factory=dict)
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
    calls: dict[str, list[tuple[ast.Call, ast.AST | None]]] = field(default_factory=dict)
    defs: dict[str, list[tuple[_Def, ast.AST | None]]] = field(default_factory=dict)
    class_defs: dict[str, list[ast.ClassDef]] = field(default_factory=dict)
    assigns: dict[str, list[ast.Assign | ast.AnnAssign]] = field(default_factory=dict)
    aliases: dict[_Key, ast.Subscript] = field(default_factory=dict)
    paths: dict[int, str] = field(default_factory=dict)
    _callees: dict[tuple[str, str], _Function | None] = field(default_factory=dict)
    unparsed: set[str] = field(default_factory=set)  # the modules this Python can't parse

    @classmethod
    def of(cls, sources: list[_Source], unparsed: Iterable[TreeFile] = ()) -> _PyIndex:
        index = cls(sources, _Modules({_module_of(s.file.rel): s.file.rel for s in sources}))
        index.unparsed = {_module_of(f.rel) for f in unparsed}
        for src in sources:
            rel = src.file.rel
            calls, defs = index.calls.setdefault(rel, []), index.defs.setdefault(rel, [])
            class_defs, assigns = (
                index.class_defs.setdefault(rel, []),
                index.assigns.setdefault(rel, []),
            )
            for node, enclosing in _enclosed(src.tree):
                if isinstance(node, ast.Call):
                    calls.append((node, enclosing))
                elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    defs.append((node, enclosing))
                    index.paths[id(node)] = rel
                    index.functions.setdefault(node.name, []).append(
                        _Function(rel, node.lineno, [_dotted(d) for d in node.decorator_list], node)
                    )
                elif isinstance(node, ast.ClassDef):
                    class_defs.append(node)
                    index.paths[id(node)] = rel
                    index.classes.setdefault(node.name, node)
                elif isinstance(node, ast.Assign | ast.AnnAssign):
                    assigns.append(node)
                    if enclosing is None and (alias := _annotated_alias(node)):
                        index.aliases[(rel, alias[0])] = alias[1]
                elif isinstance(node, ast.Import | ast.ImportFrom):
                    index.modules.add_import(rel, node)
        return index

    def locate(self, row: _Row, node: ast.AST) -> None:
        """Point a row's handler at the definition, wherever the route was registered."""
        row.handler_path = self.paths.get(id(node), row.handler_path)
        row.handler_line = getattr(node, "lineno", row.handler_line)

    def alias(
        self, expr: str, rel: str, seen: frozenset[str] = frozenset()
    ) -> tuple[ast.Subscript, str] | None:
        """The `Annotated[...]` a type-alias name stands for, and the file defining it, through
        modules (and package initializers) that re-export it."""
        if key := self.modules.key(expr, rel, set(self.aliases)):
            return self.aliases[key], key[0]
        parts = expr.split(".")
        target = self.modules.imported.get(rel, {}).get(parts[0])
        if target is None:
            return None
        mod, _, name = ".".join([target, *parts[1:]]).rpartition(".")
        where = self.modules.file(mod) if mod else None
        if where is None or where in seen or where == rel:
            return None
        return self.alias(name, where, seen | {rel})

    def callee(self, expr: str, rel: str) -> _Function | None:
        if (rel, expr) not in self._callees:
            self._callees[(rel, expr)] = self.modules.function(expr, rel, self.functions)
        return self._callees[(rel, expr)]


_TEST_DIR_PARTS = {"tests", "test", "testing", "fixtures", "examples", "example"}


def _enclosed(tree: ast.AST) -> Iterator[tuple[ast.AST, ast.AST | None]]:
    """Every node with the function it sits in (None at module level)."""
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:
        node, enclosing = stack.pop()
        for child in ast.iter_child_nodes(node):
            yield child, enclosing
            inner = (
                child if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else enclosing
            )
            stack.append((child, inner))


def _annotated_alias(node: ast.Assign | ast.AnnAssign) -> tuple[str, ast.Subscript] | None:
    target = node.targets[0] if isinstance(node, ast.Assign) else node.target
    value = node.value
    if (
        isinstance(target, ast.Name)
        and isinstance(value, ast.Subscript)
        and _last(_dotted(value.value)) == "Annotated"
    ):
        return target.id, value
    return None


def _module_statements(body: list[ast.stmt], conditional: bool) -> Iterator[tuple[ast.stmt, bool]]:
    """A module's statements, through the `if`/`try`/`with`/`for` blocks around them."""
    for n in body:
        if isinstance(n, ast.If | ast.Try | ast.For | ast.While):
            for block in ("body", "orelse", "finalbody"):
                yield from _module_statements(getattr(n, block, []), True)
            for h in getattr(n, "handlers", []):
                yield from _module_statements(h.body, True)
        elif isinstance(n, ast.With):
            yield from _module_statements(n.body, conditional)
        else:
            yield n, conditional
