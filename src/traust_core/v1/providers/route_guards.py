"""Route x guard matrix: a checkout's HTTP route registrations (go-http, django-drf, flask,
express) and the guards applied to each, matched by name and over-inclusive; target code is
parsed, never imported. Other frameworks found are coverage gaps."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    CoverageGap,
    GuardFamily,
    RouteAsymmetry,
    RouteFamily,
    RouteGuardFact,
    RouteGuardRow,
    RouteHandler,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

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
_TEST_NAME = re.compile(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)")
_TOKEN = re.compile(r"[A-Za-z_][\w.]*")

GO_VERBS = (
    "Get",
    "Post",
    "Put",
    "Delete",
    "Patch",
    "Head",
    "Options",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
)
_GO_HANDLEFUNC = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>HandleFunc|Handle)\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
_GO_VERB = re.compile(
    r"(?P<recv>[\w.]+)\.(?P<method>" + "|".join(GO_VERBS) + r")\(\s*"
    r'"(?P<pattern>[^"]+)"\s*,\s*(?P<handler>[^)]+?)\s*\)'
)
_GO_USE = re.compile(r"(?P<recv>[\w.]+)\.Use\(\s*(?P<mws>[^)]+?)\s*\)")
_GO_TEST_RECEIVERS = ("t", "b", "suite")

_PY_URL = re.compile(
    r'(?:path|re_path|url)\(\s*r?["\'](?P<pattern>[^"\']*)["\']\s*,\s*'
    r"(?P<view>[\w.]+(?:\.as_view\(\))?)"
)
_PY_PERM = re.compile(r"permission_classes\s*=\s*[\[\(](?P<perms>[^\]\)]*)[\]\)]")
_PY_CLASS = re.compile(r"^class\s+(?P<name>\w+)\s*\((?P<bases>[^)]*)\)\s*:", re.M)
_PY_DECORATED_DEF = re.compile(
    r"(?P<decos>(?:^\s*@[\w.()'\", =\[\]]+\n)+)^\s*def\s+(?P<name>\w+)\s*\(", re.M
)
_DRF_DEFAULTS = re.compile(r"DEFAULT_PERMISSION_CLASSES.*?[\[\(](?P<perms>[^\]\)]*)[\]\)]", re.S)

OTHER_FRAMEWORKS = (
    ("fastapi", re.compile(r"\bfrom fastapi import|\bFastAPI\(")),
    ("spring", re.compile(r"@(RestController|RequestMapping|GetMapping)")),
)
_FLASK_IMPORT = re.compile(
    r"^\s*(?:from\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b"
    r"|import\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b)",
    re.M,
)
_FASTAPI_IMPORT = re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)", re.M)
_FLASK_HINTS = (
    "route",
    "add_url_rule",
    "add_resource",
    "before_request",
    "before_app_request",
    "Blueprint",
    "Flask",
    "Namespace",
    "View",
    "Resource",
)
FLASK_RECEIVER_CTORS = {
    "Flask": "app",
    "Blueprint": "blueprint",
    "Api": "api",
    "Namespace": "namespace",
}
FLASK_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_FLASK_REGISTRATION_ATTRS = {"route", "add_url_rule", "add_resource", *FLASK_VERBS}
_HOOKS = ("before_request", "before_app_request")
_VIEW_BASE = re.compile(r"(MethodView|^View$|\.View$|Resource$|MethodResource$)")
# flask-local additions: `check_*` decorators guard, `*exempt*` decorators unguard.
_FLASK_GUARD_EXTRA = re.compile(r"(?i)(^|\.)check_")
_FLASK_UNGUARD_EXTRA = re.compile(r"(?i)exempt")
GUARD_FAMILIES = (
    (GuardFamily.SCOPE, re.compile(r"(?i)scope")),
    (GuardFamily.ADMIN, re.compile(r"(?i)admin")),
    (GuardFamily.ROLE, re.compile(r"(?i)(role|rbac|acl)")),
    (GuardFamily.PERMISSION, re.compile(r"(?i)permission")),
    (GuardFamily.CSRF, re.compile(r"(?i)csrf")),
    (GuardFamily.TOKEN, re.compile(r"(?i)(jwt|token|oauth|oidc)")),
    (GuardFamily.AUTHN, re.compile(r"(?i)(login|auth|session)")),
)
_CONST = re.compile(
    r"^(?P<name>[A-Z_][A-Z0-9_]*)\s*(?::\s*str\s*)?=\s*[\"'](?P<val>[^\"'\n]*)[\"']\s*$", re.M
)
_TEST_DIR_PARTS = {"tests", "test", "testing", "fixtures", "examples", "example"}


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


def _go(files: list[TreeFile]) -> list[_Row]:
    rows = []
    for f in files:
        if f.path.suffix != ".go":
            continue
        text = f.text
        if (
            ".HandleFunc(" not in text
            and ".Handle(" not in text
            and not any(f".{v}(" in text for v in GO_VERBS)
        ):
            continue
        # r.Use(mw) anywhere in the file scopes to that receiver's registrations (over-approximate)
        scope: dict[str, list[str]] = {}
        unguard_scope: dict[str, list[str]] = {}
        for m in _GO_USE.finditer(text):
            scope.setdefault(m["recv"], []).extend(_guards_in(m["mws"]))
            unguard_scope.setdefault(m["recv"], []).extend(_unguards_in(m["mws"]))
        for rx in (_GO_HANDLEFUNC, _GO_VERB):
            for m in rx.finditer(text):
                recv, handler = m["recv"], m["handler"]
                if recv in _GO_TEST_RECEIVERS:
                    continue
                rows.append(
                    _row(
                        RouteFamily.GO_HTTP,
                        m["method"],
                        m["pattern"],
                        handler,
                        f.rel,
                        _line(text, m.start()),
                        _guards_in(handler),
                        _unique(scope.get(recv, [])),
                        _unguards_in(handler) + unguard_scope.get(recv, []),
                    )
                )
    return rows


@dataclass(frozen=True)
class _ViewGuards:
    guards: list[str]
    unguards: list[str]
    path: str
    line: int
    has_perm_attr: bool


def _view_guard_index(files: list[TreeFile]) -> dict[str, _ViewGuards]:
    index: dict[str, _ViewGuards] = {}
    for f in files:
        text = f.text
        for m in _PY_CLASS.finditer(text):
            rest = text[m.end() :]
            end = re.search(r"^\S", rest, re.M)
            perms = _PY_PERM.search(rest[: end.start()] if end else rest)
            index[m["name"]] = _ViewGuards(
                _guards_in(perms["perms"]) if perms else [],
                _unguards_in(perms["perms"]) if perms else [],
                f.rel,
                _line(text, m.start()),
                bool(perms),
            )
        for m in _PY_DECORATED_DEF.finditer(text):
            guards, unguards = _guards_in(m["decos"]), _unguards_in(m["decos"])
            if guards or unguards:
                index[m["name"]] = _ViewGuards(
                    guards, unguards, f.rel, _line(text, m.start()), True
                )
    return index


def _drf_default_guards(files: list[TreeFile]) -> list[str]:
    for f in files:
        if "settings" in f.name.lower() or "settings" in str(PurePosixPath(f.rel).parent).lower():
            m = _DRF_DEFAULTS.search(f.text)
            if m:
                return _guards_in(m["perms"])
    return []


def _django(files: list[TreeFile]) -> list[_Row]:
    url_files = [f for f in files if "url" in f.name.lower()]
    if not url_files:
        return []
    views = _view_guard_index(files)
    defaults = _drf_default_guards(files)
    rows = []
    for f in url_files:
        for m in _PY_URL.finditer(f.text):
            view = m["view"]
            info = views.get(view.split(".")[0].replace(".as_view()", "")) or views.get(
                view.replace(".as_view()", "").split(".")[-1]
            )
            rows.append(
                _row(
                    RouteFamily.DJANGO_DRF,
                    "any",
                    m["pattern"] or "/",
                    view,
                    info.path if info else f.rel,
                    info.line if info else _line(f.text, m.start()),
                    info.guards if info else [],
                    [] if info and info.has_perm_attr else defaults,
                    info.unguards if info else [],
                )
            )
    return rows


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


def _flask_split(names: Iterable[str]) -> tuple[list[str], list[str]]:
    guards, unguards = [], []
    for n in names:
        if not n or _last(n) in _FLASK_REGISTRATION_ATTRS:
            continue
        if UNGUARD_RX.search(n) or _FLASK_UNGUARD_EXTRA.search(n):
            unguards.append(n)
        elif GUARD_RX.search(n) or _FLASK_GUARD_EXTRA.search(n):
            guards.append(n)
    return _unique(guards), sorted(set(unguards))


def _names_in(node: ast.AST | None) -> list[str]:
    """A decorators-style value: a list of decorators, or a verb -> list dict."""
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [_dotted(e) for e in node.elts]
    if isinstance(node, ast.Dict):
        return [n for v in node.values for n in _names_in(v)]
    return []


def _method_decorators(node: ast.AST) -> tuple[list[str], dict[str, list[str]]]:
    if isinstance(node, ast.Dict):
        per = {}
        for k, v in zip(node.keys, node.values, strict=False):
            if key := _const_str(k):
                per[key.lower()] = _names_in(v)
        return [], per
    return _names_in(node), {}


def _can_reject(fn: ast.AST) -> bool:
    """A before_request hook guards only if it can end the request: raise, abort() or return."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Raise) or (isinstance(n, ast.Return) and n.value is not None):
            return True
        if isinstance(n, ast.Call) and _last(_dotted(n.func)) == "abort":
            return True
    return False


def _mentions_guard(fn: ast.AST, name: str) -> bool:
    if GUARD_RX.search(name) or _FLASK_GUARD_EXTRA.search(name):
        return True
    return any(
        isinstance(n, ast.Name | ast.Attribute) and GUARD_RX.search(_dotted(n))
        for n in ast.walk(fn)
    )


@dataclass(frozen=True)
class _Source:
    file: TreeFile
    tree: ast.Module

    @property
    def imports_flask(self) -> bool:
        return bool(_FLASK_IMPORT.search(self.file.text))


def _flask_sources(files: list[TreeFile]) -> list[_Source]:
    sources = []
    for f in files:
        if not f.text or not any(h in f.text for h in _FLASK_HINTS):
            continue
        try:
            sources.append(_Source(f, ast.parse(f.text, filename=f.rel)))
        except (SyntaxError, ValueError):
            continue
    return sources


@dataclass(frozen=True)
class _Function:
    path: str
    line: int
    decos: list[str]
    node: ast.AST | None = None


@dataclass
class _Class:
    path: str
    line: int
    bases: list[str]
    class_decos: list[str]
    view_like: bool
    decorators: list[str] = field(default_factory=list)
    method_all: list[str] = field(default_factory=list)
    method_per: dict[str, list[str]] = field(default_factory=dict)
    methods: dict[str, _Function] = field(default_factory=dict)


@dataclass(frozen=True)
class _Hook:
    recv: str
    fname: str
    app_hook: bool
    path: str
    node: ast.AST
    app_level: bool = False

    @property
    def label(self) -> str:
        return f"before_request:{self.fname}"


@dataclass
class _FlaskIndex:
    """Flask receivers (only from files importing a flask-family module), functions, view
    classes, guarding before_request hooks, blueprint registrations and from-imports."""

    receivers: dict[str, str] = field(default_factory=dict)
    functions: dict[str, list[_Function]] = field(default_factory=dict)
    classes: dict[str, _Class] = field(default_factory=dict)
    hooks: list[_Hook] = field(default_factory=list)
    registered: dict[str, set[str]] = field(default_factory=dict)
    imported: dict[str, dict[str, str]] = field(default_factory=dict)

    def resolve_fn(self, name: str, rel: str) -> _Function | None:
        found = self.functions.get(_last(name), [])
        return next((c for c in found if c.path == rel), found[0] if found else None)

    def chain(self, name: str, seen: set[str] | None = None) -> list[_Class]:
        """The class and its in-repo bases, nearest first, cycle-safe."""
        seen = seen if seen is not None else set()
        info = self.classes.get(name)
        if info is None or name in seen:
            return []
        seen.add(name)
        return [info, *(c for b in info.bases for c in self.chain(_last(b), seen))]

    def is_view(self, name: str) -> bool:
        return any(c.view_like or c.methods for c in self.chain(name))

    def baseline(self, receiver: str | None, reg_path: str) -> list[str]:
        """Hooks covering a route on `receiver` in `reg_path`: a blueprint hook its blueprint's
        routes; an app hook the same app object's routes (in the hook's file, or the module it
        imports that app from) and every blueprint the hook's file registers. Never every flask
        route in the tree: one repo can hold several apps."""
        out = []
        for h in self.hooks:
            if not h.app_level:
                if receiver and receiver == h.recv:
                    out.append(h.label)
                continue
            same_app = receiver == h.recv and (
                reg_path == h.path
                or _same_module(reg_path, self.imported.get(h.path, {}).get(h.recv, ""))
            )
            if same_app or (receiver and receiver in self.registered.get(h.path, set())):
                out.append(h.label)
        return _unique(out)


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


def _flask_index(sources: list[_Source]) -> _FlaskIndex:
    index = _FlaskIndex()
    pending: list[tuple[str, str, bool, str]] = []
    hooks: list[_Hook] = []
    for src in sources:
        rel, imports_flask = src.file.rel, src.imports_flask
        for node in ast.walk(src.tree):
            if isinstance(node, ast.ImportFrom):
                mod = _resolve_import(rel, node.module, node.level)
                for alias in node.names:
                    index.imported.setdefault(rel, {})[alias.asname or alias.name] = mod
            if imports_flask and isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                ctor = _last(_dotted(node.value.func))
                kind = FLASK_RECEIVER_CTORS.get(ctor) or (
                    "namespace" if ctor == "namespace" else None
                )
                for t in node.targets if kind else ():
                    if isinstance(t, ast.Name):
                        index.receivers[t.id] = kind  # type: ignore[assignment]
                    elif isinstance(t, ast.Attribute):
                        index.receivers[t.attr] = kind  # type: ignore[assignment]
            if not isinstance(node, ast.Call):
                continue
            fn = _dotted(node.func)
            last = _last(fn)
            if last == "register_blueprint" and node.args:
                index.registered.setdefault(rel, set()).add(_last(_dotted(node.args[0])))
            if (
                last in _HOOKS
                and node.args
                and "." in fn
                and (hook := _last(_dotted(node.args[0])))
            ):
                pending.append((_last(fn.rsplit(".", 1)[0]), hook, last == _HOOKS[1], rel))
        for node in src.tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                decos = [_dotted(d) for d in node.decorator_list]
                index.functions.setdefault(node.name, []).append(
                    _Function(rel, node.lineno, decos, node)
                )
                for d in decos:
                    if _last(d) in _HOOKS and "." in d:
                        recv = _last(d.rsplit(".", 1)[0])
                        hooks.append(_Hook(recv, node.name, _last(d) == _HOOKS[1], rel, node))
            elif isinstance(node, ast.ClassDef):
                index.classes[node.name] = _class_info(node, rel)
    for recv, fname, app_hook, rel in pending:
        fn_info = index.resolve_fn(fname, rel)
        if fn_info is not None and fn_info.node is not None:
            hooks.append(_Hook(recv, fname, app_hook, rel, fn_info.node))
    index.hooks = [
        _Hook(
            h.recv,
            h.fname,
            h.app_hook,
            h.path,
            h.node,
            h.app_hook or index.receivers.get(h.recv) == "app",
        )
        for h in hooks
        if _can_reject(h.node) and _mentions_guard(h.node, h.fname)
    ]
    return index


def _class_info(node: ast.ClassDef, rel: str) -> _Class:
    bases = [_dotted(b) for b in node.bases]
    info = _Class(
        rel,
        node.lineno,
        bases,
        [_dotted(d) for d in node.decorator_list],
        any(_VIEW_BASE.search(b) for b in bases),
    )
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name) and t.id == "decorators":
                    info.decorators = _names_in(stmt.value)
                elif isinstance(t, ast.Name) and t.id == "method_decorators":
                    info.method_all, info.method_per = _method_decorators(stmt.value)
        elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and (
            stmt.name in FLASK_VERBS or stmt.name == "dispatch_request"
        ):
            info.methods[stmt.name] = _Function(
                rel, stmt.lineno, [_dotted(d) for d in stmt.decorator_list]
            )
    return info


def _string_constants(files: list[TreeFile]) -> dict[str, str]:
    """Module-level UPPER_CASE string constants, so `rule=SOME_PATH` resolves to its path."""
    consts: dict[str, str] = {}
    for f in files:
        for m in _CONST.finditer(f.text):
            consts.setdefault(m["name"], m["val"])
    return consts


def _pattern(node: ast.AST | None, consts: dict[str, str]) -> tuple[str | None, bool]:
    """(pattern, dynamic): a computed path is kept as its source text, never dropped."""
    if node is None:
        return None, False
    if (s := _const_str(node)) is not None:
        return s, False
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id], False
    try:
        return ast.unparse(node)[:160], True
    except (AttributeError, ValueError, RecursionError):
        return "<dynamic>", True


def _mark(row: _Row, receiver: str | None, dynamic: bool, reg_path: str) -> _Row:
    row.receiver, row.dynamic = receiver, dynamic
    row.test_path = any(p in _TEST_DIR_PARTS for p in reg_path.split("/")[:-1])
    return row


def _class_rows(
    cls_name: str,
    patterns: list[tuple[str, bool]],
    receiver: str | None,
    reg_path: str,
    reg_line: int,
    index: _FlaskIndex,
) -> list[_Row]:
    chain = index.chain(cls_name)
    if not chain:
        return []
    methods: dict[str, _Function] = {}
    for c in reversed(chain):
        methods.update(c.methods)
    class_level: list[str] = []
    per_verb: dict[str, list[str]] = {}
    for c in chain:
        class_level += c.class_decos + c.decorators + c.method_all
        for verb, names in c.method_per.items():
            per_verb.setdefault(verb, []).extend(names)
    cls_guards, cls_unguards = _flask_split(class_level)
    base_guards = index.baseline(receiver, reg_path)
    verbs = [v for v in methods if v != "dispatch_request"] or (
        ["dispatch_request"] if "dispatch_request" in methods else []
    )
    rows = []
    for verb in verbs:
        guards, unguards = _flask_split(methods[verb].decos)
        pv_guards, pv_unguards = _flask_split(per_verb.get(verb, []))
        owner = next((c for c in chain if verb in c.methods), chain[0])
        for pattern, dynamic in patterns:
            row = _row(
                RouteFamily.FLASK,
                "ANY" if verb == "dispatch_request" else verb.upper(),
                pattern,
                f"{cls_name}.{verb}",
                reg_path,
                reg_line,
                guards,
                _unique(pv_guards + cls_guards + base_guards),
                sorted(set(unguards + pv_unguards + cls_unguards)),
            )
            row.handler_path, row.handler_line = owner.path, methods[verb].line
            row.view_class = cls_name
            rows.append(_mark(row, receiver, dynamic, reg_path))
    return rows


def _function_row(
    name: str,
    fn: _Function | None,
    pattern: str,
    dynamic: bool,
    methods: list[str],
    receiver: str | None,
    reg_path: str,
    reg_line: int,
    index: _FlaskIndex,
) -> _Row:
    guards, unguards = _flask_split(fn.decos if fn else [])
    row = _row(
        RouteFamily.FLASK,
        ",".join(methods) if methods else "GET",
        pattern,
        name,
        reg_path,
        reg_line,
        guards,
        index.baseline(receiver, reg_path),
        unguards,
    )
    if fn:
        row.handler_path, row.handler_line = fn.path, fn.line
    return _mark(row, receiver, dynamic, reg_path)


def _view_target(view: ast.AST) -> tuple[str, list[str]]:
    """(handler, names wrapped around it) for `f`, `guard(f)`, `lambda: f(...)`, `mod.f`."""
    if isinstance(view, ast.Lambda):
        body = view.body
        return (_dotted(body.func) if isinstance(body, ast.Call) else _dotted(body)), []
    if isinstance(view, ast.Call) and view.args:
        inner, wraps = _view_target(view.args[0])
        return inner, [_dotted(view.func), *wraps]
    return _dotted(view), []


class _FlaskFile:
    """One file's flask registrations. A file also importing fastapi spells verb decorators the
    same way, so there only route / add_url_rule / add_resource on known flask receivers count,
    and a name it binds to a non-flask constructor shadows the global one."""

    def __init__(self, src: _Source, index: _FlaskIndex, consts: dict[str, str]) -> None:
        self.src, self.index, self.consts = src, index, consts
        self.rel = src.file.rel
        self.mixed = bool(_FASTAPI_IMPORT.search(src.file.text))
        self.other = {
            t.id
            for n in ast.walk(src.tree)
            if self.mixed and isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
            if _last(_dotted(n.value.func)) not in FLASK_RECEIVER_CTORS
            for t in n.targets
            if isinstance(t, ast.Name)
        }

    def receiver(self, dotted: str) -> str | None:
        if "." not in dotted:
            return None
        recv = _last(dotted.rsplit(".", 1)[0])
        if recv in self.other:
            return None
        if self.mixed:
            return recv if recv in self.index.receivers else None
        return recv if (recv in self.index.receivers or self.src.imports_flask) else None

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for node in ast.walk(self.src.tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                rows += self._decorated(node)
            if isinstance(node, ast.Call):
                rows += self._call(node)
        return rows

    def _decorated(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[_Row]:
        rows: list[_Row] = []
        for d in node.decorator_list:
            if not isinstance(d, ast.Call):
                continue
            dn = _dotted(d.func)
            attr, recv = _last(dn), self.receiver(dn)
            if recv is None or attr not in ("route", *FLASK_VERBS):
                continue
            if attr != "route" and (self.mixed or recv not in self.index.receivers):
                continue
            pattern, dynamic = _pattern(d.args[0] if d.args else _kwarg(d, "rule"), self.consts)
            if pattern is None:
                continue
            if isinstance(node, ast.ClassDef):
                rows += _class_rows(
                    node.name, [(pattern, dynamic)], recv, self.rel, d.lineno, self.index
                )
                continue
            methods = (
                [attr.upper()]
                if attr != "route"
                else [m.upper() for m in _str_list(_kwarg(d, "methods"))]
            )
            fn = _Function(self.rel, node.lineno, [_dotted(x) for x in node.decorator_list])
            rows.append(
                _function_row(
                    node.name, fn, pattern, dynamic, methods, recv, self.rel, d.lineno, self.index
                )
            )
        return rows

    def _call(self, node: ast.Call) -> list[_Row]:
        fn = _dotted(node.func)
        attr = _last(fn)
        recv = self.receiver(fn) if attr in ("add_url_rule", "add_resource") else None
        if recv is None:
            return []
        if attr == "add_resource":
            if not node.args:
                return []
            cls = _last(_dotted(node.args[0]))
            patterns = [
                (p, dynamic)
                for p, dynamic in (_pattern(a, self.consts) for a in node.args[1:])
                if p
            ]
            if cls and patterns and cls in self.index.classes:
                return _class_rows(cls, patterns, recv, self.rel, node.lineno, self.index)
            return []
        pattern, dynamic = _pattern(
            node.args[0] if node.args else _kwarg(node, "rule"), self.consts
        )
        view = _kwarg(node, "view_func")
        if view is None and len(node.args) >= 3:
            view = node.args[2]
        if pattern is None or view is None:
            return []
        if (
            isinstance(view, ast.Call)
            and isinstance(view.func, ast.Attribute)
            and view.func.attr == "as_view"
        ):
            cls = _last(_dotted(view.func.value))
            if self.index.is_view(cls):
                return _class_rows(
                    cls, [(pattern, dynamic)], recv, self.rel, node.lineno, self.index
                )
            return []
        target, wraps = _view_target(view)
        row = _function_row(
            target or "<view>",
            self.index.resolve_fn(target, self.rel) if target else None,
            pattern,
            dynamic,
            [m.upper() for m in _str_list(_kwarg(node, "methods"))],
            recv,
            self.rel,
            node.lineno,
            self.index,
        )
        wrap_guards, wrap_unguards = _flask_split(wraps)
        if wrap_guards or wrap_unguards:
            row.guards = _unique(wrap_guards + row.guards)
            row.unguards = sorted(set(wrap_unguards + row.unguards))
            row.judge()
        return [row]


def _flask(files: list[TreeFile]) -> tuple[list[_Row], bool]:
    """The flask rows, and whether the tree uses flask at all (so no rows is a gap, not clean)."""
    sources = _flask_sources(files)
    if not any(s.imports_flask for s in sources):
        return [], False
    index = _flask_index(sources)
    consts = _string_constants(files)
    return [r for s in sources for r in _FlaskFile(s, index, consts).rows()], True


_METHOD_LABELS = (RouteFamily.FLASK, RouteFamily.EXPRESS)


def _asymmetries(rows: list[_Row]) -> list[RouteAsymmetry]:
    """Per family and registration file, guarded rows next to bare ones (the bare are marked).
    Flask labels carry the method: class-based views share one pattern."""
    groups: dict[tuple[RouteFamily, str], list[_Row]] = {}
    for r in rows:
        groups.setdefault((r.family, r.path), []).append(r)
    found = []
    for (family, path), members in sorted(groups.items()):
        guarded = [r for r in members if r.guarded]
        bare = [r for r in members if not r.guarded]
        if guarded and bare:
            label = (lambda r: r.label) if family in _METHOD_LABELS else (lambda r: r.pattern)
            found.append(
                RouteAsymmetry(
                    family=family,
                    path=RepoPath(path),
                    guarded=tuple(label(r) for r in guarded),
                    unguarded=tuple(label(r) for r in bare),
                )
            )
            for r in bare:
                r.mark()
    return found


def _guard_families(row: _Row) -> set[GuardFamily]:
    return {
        next(fam for fam, rx in GUARD_FAMILIES if rx.search(g))
        for g in row.guards + row.scope_guards
        if any(rx.search(g) for _, rx in GUARD_FAMILIES)
    }


def _family_asymmetries(rows: list[_Row]) -> list[RouteAsymmetry]:
    """Within one flask view class or receiver, a guard family most rows carry, missing from
    guarded rows that lack it ("every neighbour performs this check but this one")."""
    groups: dict[tuple[str, str], list[_Row]] = {}
    for r in rows:
        if r.family is RouteFamily.FLASK:
            groups.setdefault((r.path, r.view_class or r.receiver or ""), []).append(r)
    found = []
    for (path, key), members in sorted(groups.items()):
        if len(members) < 2:
            continue
        fams = [_guard_families(r) for r in members]
        for fam, _ in GUARD_FAMILIES:
            have = [r for r, fs in zip(members, fams, strict=True) if fam in fs]
            lack = [r for r, fs in zip(members, fams, strict=True) if fam not in fs and r.guarded]
            if not have or not lack or len(have) <= len(lack):
                continue
            found.append(
                RouteAsymmetry(
                    family=RouteFamily.FLASK,
                    path=RepoPath(path),
                    group=key,
                    guard_family=fam,
                    guarded=tuple(r.label for r in have),
                    unguarded=tuple(r.label for r in lack),
                )
            )
            for r in lack:
                r.mark(fam)
    return found


def _other_frameworks(files: list[TreeFile]) -> list[CoverageGap]:
    hits: dict[str, str] = {}
    for f in files:
        if f.path.suffix in (".js", ".ts", ".py", ".java", ".kt"):
            for name, rx in OTHER_FRAMEWORKS:
                if name not in hits and rx.search(f.text):
                    hits[name] = f.rel
    return [
        CoverageGap(
            system=name,
            reason=f"{name} routes detected but this enumerator covers only "
            f"{', '.join(RouteFamily)} — this family's route x guard matrix is UNENUMERATED",
            evidence=RepoPath(path),
        )
        for name, path in sorted(hits.items())
    ]


def route_guards(files: list[TreeFile]) -> RouteGuardFact:
    """The matrix over a checkout's (non-test) files, judged and asymmetric rows first."""
    files = [f for f in files if not _TEST_NAME.search(f.name.lower())]
    py = [f for f in files if f.path.suffix == ".py"]
    flask_rows, uses_flask = _flask(py)
    from traust_core.v1.providers.express_routes import express_rows  # it builds on this module

    js_rows, uses_express, parsed = express_rows(files)
    rows = _go(files) + _django(py) + flask_rows + js_rows
    others = [r for r in rows if r.family is not RouteFamily.FLASK]
    flask = [r for r in rows if r.family is RouteFamily.FLASK]
    asymmetries = _asymmetries(others) + _asymmetries(flask) + _family_asymmetries(flask)
    gaps = _other_frameworks(files)
    if uses_express and not js_rows:
        reason = (
            "express imports detected but the JS/TS parser is not installed (install "
            "traust-core[js])"
            if not parsed
            else "express imports detected but no route registration this enumerator recognizes "
            "(app/router verb calls, route() chains, use() mounts)"
        )
        gaps.append(
            CoverageGap(
                system=RouteFamily.EXPRESS,
                reason=f"{reason} — the express route x guard matrix is UNENUMERATED",
                evidence=RepoPath(uses_express),
            )
        )
    if uses_flask and not flask:
        evidence = next((f.rel for f in py if _FLASK_IMPORT.search(f.text)), None)
        gaps.append(
            CoverageGap(
                system="flask",
                reason="flask imports detected but no route registration this enumerator "
                "recognizes (route/verb decorators, add_url_rule, add_resource) — the flask "
                "route x guard matrix is UNENUMERATED",
                evidence=RepoPath(evidence) if evidence else None,
            )
        )
    rows.sort(key=lambda r: (not r.judgement_required, not r.asymmetry, r.path, r.line))
    return RouteGuardFact(
        routes=tuple(r.model() for r in rows),
        asymmetries=tuple(asymmetries),
        coverage_gaps=tuple(gaps),
    )


class RouteGuardMatrix:
    kind = CodeFactKind.ROUTE_GUARD
    name = "route-guards"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = route_guards(tree_files(request.checkout()))
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
