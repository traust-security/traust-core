"""Route x guard matrix: a checkout's HTTP route registrations (go-http, django-drf, flask,
fastapi, aiohttp, express) and the guards applied to each, matched by name and over-inclusive;
target code is parsed, never imported. Other frameworks found are coverage gaps."""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Callable, Iterable, Iterator
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
from traust_core.v1.providers.syntax import grammar_missing
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
# Words for middleware that loads state or sets headers (sessions, cookies, the identity
# store): they don't make a name a guard, only the words left once they're removed can.
NON_ENFORCING_RX = re.compile(
    r"(?i)(session|cookie|cors|trace|compression|timeout|request_?id|propagate|"
    r"identitymiddleware|logger|normalizepath|defaultheaders)"
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

# Detected but not enumerated: Java routes are (java_routes), Kotlin's and these are not.
OTHER_FRAMEWORKS = (
    ("spring (kotlin)", (".kt",), re.compile(r"@(RestController|RequestMapping|GetMapping)")),
    ("micronaut", (".java", ".kt"), re.compile(r"\bio\.micronaut\.http\.annotation\b")),
    (
        "spring functional routes",
        (".java", ".kt"),
        re.compile(r"\bRouterFunctions\.(?:route|nest)\b|\bcoRouter\s*\{"),
    ),
)
_FLASK_IMPORT = re.compile(
    r"^\s*(?:from\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b"
    r"|import\s+(?:flask|flask_restful|flask_restx|flask_restplus|flask_smorest)\b)",
    re.M,
)
# A database or ORM session dependency (`get_db_session`, `SessionLocal`), not a session check
_DB_SESSION_RX = re.compile(
    r"(?i)^(get_|new_|open_)?(async_?|db_?|database_?|sql_?|orm_?)*session(_?(maker|local|factory|scope|dep))?$"
)
_FASTAPI_IMPORT = re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)", re.M)
_PY_WEB_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:fastapi|starlette|django|rest_framework|aiohttp)\b", re.M
)
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


def _raises(fn: ast.AST) -> bool:
    return any(isinstance(n, ast.Raise) for n in ast.walk(fn))


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


# The server package only: a client-only `import aiohttp` registers no routes.
_AIOHTTP_IMPORT = re.compile(
    r"^\s*(?:from\s+aiohttp\s+import\s+[^\n]*\bweb\b|from\s+aiohttp\.web\b"
    r"|import\s+aiohttp\.web\b)|\baiohttp\.web\.",
    re.M,
)
FASTAPI_CTORS = ("FastAPI", "APIRouter")
FASTAPI_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
_FASTAPI_DECORATORS = {*FASTAPI_VERBS, "api_route", "websocket"}
_DEPENDS = ("Depends", "Security")
FAIL_OPEN = "fail-open"
_FASTAPI_SECURITY = re.compile(
    r"^(HTTPBearer|HTTPBasic|HTTPDigest|OAuth2\w*|APIKey(Header|Query|Cookie)|OpenIdConnect)$"
)
# Framework middleware that only sets up state (a session, CORS, the authenticated user): it never
# refuses a request. An in-repo class of the same name is judged by its name like any other.
_NON_ENFORCING_MIDDLEWARE = re.compile(
    r"(?i)^(session\w*|cors\w*|gzip\w*|trustedhost\w*|httpsredirect\w*|"
    r"authenticationmiddleware|setup)$"
)
_FRAMEWORK_PACKAGES = ("starlette", "fastapi", "aiohttp", "aiohttp_session", "aiohttp_cors")
AIOHTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_AIOHTTP_ADD = {f"add_{v}": v.upper() for v in AIOHTTP_VERBS}
_DEPTH = 4
_MAX_MOUNTS = 8

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


def _param_names(fn: ast.AST | None) -> list[str]:
    args = getattr(fn, "args", None)
    return [a.arg for a in (*args.posonlyargs, *args.args)] if args else []


def _unquoted(ann: ast.AST | None) -> ast.AST | None:
    """A string annotation (`user: "CurrentUser"`) as the expression it names."""
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        try:
            return ast.parse(ann.value, mode="eval").body
        except SyntaxError:
            return ann
    return ann


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


@dataclass
class _Modules:
    """Which file a module name is, and what each file imports under which name."""

    by_module: dict[str, str] = field(default_factory=dict)
    imported: dict[str, dict[str, str]] = field(default_factory=dict)

    suffixes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for mod, rel in sorted(self.by_module.items()):
            parts = mod.split(".")
            for i in range(len(parts)):
                self.suffixes.setdefault(".".join(parts[i:]), rel)

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

    @classmethod
    def of(cls, sources: list[_Source]) -> _PyIndex:
        index = cls(sources, _Modules({_module_of(s.file.rel): s.file.rel for s in sources}))
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


class _Bindings:
    """The receivers a helper's parameters are called with (`attach_router(app)`), through
    aliased imports and helpers that pass their parameter on to other helpers."""

    def __init__(self, index: _PyIndex, bound: Callable[[str, str], _Key | None]) -> None:
        self.bound = bound
        self.params: dict[tuple[str, int, int], set[_Key]] = {}
        edges = []
        for rel, calls in index.calls.items():
            for call, enclosing in calls:
                if not any(isinstance(a, ast.Name) for a in call.args):
                    continue
                callee = index.callee(_dotted(call.func), rel)
                if callee is None:
                    continue
                offset = 1 if _param_names(callee.node)[:1] in (["self"], ["cls"]) else 0
                own = _param_names(enclosing)
                for i, arg in enumerate(call.args):
                    if not isinstance(arg, ast.Name):
                        continue
                    slot = (callee.path, callee.line, i + offset)
                    if (key := bound(arg.id, rel)) is not None:
                        self.params.setdefault(slot, set()).add(key)
                    elif enclosing is not None and arg.id in own:
                        edges.append(((rel, enclosing.lineno, own.index(arg.id)), slot))
        changed = True
        while changed:
            changed = False
            for origin, slot in edges:
                if new := self.params.get(origin, set()) - self.params.get(slot, set()):
                    self.params.setdefault(slot, set()).update(new)
                    changed = True

    def of(self, expr: str, rel: str, enclosing: ast.AST | None) -> list[_Key]:
        if (key := self.bound(expr, rel)) is not None:
            return [key]
        own, root = _param_names(enclosing), expr.split(".")[0]
        if enclosing is None or root not in own:
            return []
        return sorted(self.params.get((rel, getattr(enclosing, "lineno", 0), own.index(root)), ()))


def _guard_split(names: Iterable[str]) -> tuple[list[str], list[str]]:
    guards, unguards = [], []
    for n in names:
        if UNGUARD_RX.search(n):
            unguards.append(n)
        elif GUARD_RX.search(n):
            guards.append(n)
    return _unique(guards), sorted(set(unguards))


def _middleware_rejects(fn: ast.AST) -> bool:
    """A middleware guards only if it can answer without passing the request on."""
    args = getattr(fn, "args", None)
    params = [a.arg for a in args.args] if args else []
    onward = params[1] if len(params) > 1 else None
    for n in ast.walk(fn):
        if isinstance(n, ast.Raise):
            return True
        if isinstance(n, ast.Return) and n.value is not None:
            value = n.value.value if isinstance(n.value, ast.Await) else n.value
            if not (isinstance(value, ast.Call) and _dotted(value.func) == onward):
                return True
    return False


def _guard_named(name: str) -> bool:
    return bool(GUARD_RX.search(name) or _FLASK_GUARD_EXTRA.search(name))


def _middleware_guard(
    name: str, rel: str, functions: dict[str, list[_Function]], modules: _Modules
) -> bool:
    if not name or UNGUARD_RX.search(name):
        return False
    origin = modules.origin(name, rel)
    if origin.split(".")[0] in _FRAMEWORK_PACKAGES and _NON_ENFORCING_MIDDLEWARE.search(
        _last(name)
    ):
        return False
    if not _guard_named(_last(name)):
        return False
    fn = modules.function(name, rel, functions)
    return fn is None or fn.node is None or _middleware_rejects(fn.node)


@dataclass
class _Mount:
    parent: _Key
    prefix: str
    guards: list[str]
    unguards: list[str]


@dataclass
class _Receiver:
    prefix: str = ""
    guards: list[str] = field(default_factory=list)
    unguards: list[str] = field(default_factory=list)


@dataclass
class _Scope:
    prefix: str
    guards: list[str]
    unguards: list[str]


def _chains(
    key: _Key,
    receivers: dict[_Key, _Receiver],
    mounts: dict[_Key, list[_Mount]],
    middleware: dict[_Key, list[str]],
    seen: frozenset[_Key] = frozenset(),
) -> list[_Scope]:
    """Every way a receiver's routes are reached: each mount's prefix and the guards it adds."""
    recv = receivers[key]
    own = _Scope(recv.prefix, [*recv.guards, *middleware.get(key, [])], list(recv.unguards))
    parents = [m for m in mounts.get(key, []) if m.parent not in seen and m.parent in receivers]
    if not parents:
        return [own]
    out = []
    for m in parents[:_MAX_MOUNTS]:
        for up in _chains(m.parent, receivers, mounts, middleware, seen | {key}):
            out.append(
                _Scope(
                    up.prefix + m.prefix + own.prefix,
                    _unique([*up.guards, *m.guards, *own.guards]),
                    sorted({*up.unguards, *m.unguards, *own.unguards}),
                )
            )
    return out[:_MAX_MOUNTS]


class _FastApi:
    """FastAPI routes and the dependencies guarding them, through routers, mounts and
    middleware; a dependency is followed into its own dependencies by name."""

    def __init__(self, index: _PyIndex, consts: dict[str, str]) -> None:
        self.index, self.consts = index, consts
        self.modules, self.functions = index.modules, index.functions
        self.security: set[str] = set()
        self.fail_open: set[str] = set()  # schemes built with auto_error=False: a missing
        # credential yields None, not a 401
        self.receivers: dict[_Key, _Receiver] = {}
        self.mounts: dict[_Key, list[_Mount]] = {}
        self.middleware: dict[_Key, list[str]] = {}
        self._bind()

    def _ctors(self) -> set[str]:
        """FastAPI and APIRouter, and the tree's subclasses of either."""
        ctors = set(FASTAPI_CTORS)
        classes = [c for cs in self.index.class_defs.values() for c in cs]
        grew = True
        while grew:
            grew = False
            for node in classes:
                if node.name not in ctors and any(_last(_dotted(b)) in ctors for b in node.bases):
                    ctors.add(node.name)
                    grew = True
        return ctors

    def _bind(self) -> None:
        ctors = self._ctors()
        for rel, assigns in self.index.assigns.items():
            for node in assigns:
                if not isinstance(node.value, ast.Call):
                    continue
                ctor = _last(_dotted(node.value.func))
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [
                    t.id if isinstance(t, ast.Name) else t.attr
                    for t in targets
                    if isinstance(t, ast.Name | ast.Attribute)
                ]
                if _FASTAPI_SECURITY.match(ctor):
                    self.security.update(names)
                    auto_error = _kwarg(node.value, "auto_error")
                    if isinstance(auto_error, ast.Constant) and auto_error.value is False:
                        self.fail_open.update(names)
                if ctor not in ctors:
                    continue
                guards, unguards = self._dependencies(_kwarg(node.value, "dependencies"), rel)
                prefix = _const_str(_kwarg(node.value, "prefix")) or ""
                for name in names:
                    self.receivers[(rel, name)] = _Receiver(prefix, guards, unguards)
        bound = set(self.receivers)
        self.bindings = _Bindings(self.index, lambda expr, rel: self.modules.key(expr, rel, bound))
        for rel, calls in self.index.calls.items():
            for node, enclosing in calls:
                self._wire(node, rel, enclosing)
        for rel, defs in self.index.defs.items():
            for fn, enclosing in defs:
                for d in fn.decorator_list:
                    dn = _dotted(d)
                    if _last(dn) == "middleware" and "." in dn:
                        self._middleware_fn(fn, dn.rsplit(".", 1)[0], rel, enclosing)

    def _middleware_fn(self, fn: ast.AST, recv: str, rel: str, enclosing: ast.AST | None) -> None:
        name = getattr(fn, "name", "")
        if _guard_named(name) and _middleware_rejects(fn):
            for key in self.bindings.of(recv, rel, enclosing):
                self.middleware.setdefault(key, []).append(f"middleware:{name}")

    def _wire(self, node: ast.Call, rel: str, enclosing: ast.AST | None) -> None:
        if (
            isinstance(node.func, ast.Call)
            and _last(_dotted(node.func.func)) == "middleware"
            and "." in (inner := _dotted(node.func.func))
            and node.args
            and (fn := self.index.callee(_dotted(node.args[0]), rel))
            and fn.node is not None
        ):
            self._middleware_fn(fn.node, inner.rsplit(".", 1)[0], rel, enclosing)
            return
        fn_name = _dotted(node.func)
        attr = _last(fn_name)
        if attr not in ("include_router", "mount", "add_middleware") or "." not in fn_name:
            return
        parents = self.bindings.of(fn_name.rsplit(".", 1)[0], rel, enclosing)
        if attr == "add_middleware":
            name = _dotted(node.args[0]) if node.args else ""
            if _middleware_guard(name, rel, self.functions, self.modules):
                for parent in parents:
                    self.middleware.setdefault(parent, []).append(f"middleware:{_last(name)}")
            return
        child_expr = (
            node.args[1]
            if attr == "mount" and len(node.args) > 1
            else (node.args[0] if attr == "include_router" and node.args else _kwarg(node, "app"))
        )
        children = self.bindings.of(_dotted(child_expr), rel, enclosing) if child_expr else []
        prefix_node = node.args[0] if attr == "mount" and node.args else _kwarg(node, "prefix")
        guards, unguards = self._dependencies(_kwarg(node, "dependencies"), rel)
        for child in children:
            for parent in parents:
                self.mounts.setdefault(child, []).append(
                    _Mount(parent, _const_str(prefix_node) or "", guards, unguards)
                )

    def _dependency(self, call: ast.Call, annotation: ast.AST | None) -> str:
        target = call.args[0] if call.args else _kwarg(call, "dependency")
        name = _dotted(target if target is not None else annotation)
        if _last(_dotted(call.func)) == "Security":
            scopes = _str_list(_kwarg(call, "scopes"))
            return f"Security:{name}" + (f"[{','.join(scopes)}]" if scopes else "")
        return name

    def _depends(self, node: ast.AST | None, annotation: ast.AST | None = None) -> list[str]:
        if isinstance(node, ast.Call) and _last(_dotted(node.func)) in _DEPENDS:
            return [self._dependency(node, annotation)]
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return [n for e in node.elts for n in self._depends(e)]
        return []

    def _params(self, fn: ast.AST, rel: str) -> list[tuple[str, str]]:
        args = getattr(fn, "args", None)
        if args is None:
            return []
        positional = [*args.posonlyargs, *args.args]
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = [
            *zip(positional, defaults, strict=True),
            *zip(args.kwonlyargs, args.kw_defaults, strict=True),
        ]
        out: list[tuple[str, str]] = []
        for param, default in pairs:
            ann, where = _unquoted(param.annotation), rel
            # `user: CurrentUser`, CurrentUser = Annotated[User, Depends(...)] elsewhere
            if isinstance(ann, ast.Name | ast.Attribute) and (
                found := self.index.alias(_dotted(ann), rel)
            ):
                ann, where = found
            if isinstance(ann, ast.Subscript) and _last(_dotted(ann.value)) == "Annotated":
                parts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
                for extra in parts[1:]:
                    out += [(n, where) for n in self._depends(extra, parts[0])]
            out += [(n, rel) for n in self._depends(default, ann)]
        return [(n, w) for n, w in out if n]

    def _classify(
        self, names: list[tuple[str, str]], depth: int = 0, seen: frozenset[str] = frozenset()
    ) -> tuple[list[str], list[str]]:
        """Each dependency name with the file it is resolved from."""
        guards: list[str] = []
        unguards: list[str] = []
        for name, rel in names:
            bare = name.removeprefix("Security:").split("[")[0]
            if UNGUARD_RX.search(bare):
                unguards.append(name)
            elif (
                name.startswith("Security:")
                or (GUARD_RX.search(bare) and not _DB_SESSION_RX.match(_last(bare)))
                or _FASTAPI_SECURITY.match(_last(bare))
                or _last(bare) in self.security
            ):
                guards.append(name)
                if _last(bare) in self.fail_open:
                    unguards.append(f"{FAIL_OPEN}:{name}")
            elif depth < _DEPTH and bare not in seen:
                fn = self.index.callee(bare, rel) if bare else None
                if fn is not None and fn.node is not None:
                    g, u = self._classify(self._params(fn.node, fn.path), depth + 1, seen | {bare})
                    if _raises(fn.node):  # it refuses the missing credential itself
                        u = [x for x in u if not x.startswith(f"{FAIL_OPEN}:")]
                    guards += [f"{bare}>{x}" for x in g]
                    unguards += [f"{bare}>{x}" for x in u]
        return _unique(guards), sorted(set(unguards))

    def _dependencies(self, node: ast.AST | None, rel: str) -> tuple[list[str], list[str]]:
        return self._classify([(n, rel) for n in self._depends(node)])

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for rel, defs in self.index.defs.items():
            for fn, enclosing in defs:
                for d in fn.decorator_list:
                    if isinstance(d, ast.Call) and _last(_dotted(d.func)) in _FASTAPI_DECORATORS:
                        rows += self._route(d, fn, rel, enclosing)
        for rel, calls in self.index.calls.items():
            for node, enclosing in calls:
                if _last(_dotted(node.func)) in ("add_api_route", "add_api_websocket_route"):
                    rows += self._route(node, None, rel, enclosing)
        return rows

    def _route(
        self, call: ast.Call, fn: ast.AST | None, rel: str, enclosing: ast.AST | None
    ) -> list[_Row]:
        dn = _dotted(call.func)
        attr = _last(dn)
        keys = self.bindings.of(dn.rsplit(".", 1)[0], rel, enclosing) if "." in dn else []
        if not keys:
            return []
        pattern, dynamic = _pattern(
            call.args[0] if call.args else _kwarg(call, "path"), self.consts
        )
        if pattern is None:
            return []
        handler = getattr(fn, "name", "")
        if fn is None:
            endpoint = call.args[1] if len(call.args) > 1 else _kwarg(call, "endpoint")
            handler = _dotted(endpoint)
            found = self.index.callee(handler, rel) if handler else None
            fn = found.node if found else None
        if attr in ("websocket", "add_api_websocket_route"):
            methods = ["WS"]
        elif attr in FASTAPI_VERBS:
            methods = [attr.upper()]
        else:
            methods = [m.upper() for m in _str_list(_kwarg(call, "methods"))] or ["GET"]
        route_guards, route_unguards = self._dependencies(_kwarg(call, "dependencies"), rel)
        param_guards, param_unguards = (
            self._classify(self._params(fn, self.index.paths.get(id(fn), rel))) if fn else ([], [])
        )
        decorator_guards, decorator_unguards = _guard_split(
            _dotted(d)
            for d in getattr(fn, "decorator_list", [])
            if not isinstance(d, ast.Call) or _last(_dotted(d.func)) not in _FASTAPI_DECORATORS
        )
        rows = []
        scopes = [
            (key, s)
            for key in keys
            for s in _chains(key, self.receivers, self.mounts, self.middleware)
        ]
        for key, scope in scopes[:_MAX_MOUNTS]:
            row = _row(
                RouteFamily.FASTAPI,
                ",".join(methods),
                scope.prefix + pattern,
                handler or "<endpoint>",
                rel,
                call.lineno,
                _unique([*route_guards, *param_guards, *decorator_guards]),
                scope.guards,
                sorted({*route_unguards, *param_unguards, *decorator_unguards, *scope.unguards}),
            )
            if fn is not None:
                self.index.locate(row, fn)
            rows.append(_mark(row, key[1], dynamic, rel))
        return rows


def _fastapi(index: _PyIndex, consts: dict[str, str]) -> tuple[list[_Row], bool]:
    if not any(_FASTAPI_IMPORT.search(s.file.text) for s in index.sources):
        return [], False
    return _FastApi(index, consts).rows(), True


def _top_level_guard_calls(fn: ast.AST | None) -> tuple[list[str], list[str]]:
    """Guard-shaped calls a handler makes as bare statements of its own body (`await
    check_authorized(request)`): a check that raises. A call whose result is kept
    (`user = await authorized_userid(request)`) only reads who is calling."""
    names = []
    for stmt in getattr(fn, "body", []):
        value = stmt.value if isinstance(stmt, ast.Expr) else None
        value = value.value if isinstance(value, ast.Await) else value
        if isinstance(value, ast.Call):
            names.append(_dotted(value.func))
    guards, unguards = _guard_split(names)
    return [f"call:{g}" for g in guards], [f"call:{u}" for u in unguards]


class _Aiohttp:
    """aiohttp routes (router.add_*, add_routes, RouteTableDef decorators, class views) and the
    decorators, guard calls and app middlewares guarding them."""

    def __init__(self, index: _PyIndex, consts: dict[str, str]) -> None:
        self.index, self.consts = index, consts
        self.modules, self.functions, self.classes = index.modules, index.functions, index.classes
        self.apps: dict[_Key, list[str]] = {}
        self.aliases: dict[_Key, _Key] = {}
        self.tables: set[_Key] = set()
        self.table_apps: dict[_Key, list[_Key]] = {}
        self._bind()
        self._wire()

    def _bind(self) -> None:
        for rel, assigns in self.index.assigns.items():
            for node in assigns:
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                    continue
                ctor = _last(_dotted(node.value.func))
                for t in node.targets:
                    if not isinstance(t, ast.Name):
                        continue
                    if ctor == "Application":
                        self.apps[(rel, t.id)] = [
                            f"middleware:{_last(m)}"
                            for m in _names_in(_kwarg(node.value, "middlewares"))
                            if _middleware_guard(m, rel, self.functions, self.modules)
                        ]
                    elif ctor == "RouteTableDef":
                        self.tables.add((rel, t.id))

    def _app(self, expr: str, rel: str) -> _Key | None:
        root = expr.removesuffix(".router")
        key = self.modules.key(root, rel, set(self.apps) | set(self.aliases))
        return self.aliases.get(key, key) if key else None

    def _wire(self) -> None:
        for rel, assigns in self.index.assigns.items():
            for node in assigns:
                if (
                    isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Attribute)
                    and node.value.attr == "router"
                    and (app := self._app(_dotted(node.value), rel))
                ):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.aliases[(rel, t.id)] = app
        self.bindings = _Bindings(self.index, self._app)
        for rel, calls in self.index.calls.items():
            for node, enclosing in calls:
                if "." not in (fn := _dotted(node.func)):
                    continue
                if fn.endswith(".middlewares.append") and node.args:
                    name = _dotted(node.args[0])
                    if _middleware_guard(name, rel, self.functions, self.modules):
                        for app in self._receiver_apps(
                            fn.removesuffix(".middlewares.append"), rel, enclosing
                        ):
                            self.apps[app].append(f"middleware:{_last(name)}")
                if _last(fn) == "add_routes" and node.args:
                    table = self.modules.key(_dotted(node.args[0]), rel, self.tables)
                    for app in self._receiver_apps(fn.rsplit(".", 1)[0], rel, enclosing):
                        if table:
                            self.table_apps.setdefault(table, []).append(app)

    def _receiver_apps(self, recv: str, rel: str, enclosing: ast.AST | None) -> list[_Key]:
        """The apps a receiver is: a bound app or alias, or the app a helper is called with."""
        return self.bindings.of(recv.removesuffix(".router"), rel, enclosing)

    def _handler(self, expr: ast.AST | None, rel: str) -> tuple[str, ast.AST | None]:
        name = _dotted(expr)
        if name and _last(name) in self.classes:
            return name, self.classes[_last(name)]
        found = self.index.callee(name, rel) if name else None
        return name or "<handler>", found.node if found else None

    def _view_rows(
        self,
        view: ast.ClassDef,
        pattern: str,
        dynamic: bool,
        scope: list[str],
        receiver: str | None,
        rel: str,
        line: int,
    ) -> list[_Row]:
        cls_guards, cls_unguards = _guard_split(_dotted(d) for d in view.decorator_list)
        rows = []
        for stmt in view.body:
            if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if stmt.name.lower() not in AIOHTTP_VERBS:
                continue
            guards, unguards = _guard_split(_dotted(d) for d in stmt.decorator_list)
            calls, uncalls = _top_level_guard_calls(stmt)
            row = _row(
                RouteFamily.AIOHTTP,
                stmt.name.upper(),
                pattern,
                f"{view.name}.{stmt.name}",
                rel,
                line,
                _unique([*guards, *calls, *cls_guards]),
                scope,
                sorted({*unguards, *uncalls, *cls_unguards}),
            )
            row.view_class = view.name
            self.index.locate(row, stmt)
            rows.append(_mark(row, receiver, dynamic, rel))
        return rows

    def _rows(
        self,
        method: str,
        pattern_node: ast.AST | None,
        target: ast.AST | str | None,
        apps: list[_Key],
        receiver: str | None,
        rel: str,
        line: int,
    ) -> list[_Row]:
        pattern, dynamic = _pattern(pattern_node, self.consts)
        if pattern is None:
            return []
        scope = _unique(g for app in apps for g in self.apps.get(app, []))
        if isinstance(target, ast.ClassDef):
            return self._view_rows(target, pattern, dynamic, scope, receiver, rel, line)
        name, node = (
            (getattr(target, "name", ""), target)
            if isinstance(target, ast.FunctionDef | ast.AsyncFunctionDef)
            else self._handler(target, rel)
        )  # type: ignore[arg-type]
        if isinstance(node, ast.ClassDef):
            return self._view_rows(node, pattern, dynamic, scope, receiver, rel, line)
        decos = [_dotted(d) for d in getattr(node, "decorator_list", [])]
        guards, unguards = _guard_split(
            d for d in decos if _last(d) not in (*AIOHTTP_VERBS, "route", "view")
        )
        calls, uncalls = _top_level_guard_calls(node)
        row = _row(
            RouteFamily.AIOHTTP,
            method,
            pattern,
            name,
            rel,
            line,
            _unique([*guards, *calls]),
            scope,
            sorted({*unguards, *uncalls}),
        )
        if node is not None:
            self.index.locate(row, node)
        return [_mark(row, receiver, dynamic, rel)]

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for rel in self.index.calls:
            for fn, _ in self.index.defs[rel]:
                rows += self._table_routes(fn, rel)
            for cls in self.index.class_defs[rel]:
                rows += self._table_routes(cls, rel)
            for node, enclosing in self.index.calls[rel]:
                rows += self._call(node, rel, enclosing)
        return rows

    def _table_routes(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, rel: str
    ) -> list[_Row]:
        rows: list[_Row] = []
        for d in node.decorator_list:
            if not isinstance(d, ast.Call) or "." not in (dn := _dotted(d.func)):
                continue
            table = self.modules.key(dn.rsplit(".", 1)[0], rel, self.tables)
            attr = _last(dn)
            if table is None or attr not in (*AIOHTTP_VERBS, "route", "view"):
                continue
            method, pattern_node = _route_args(attr, d)
            rows += self._rows(
                method, pattern_node, node, self.table_apps.get(table, []), table[1], rel, d.lineno
            )
        return rows

    def _call(self, node: ast.Call, rel: str, enclosing: ast.AST | None) -> list[_Row]:
        fn = _dotted(node.func)
        attr = _last(fn)
        if "." not in fn:
            return []
        recv = fn.rsplit(".", 1)[0]
        receiver = _last(recv.removesuffix(".router"))
        if attr in (*_AIOHTTP_ADD, "add_route", "add_view") and (
            recv.endswith("router") or self._app(recv, rel)
        ):
            kind = "route" if attr == "add_route" else ("view" if attr == "add_view" else attr[4:])
            method, pattern_node = _route_args(kind, node)
            target = _handler_arg(kind, node)
            apps = self._receiver_apps(recv, rel, enclosing)
            return self._rows(method, pattern_node, target, apps, receiver, rel, node.lineno)
        if (
            attr != "add_routes"
            or not node.args
            or not isinstance(node.args[0], ast.List | ast.Tuple)
        ):
            return []
        apps = self._receiver_apps(recv, rel, enclosing)
        rows: list[_Row] = []
        for e in node.args[0].elts:
            kind = _last(_dotted(e.func)) if isinstance(e, ast.Call) else ""
            if isinstance(e, ast.Call) and kind in (*AIOHTTP_VERBS, "route", "view"):
                method, pattern_node = _route_args(kind, e)
                rows += self._rows(
                    method, pattern_node, _handler_arg(kind, e), apps, receiver, rel, e.lineno
                )
        return rows


def _route_args(kind: str, call: ast.Call) -> tuple[str, ast.AST | None]:
    """(method, path node) of an aiohttp `get(path, …)`, `route(method, path, …)` or `view`."""
    if kind == "route":
        method = (_const_str(call.args[0]) if call.args else None) or "ANY"
        return method.upper(), call.args[1] if len(call.args) > 1 else _kwarg(call, "path")
    method = "ANY" if kind == "view" else kind.upper()
    return method, call.args[0] if call.args else _kwarg(call, "path")


def _handler_arg(kind: str, call: ast.Call) -> ast.AST | None:
    index = 2 if kind == "route" else 1
    return call.args[index] if len(call.args) > index else _kwarg(call, "handler")


def _aiohttp(index: _PyIndex, consts: dict[str, str]) -> tuple[list[_Row], bool]:
    if not any(_AIOHTTP_IMPORT.search(s.file.text) for s in index.sources):
        return [], False
    return _Aiohttp(index, consts).rows(), True


_METHOD_LABELS = (
    RouteFamily.FLASK,
    RouteFamily.FASTAPI,
    RouteFamily.AIOHTTP,
    RouteFamily.EXPRESS,
    RouteFamily.SPRING,
    RouteFamily.JAX_RS,
    RouteFamily.AXUM,
    RouteFamily.ACTIX,
    RouteFamily.RAILS,
    RouteFamily.SINATRA,
)


def _asymmetries(rows: list[_Row]) -> list[RouteAsymmetry]:
    """Per family and registration file, guarded rows next to bare ones (the bare are marked).
    Python labels carry the method: one pattern often serves several."""
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
    """Within one view class or receiver, a guard family most rows carry, missing from
    guarded rows that lack it ("every neighbour performs this check but this one")."""
    groups: dict[tuple[RouteFamily, str, str], list[_Row]] = {}
    for r in rows:
        if r.family in _METHOD_LABELS:
            groups.setdefault((r.family, r.path, r.view_class or r.receiver or ""), []).append(r)
    found = []
    for (family, path, key), members in sorted(groups.items()):
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
                    family=family,
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
        for name, suffixes, rx in OTHER_FRAMEWORKS:
            if name not in hits and f.path.suffix in suffixes and rx.search(f.text):
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
    sources, unparsed = _parsed(py)
    index, consts = _PyIndex.of(sources), _string_constants(py)
    fastapi_rows, uses_fastapi = _fastapi(index, consts)
    aiohttp_rows, uses_aiohttp = _aiohttp(index, consts)
    # they build on this module
    from traust_core.v1.providers.express_routes import express_rows
    from traust_core.v1.providers.java_routes import java_rows
    from traust_core.v1.providers.ruby_routes import callback_asymmetries, ruby_rows
    from traust_core.v1.providers.rust_routes import rust_rows

    js_rows, uses_express, parsed = express_rows(files)
    java, rust, ruby = java_rows(files), rust_rows(files), ruby_rows(files)
    rows = [
        *_go(files),
        *_django(py),
        *flask_rows,
        *fastapi_rows,
        *aiohttp_rows,
        *js_rows,
        *java.rows,
        *rust.rows,
        *ruby.rows,
    ]
    labelled = [r for r in rows if r.family in _METHOD_LABELS]
    asymmetries = [
        *_asymmetries(rows),
        *_family_asymmetries(labelled),
        *callback_asymmetries(ruby.rows),
    ]
    gaps = _other_frameworks(files)
    if web := [
        f for f in unparsed if _PY_WEB_IMPORT.search(f.text) or _FLASK_IMPORT.search(f.text)
    ]:
        version = ".".join(map(str, sys.version_info[:2]))
        gaps.append(
            CoverageGap(
                system="python",
                reason=f"{len(web)} Python web file(s) use syntax Python {version} can't parse — "
                "their routes, dependencies and guards are UNENUMERATED (scan on a newer Python)",
                count=len(web),
                paths=tuple(RepoPath(f.rel) for f in web[:20]),
                evidence=RepoPath(web[0].rel),
            )
        )
    if uses_express and not js_rows:
        reason = (
            f"express imports detected but {grammar_missing('JS/TS', 'tree-sitter-javascript')}"
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
    for family, evidence in java.evidence.items():
        if family in java.generated:
            controllers = java.generated[family]
            reason = (
                f"{len(controllers)} controller(s) implement API interfaces that are not in the "
                "checkout (generated at build time, e.g. by an OpenAPI generator)"
            )
            evidence = controllers[0]
        elif any(r.family is family for r in java.rows):
            continue
        elif not java.parsed:
            reason = f"annotations detected but {grammar_missing('Java', 'tree-sitter-java')}"
        else:
            reason = (
                "annotations detected but no route this enumerator recognizes (Spring "
                "@*Mapping on a controller, JAX-RS @Path resources with a verb annotation)"
            )
        gaps.append(
            CoverageGap(
                system=family,
                reason=f"{family}: {reason} — the {family} route x guard matrix is UNENUMERATED",
                evidence=RepoPath(evidence),
            )
        )
    for family, evidence, parsed, found, lang, shapes in (
        *(
            (f, e, rust.parsed, rust.rows, "rust", "axum Router route/nest/merge chains, "
             "actix-web App/scope services, routes and route macros")
            for f, e in rust.evidence.items()
        ),
        *(
            (f, e, ruby.parsed, ruby.rows, "ruby", "config/routes.rb resources and verbs, "
             "Sinatra verb blocks")
            for f, e in ruby.evidence.items()
        ),
    ):  # fmt: skip
        if any(r.family is family for r in found):
            continue
        reason = (
            f"used but {grammar_missing(lang.title(), f'tree-sitter-{lang}')}"
            if not parsed
            else f"used but no route this enumerator recognizes ({shapes})"
        )
        gaps.append(
            CoverageGap(
                system=family,
                reason=f"{family} {reason} — the {family} route x guard matrix is UNENUMERATED",
                evidence=RepoPath(evidence),
            )
        )
    for family, used, found, rx, shapes in (
        (
            RouteFamily.FLASK,
            uses_flask,
            flask_rows,
            _FLASK_IMPORT,
            "route/verb decorators, add_url_rule, add_resource",
        ),
        (
            RouteFamily.FASTAPI,
            uses_fastapi,
            fastapi_rows,
            _FASTAPI_IMPORT,
            "verb/api_route/websocket decorators, add_api_route",
        ),
        (
            RouteFamily.AIOHTTP,
            uses_aiohttp,
            aiohttp_rows,
            _AIOHTTP_IMPORT,
            "router.add_*, add_routes, RouteTableDef decorators",
        ),
    ):
        if used and not found:
            evidence = next((f.rel for f in py if rx.search(f.text)), None)
            gaps.append(
                CoverageGap(
                    system=family,
                    reason=f"{family} imports detected but no route registration this enumerator "
                    f"recognizes ({shapes}) — the {family} route x guard matrix is UNENUMERATED",
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
