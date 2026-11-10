"""Route x guard matrix: a checkout's HTTP route registrations (go-http, django-drf, flask,
fastapi, aiohttp, express) and the guards applied to each, matched by name and over-inclusive;
target code is parsed, never imported. Other frameworks found are coverage gaps."""

from __future__ import annotations

import ast
import re
import sys
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import cache, partial
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, TypeVar

from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    CoverageGap,
    GuardFamily,
    RouteAsymmetry,
    RouteFamily,
    RouteGuardFact,
)
from traust_core.v1.models.common import RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.python_guards import (
    FLASK_LOGIN_GUARDS,
    KNOWN_GUARDS,
    UNREADABLE,
    GuardReader,
    requires_nothing,
)
from traust_core.v1.providers.route_ownership import (
    HandlerFacts,
    path_params,
    privileged_only,
    rank,
)
from traust_core.v1.providers.route_plumbing import (
    _FLASK_IMPORT,
    GUARD_RX,
    NON_ENFORCING_RX,
    UNGUARD_RX,
    _c3,
    _const_str,
    _dotted,
    _Function,
    _guards_in,
    _Key,
    _kwarg,
    _last,
    _line,
    _mark,
    _module_statements,
    _Modules,
    _own_nodes,
    _parsed,
    _PyIndex,
    _resolve_import,
    _Row,
    _row,
    _same_module,
    _Source,
    _str_list,
    _string_constants,
    _targets,
    _unguards_in,
    _unique,
    constants_for,
    file_constants,
)
from traust_core.v1.providers.syntax import grammar_missing
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

if TYPE_CHECKING:
    from traust_core.v1.providers.python_ownership import Opaque, PyOwnership, Target

_TEST_NAME = re.compile(r"(^|[._-])(test|spec|mock|fixture)s?([._-]|$)")


def _deco_name(d: ast.AST, renamed: dict[str, str] | None = None) -> str:
    """A decorator's name; `optional:` when it lets an anonymous caller through
    (`jwt_required(optional=True)`), none when it asks for nothing (`roles_required()`).
    `renamed` maps the file's import aliases to the names they import."""
    written = _last(_dotted(d.func if isinstance(d, ast.Call) else d))
    called = (renamed or {}).get(written, written)
    if requires_nothing(d, called):
        return ""
    optional = isinstance(d, ast.Call) and (
        any(
            k.arg == "optional" and not (isinstance(k.value, ast.Constant) and not k.value.value)
            for k in d.keywords
        )
        # `jwt_required(True)`: flask-jwt-extended's first parameter is `optional`
        or (
            called == "jwt_required"
            and bool(d.args)
            and not (isinstance(d.args[0], ast.Constant) and d.args[0].value is False)
        )
    )
    return f"{_OPTIONAL}{_dotted(d)}" if optional else _dotted(d)


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
    # Flask-based, its routes declared in an OpenAPI spec
    ("connexion", (".py",), re.compile(r"^\s*(?:from|import)\s+connexion\b", re.M)),
)
# A database or ORM session dependency (`get_db_session`, `SessionLocal`), not a session check
_DB_SESSION_RX = re.compile(
    r"(?i)^(get_|new_|open_)?(async_?|db_?|database_?|sql_?|orm_?|read_?|write_?|readonly_?|replica_?)*"
    r"session(_?(maker|local|factory|scope|dep))?$"
)
_FASTAPI_IMPORT = re.compile(r"^\s*(?:from\s+fastapi\b|import\s+fastapi\b)", re.M)
_PY_WEB_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+(?:fastapi|starlette|django|rest_framework|aiohttp)\b", re.M
)
FLASK_RECEIVER_CTORS = {
    "Flask": "app",
    "APIFlask": "app",
    "Blueprint": "blueprint",
    "APIBlueprint": "blueprint",
    "Api": "api",
    "Namespace": "namespace",
}
FLASK_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_FLASK_REGISTRATION_ATTRS = {"route", "add_url_rule", "add_resource", *FLASK_VERBS}
_VIEW_BASE = re.compile(r"(MethodView|^View$|\.View$|Resource$|MethodResource$)")
# flask-local additions: `check_*` decorators guard, `*exempt*` decorators unguard.
_FLASK_GUARD_EXTRA = re.compile(r"(?i)(^|\.)check_")
_FLASK_UNGUARD_EXTRA = re.compile(r"(?i)exempt")
# flask-login's `LOGIN_DISABLED` set to anything but false, in code or a config file
_LOGIN_DISABLED = re.compile(
    r"(?:LOGIN_DISABLED|_login_disabled)\W*(?:=|:|,)(?!\s*[\"']?(?i:false|0|no|off|none)\b)"
)
_CONFIG_SUFFIXES = {".py", ".cfg", ".ini", ".env", ".toml", ".yaml", ".yml", ".json", ".conf"}
# a response cache answers from the cache ahead of the decorators it wraps
_RESPONSE_CACHE = re.compile(r"^(cached|memoize|cache_page|cache_response)$")
# the packages whose `Resource` reads `method_decorators`
_RESTFUL = ("flask_restful", "flask_restx", "flask_restplus")
_VIEW_LISTS = ("decorators", "method_decorators")
GUARD_FAMILIES = (
    (GuardFamily.SCOPE, re.compile(r"(?i)scope")),
    (GuardFamily.ADMIN, re.compile(r"(?i)admin")),
    (GuardFamily.ROLE, re.compile(r"(?i)(role|rbac|acl)")),
    (GuardFamily.PERMISSION, re.compile(r"(?i)permission")),
    (GuardFamily.CSRF, re.compile(r"(?i)csrf")),
    (GuardFamily.TOKEN, re.compile(r"(?i)(jwt|token|oauth|oidc)")),
    (GuardFamily.AUTHN, re.compile(r"(?i)(login|auth|session)")),
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


def _flask_split(
    names: list[str], reader: GuardReader, outer_first: bool = True
) -> tuple[list[str], list[str]]:
    """The guards among decorator names (a known auth guard, D37), but none a response cache
    wraps; `optional:` and exemptions unguard. `View.decorators` lists the innermost first."""
    cached = [i for i, n in enumerate(names) if _caches([n])]
    inside = (
        set(range(cached[0] + 1, len(names)) if outer_first else range(cached[-1]))
        if cached
        else set()
    )
    guards, unguards = [], []
    for i, n in enumerate(names):
        if not n or _last(n) in _FLASK_REGISTRATION_ATTRS:
            continue
        if n.startswith(_OPTIONAL) or UNGUARD_RX.search(_last(n)) or _FLASK_UNGUARD_EXTRA.search(n):
            unguards.append(n)
        elif i not in inside and reader.guards(n):
            guards.append(n)
    return _unique(guards), sorted(set(unguards))


def _caches(names: Iterable[str]) -> bool:
    return any(_RESPONSE_CACHE.match(_last(n)) for n in names)


def _names_in(node: ast.AST | None, name: Callable[[ast.AST], str] = _dotted) -> list[str]:
    """A decorators-style value: a list of decorators, or a verb -> list dict."""
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [name(e) for e in node.elts]
    if isinstance(node, ast.Dict):
        return [n for v in node.values for n in _names_in(v, name)]
    return []


def _method_decorators(
    node: ast.AST, deco: Callable[[ast.AST], str]
) -> tuple[list[str], dict[str, list[str]]]:
    if isinstance(node, ast.Dict):
        per = {}
        for k, v in zip(node.keys, node.values, strict=False):
            if key := _const_str(k):
                per[key.lower()] = _names_in(v, deco)
        return [], per
    return _names_in(node, deco), {}


def _raises(fn: ast.AST) -> bool:
    """The function itself raises — a raise inside a nested helper is its behavior only
    when the function can reach that helper through calls (directly, or through a helper
    the call reaches)."""
    own = list(_own_nodes(fn))
    if any(isinstance(n, ast.Raise) for n in own):
        return True
    nested = {n.name: n for n in own if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
    if not nested:
        return False

    def called(scope: list[ast.AST]) -> set[str]:
        return {
            n.func.id for n in scope if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }

    # helpers reachable from the function, including through sibling helpers it calls
    reachable = called(own)
    changed = True
    while changed:
        changed = False
        for name in sorted(reachable):
            if name in nested and (deeper := called(list(_own_nodes(nested[name]))) - reachable):
                reachable |= deeper
                changed = True
    return any(name in nested and _raises(nested[name]) for name in reachable)


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
    # whether the class sets `decorators` / `method_decorators` itself (an empty list too)
    sets_decorators: bool = False
    sets_method_decorators: bool = False
    node: ast.ClassDef | None = None
    owner: str = ""


_D = TypeVar("_D", _Function, _Class)


@cache
def _test_module(rel: str) -> bool:
    """A file a test suite runs: named like a test, in a tests directory, or a conftest."""
    parts = PurePosixPath(rel.lower()).parts
    return parts[-1] == "conftest.py" or any(_TEST_NAME.search(p) for p in parts)


def _visible(found: list[_D], rel: str) -> list[_D]:
    """The definitions `rel` may mean by name: a test module's only within that module."""
    return [c for c in found if c.path == rel or not _test_module(c.path)]


def _scoped(tree: ast.AST) -> Iterator[tuple[ast.AST, ast.AST | None]]:
    """`ast.walk`'s nodes, each with the function or class it sits in (None at module level)."""
    todo: deque[tuple[ast.AST, ast.AST | None]] = deque([(tree, None)])
    while todo:
        node, scope = todo.popleft()
        yield node, scope
        inner = (
            node
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            else scope
        )
        todo.extend((child, inner) for child in ast.iter_child_nodes(node))


@dataclass
class _FlaskIndex:
    """Flask receivers (only from files importing a flask-family module), functions, view
    classes, guarding before_request hooks, blueprint registrations and from-imports."""

    receivers: dict[str, str] = field(default_factory=dict)
    functions: dict[str, list[_Function]] = field(default_factory=dict)
    classes: dict[str, _Class] = field(default_factory=dict)
    registered: dict[str, set[tuple[str, str]]] = field(default_factory=dict)  # (app, blueprint)
    imported: dict[str, dict[str, str]] = field(default_factory=dict)
    renamed: dict[str, dict[str, str]] = field(default_factory=dict)  # `import X as Y`: Y -> X
    class_defs: dict[str, list[_Class]] = field(default_factory=dict)
    _readers: dict[str, GuardReader] = field(default_factory=dict)
    login_disabled: bool = False
    # known guard names a checkout assignment binds: `login_required = lambda f: f`
    assigned: dict[str, list[_Function]] = field(default_factory=dict)
    # (class, attribute) set outside the class body: `Items.decorators = []`
    rebound: set[tuple[str, str]] = field(default_factory=set)
    unparsed: list[str] = field(default_factory=list)  # checkout modules this Python can't parse
    _chains: dict[tuple[str, str], list[_Class]] = field(default_factory=dict)
    methods: dict[str, list[_Function]] = field(default_factory=dict)  # reached as `obj.name`
    called: set[str] = field(default_factory=set)  # every function name the checkout calls
    # the function NODES the checkout calls, resolved to their definitions
    called_defs: set[int] = field(default_factory=set)
    # the checkout modules each file star-imports
    starred: dict[str, list[str]] = field(default_factory=dict)
    # each module's `__all__`, when it has one: a star import binds only what it exports
    exports: dict[str, frozenset[str]] = field(default_factory=dict)
    # each file's from-imports in source order: (line, name — "*" for a star import, module)
    import_order: dict[str, list[tuple[int, str, str]]] = field(default_factory=dict)
    modules: _Modules | None = None

    def pick(self, found: list[_D], name: str, rel: str) -> _D | None:
        """Of the definitions a name may be, the one `rel` means: its own file's (the last, which
        is what the name is bound to; None when scopes differ), the module it imports the name
        (or the name's module) from, else the only one outside test modules; None when unsure."""
        head = name.split(".")[0]
        here = [c for c in found if c.path == rel]
        if here and "." not in name:
            return max(here, key=lambda c: c.line) if len({c.owner for c in here}) == 1 else None
        module = self.imported.get(rel, {}).get(head)
        if module is not None:
            target = f"{module}.{head}" if "." in name else module
            mine = [
                c for c in found if _same_module(c.path, target) or _same_module(c.path, module)
            ]
            if len(mine) == 1:
                return mine[0]
        found = _visible(found, rel)
        return found[0] if len(found) == 1 else None

    def kind(self, name: str, rel: str) -> str | None:
        """The flask receiver kind a checkout class's bases make it (`class V(Blueprint)`)."""
        return next(
            (
                FLASK_RECEIVER_CTORS[_last(base)]
                for c in self.chain(name, rel)
                for base in c.bases
                if _last(base) in FLASK_RECEIVER_CTORS
            ),
            None,
        )

    def reader(self, rel: str) -> GuardReader:
        """Guards read from `rel`: a decorator or class resolves to the checkout's definition."""
        if rel not in self._readers:
            modules = self.modules or _Modules()

            def resolve(name: str) -> ast.AST | None:
                written = _last(name)
                # the name as written (an alias the file rebinds) and the name it imports
                names = dict.fromkeys((written, self.renamed.get(rel, {}).get(written, written)))
                kinds: list[dict[str, list[_Function]] | dict[str, list[_Class]]] = [
                    self.functions,
                    self.class_defs,
                    self.assigned,
                ]
                if "." in name:
                    kinds.append(self.methods)  # `auth.login_required` on a checkout class
                here = any(c.path == rel for b in names for k in kinds for c in k.get(b, []))
                full = modules.full(name, rel)
                if (
                    full
                    and not (here or self.star_binds(rel, names, kinds))
                    and not modules.local(full)
                ):
                    # imported from a library: its own, whatever the checkout defines elsewhere
                    return UNREADABLE if self.unparsed_import(name, rel) else None
                for bare in names:
                    for found in kinds:
                        if not _visible(found.get(bare, []), rel):
                            continue  # none, or only a test module's
                        # a checkout binding of the name, even one we can't tell is which
                        picked = self.pick(found[bare], name, rel)  # type: ignore[type-var]
                        return picked.node if picked is not None and picked.node else UNREADABLE
                return UNREADABLE if self.unparsed_import(name, rel) else None

            # flask-login's `LOGIN_DISABLED` lets every caller past its guards
            self._readers[rel] = GuardReader(
                resolve,
                disabled=FLASK_LOGIN_GUARDS if self.login_disabled else frozenset(),
                origin=lambda name: modules.full(name, rel),
                local=modules.local,
            )
        return self._readers[rel]

    def star_binds(
        self, rel: str, names: Iterable[str], kinds: Sequence[Mapping[str, Sequence[_D]]]
    ) -> bool:
        """A module `rel` star-imports binds one of the names, and that binding governs:
        the star source defines or imports the name AND exports it (`__all__` gates what a
        star import brings in), and no later import in `rel` rebinds the name over it — an
        explicit import after the star wins, as at runtime."""
        starred = self.starred.get(rel, [])
        if not starred:
            return False
        for b in names:
            binding = self._last_binding(rel, b, starred, kinds)
            if binding is None:
                continue
            _, is_star, module = binding
            if is_star:
                return True
            # the last binding names the star source itself: the same checkout definition
            if any(_same_module(module, m) for m in starred) and self._module_binds(
                module, b, kinds
            ):
                return True
        return False

    def _last_binding(
        self,
        rel: str,
        name: str,
        starred: list[str],
        kinds: Sequence[Mapping[str, Sequence[_D]]],
    ) -> tuple[int, bool, str] | None:
        """The last import of `rel` that binds `name`: an explicit import of it, or a star
        import whose module exports it. None when nothing binds it."""
        binding = None
        for line, imported, module in self.import_order.get(rel, ()):
            if imported == name:
                binding = (line, False, module)
            elif (
                imported == "*"
                and module in starred
                and self._module_binds(module, name, kinds)
                and self._exports(module, name)
            ):
                binding = (line, True, module)
        return binding

    def _exports(self, module: str, name: str) -> bool:
        """A star import from `module` brings `name` in only when the module exports it."""
        exports = self.exports.get(module)
        return exports is None or name in exports

    def _module_binds(
        self, module: str, name: str, kinds: Sequence[Mapping[str, Sequence[_D]]]
    ) -> bool:
        """`module` defines or imports `name` (what a star import of it could bind)."""
        return any(_same_module(c.path, module) for k in kinds for c in k.get(name, [])) or any(
            _same_module(r, module) and name in self.imported.get(r, {}) for r in self.imported
        )

    def resolve_fn(self, name: str, rel: str) -> _Function | None:
        bare = self.renamed.get(rel, {}).get(_last(name), _last(name))
        return self.pick(self.functions.get(bare, []), name, rel)

    def class_named(self, name: str, rel: str) -> _Class | None:
        bare = self.renamed.get(rel, {}).get(_last(name), _last(name))
        return self.pick(self.class_defs.get(bare, []), name, rel)

    def unparsed_import(self, name: str, rel: str) -> bool:
        """`rel` imports the name (or its module) from a checkout module this Python can't parse."""
        head = name.split(".")[0]
        module = self.imported.get(rel, {}).get(head)
        return module is not None and any(
            _same_module(u, m) for u in self.unparsed for m in (module, f"{module}.{head}")
        )

    def chain(self, name: str, rel: str, seen: frozenset[int] = frozenset()) -> list[_Class]:
        """The class and its in-repo bases in method resolution order (C3, else depth-first),
        cycle-safe."""
        if not seen and (name, rel) in self._chains:
            return self._chains[(name, rel)]
        info = self.class_named(name, rel)
        if info is None or id(info) in seen:
            return []
        lines = [line for b in info.bases if (line := self.chain(b, info.path, seen | {id(info)}))]
        merged = _c3([*lines, [line[0] for line in lines]], id)
        out = [info, *(merged or {id(c): c for line in lines for c in line}.values())]
        if not seen:
            self._chains[(name, rel)] = out
        return out


# where a library constructor takes its prefix positionally: `Blueprint(name, import_name,
# static_folder, static_url_path, template_folder, url_prefix)`, flask-restful `Api(app, prefix)`
_PREFIX_AT = {
    ("flask", "Blueprint"): 5,
    ("apiflask", "APIBlueprint"): 7,
    ("flask_restful", "Api"): 1,
    ("flask_restx", "Namespace"): 2,
}


def _prefix_arg(call: ast.Call, keyword: str, at: int | None) -> ast.AST | None:
    """A constructor's prefix argument, by keyword or at its position in the library's."""
    if (found := _kwarg(call, keyword)) is not None or at is None:
        return found
    return call.args[at] if len(call.args) > at else None


_LOGIN_SWITCHES = {"LOGIN_DISABLED", "_login_disabled"}


def _login_disabled(f: TreeFile, tree: ast.AST | None) -> bool:
    """A file may set flask-login's `LOGIN_DISABLED`: Python read as code (a literal false
    doesn't, a computed value may), other config line by line outside comments."""
    if tree is None:
        lines = (
            line for line in f.text.splitlines() if not line.lstrip().startswith(("#", ";", "//"))
        )
        return any(_LOGIN_DISABLED.search(line) for line in lines)
    values = _switch_values(getattr(tree, "body", []))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            values += [k.value for k in n.keywords if k.arg in _LOGIN_SWITCHES]
            if len(n.args) > 1 and _const_str(n.args[0]) in _LOGIN_SWITCHES:
                values.append(n.args[1])  # `config.setdefault("LOGIN_DISABLED", True)`
        elif isinstance(n, ast.Dict):
            values += [
                v for k, v in zip(n.keys, n.values, strict=True) if _const_str(k) in _LOGIN_SWITCHES
            ]
    return any(not isinstance(v, ast.Constant) or bool(v.value) for v in values)


def _switch_values(body: list[ast.stmt]) -> list[ast.AST]:
    """What a statement list may leave `LOGIN_DISABLED` bound to: its last assignment there,
    what a block after it may assign, and what class and function bodies assign."""
    last: list[ast.AST] = []
    after: list[ast.AST] = []  # assigned in blocks since the last assignment
    scopes: list[ast.AST] = []
    for s in body:
        if (
            isinstance(s, ast.Assign | ast.AnnAssign)
            and s.value is not None
            and any(
                (isinstance(x, ast.Name) and x.id in _LOGIN_SWITCHES)
                or (isinstance(x, ast.Attribute) and x.attr in _LOGIN_SWITCHES)
                or (isinstance(x, ast.Subscript) and _const_str(x.slice) in _LOGIN_SWITCHES)
                for x in _targets(s)
            )
        ):
            last, after = [s.value], []
        elif isinstance(s, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            scopes += _switch_values(s.body)
        else:
            for _, value in ast.iter_fields(s):  # `if`/`else`, `try`, `for`, `with`, `match`
                if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                    after += _switch_values(value)
                elif isinstance(value, list):
                    for h in value:
                        if isinstance(h, ast.excepthandler | ast.match_case):
                            after += _switch_values(h.body)
    return [*last, *after, *scopes]


def _flask_index(
    sources: list[_Source], files: list[TreeFile], modules: _Modules | None = None
) -> _FlaskIndex:
    index = _FlaskIndex(modules=modules)
    trees = {s.file.rel: s.tree for s in sources}
    # a test module's switch (`app.config["LOGIN_DISABLED"] = True`) runs only under its tests
    index.login_disabled = any(
        _login_disabled(f, trees.get(f.rel))
        for f in files
        if (f.path.suffix in _CONFIG_SUFFIXES or f.name.startswith(".env"))
        and not _test_module(f.rel)
    )
    parsed = {s.file.rel for s in sources}
    index.unparsed = [
        f.rel for f in files if f.path.suffix == ".py" and f.text and f.rel not in parsed
    ]
    for src in sources:
        rel, imports_flask = src.file.rel, src.imports_flask

        for node in ast.walk(src.tree):
            if isinstance(node, ast.ImportFrom):
                mod = _resolve_import(rel, node.module, node.level)
                if any(a.name == "*" for a in node.names) and (
                    node.level or (modules is not None and modules.local(mod))
                ):
                    index.starred.setdefault(rel, []).append(mod)
                for alias in node.names:
                    index.imported.setdefault(rel, {})[alias.asname or alias.name] = mod
                    if alias.asname:
                        index.renamed.setdefault(rel, {})[alias.asname] = alias.name
        # module-level from-imports in source order: which binding of a name is the last
        # one, and where a star import sits beside an explicit import of the same name
        events: list[tuple[int, str, str]] = []
        for node, _ in _module_statements(src.tree.body, False):
            if not isinstance(node, ast.ImportFrom):
                continue
            mod = _resolve_import(rel, node.module, node.level)
            for alias in node.names:
                events.append((node.lineno, alias.name, mod))
        index.import_order[rel] = sorted(events)
        # a module's `__all__` gates what a star import of it binds
        exported: set[str] = set()
        for node, _ in _module_statements(src.tree.body, False):
            if not isinstance(node, ast.Assign | ast.AugAssign | ast.AnnAssign):
                continue
            targets = _targets(node)
            if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
                continue
            value = node.value
            if isinstance(node, ast.AugAssign) and isinstance(node.value, ast.Call):
                value = node.value.args[0] if node.value.args else None
            elements = _str_list(value) if value is not None else None
            if elements is None:
                exported.clear()  # not a readable list: treat the module as having no __all__
                break
            exported.update(elements)
        if exported:
            index.exports[rel] = frozenset(exported)
        renamed = index.renamed.get(rel, {})
        for node, scope in _scoped(src.tree):
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                for t in _targets(node):
                    # a known guard's name, or an alias of one, rebound: `login_required = ..`
                    if isinstance(t, ast.Name) and (t.id in KNOWN_GUARDS or t.id in renamed):
                        index.assigned.setdefault(t.id, []).append(
                            _Function(rel, node.lineno, [], node.value)
                        )
                    elif isinstance(t, ast.Attribute) and t.attr in _VIEW_LISTS:
                        index.rebound.add((_last(_dotted(t.value)), t.attr))
            if (
                imports_flask
                and isinstance(node, ast.Assign | ast.AnnAssign)
                and isinstance(node.value, ast.Call)
            ):
                # `bp: Blueprint = FlaskBlueprint(..)` with `Blueprint as FlaskBlueprint`
                ctor = _last(_dotted(node.value.func))
                ctor = renamed.get(ctor, ctor)
                kind = FLASK_RECEIVER_CTORS.get(ctor)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets if kind else ():
                    if isinstance(t, ast.Name):
                        index.receivers[t.id] = kind  # type: ignore[assignment]
                    elif isinstance(t, ast.Attribute):
                        index.receivers[t.attr] = kind  # type: ignore[assignment]
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                decos = [_deco_name(d, renamed) for d in node.decorator_list]
                # a method is reached through its class, never by a bare name
                into = index.methods if isinstance(scope, ast.ClassDef) else index.functions
                owner = (
                    scope.name if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef) else ""
                )
                into.setdefault(node.name, []).append(
                    _Function(rel, node.lineno, decos, node, owner)
                )
            elif isinstance(node, ast.ClassDef):
                info = _class_info(node, rel, renamed)
                index.classes.setdefault(node.name, info)
                index.class_defs.setdefault(node.name, []).append(info)
            if not isinstance(node, ast.Call):
                continue
            fn = _dotted(node.func)
            last = _last(fn)
            index.called.add(last)
            if last == "register_blueprint" and node.args and "." in fn:
                index.registered.setdefault(rel, set()).add(
                    (_last(fn.rsplit(".", 1)[0]), _last(_dotted(node.args[0])))
                )
    # which function DEFINITIONS the checkout calls (not bare names: an unrelated module
    # calling its own `register()` must not make an uncalled flask helper look mounted)
    for src in sources:
        for node in ast.walk(src.tree):
            if not isinstance(node, ast.Call):
                continue
            callee = index.resolve_fn(_dotted(node.func), src.file.rel)
            if callee is not None and callee.node is not None:
                index.called_defs.add(id(callee.node))

    # a checkout subclass of Blueprint or Flask: `bp = VersionedBlueprint("notes", ..)`
    for src in sources:
        for node in ast.walk(src.tree):
            if isinstance(node, ast.Assign | ast.AnnAssign) and isinstance(node.value, ast.Call):
                kind = index.kind(_dotted(node.value.func), src.file.rel)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets if kind else ():
                    if isinstance(t, ast.Name) and t.id not in index.receivers:
                        index.receivers[t.id] = kind
    # a receiver a checkout factory returns: `bp = make_blueprint("notes")`
    for src in sources:
        for node in ast.walk(src.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                made = index.resolve_fn(_dotted(node.value.func), src.file.rel)
                text = ast.unparse(made.node) if made is not None and made.node else ""
                kind = "blueprint" if "Blueprint(" in text else "app" if "Flask(" in text else None
                for t in node.targets if kind else ():
                    if isinstance(t, ast.Name) and t.id not in index.receivers:
                        index.receivers[t.id] = kind
    return index


def _class_info(node: ast.ClassDef, rel: str, renamed: dict[str, str] | None = None) -> _Class:
    deco = partial(_deco_name, renamed=renamed)
    bases = [_dotted(b) for b in node.bases]
    info = _Class(
        rel,
        node.lineno,
        bases,
        [deco(d) for d in node.decorator_list],
        any(_VIEW_BASE.search(b) for b in bases),
        node=node,
    )
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if isinstance(t, ast.Name) and t.id == "decorators":
                    info.decorators = _names_in(stmt.value, deco)
                    info.sets_decorators = True
                elif isinstance(t, ast.Name) and t.id == "method_decorators":
                    info.method_all, info.method_per = _method_decorators(stmt.value, deco)
                    info.sets_method_decorators = True
        elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and (
            stmt.name in FLASK_VERBS or stmt.name == "dispatch_request"
        ):
            info.methods[stmt.name] = _Function(
                rel, stmt.lineno, [deco(d) for d in stmt.decorator_list]
            )
    for stmt in node.body:
        # `post = get`: the same method answers another verb
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name):
            for t in stmt.targets:
                name = _dotted(t)
                if name in FLASK_VERBS and stmt.value.id in info.methods:
                    info.methods.setdefault(name, info.methods[stmt.value.id])
    return info


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


def _class_rows(
    cls_name: str,
    patterns: list[tuple[str, bool]],
    receiver: str | None,
    reg_path: str,
    reg_line: int,
    index: _FlaskIndex,
) -> list[_Row]:
    chain = index.chain(cls_name, reg_path)
    if not chain:
        # a library's view class (`GraphQLView`): its methods and guards aren't in the checkout
        return [
            _mark(
                _row(RouteFamily.FLASK, "ANY", p, cls_name, reg_path, reg_line, [], [], []),
                receiver,
                dynamic,
                reg_path,
            )
            for p, dynamic in patterns
        ]
    methods: dict[str, _Function] = {}
    for c in reversed(chain):
        methods.update(c.methods)
    reader = index.reader(chain[0].path)
    # `decorators` and `method_decorators` are class attributes: the nearest class's list wins,
    # and only flask-restful/restx Resources read `method_decorators`
    decorators = next((c for c in chain if c.sets_decorators), None)
    resource = any(
        index.imported.get(c.path, {}).get(b.split(".")[0], b).startswith(_RESTFUL)
        for c in chain
        for b in c.bases
    )
    method_decorators = next((c for c in chain if c.sets_method_decorators), None)
    method_decorators = method_decorators if resource else None
    as_view: list[str] = list(decorators.decorators if decorators else [])
    dispatch = method_decorators.method_all if method_decorators else []
    per_verb: dict[str, list[str]] = dict(method_decorators.method_per) if method_decorators else {}
    # what a list set outside the class body holds is unknown: it may hold a cache
    rebound = any(
        (c.node.name, attr) in index.rebound
        for c in chain
        if c.node is not None
        for attr in _VIEW_LISTS
    )
    cls_guards, cls_unguards = _flask_split(as_view, reader, outer_first=False)
    more, fewer = _flask_split(dispatch, reader, outer_first=False)
    cached = rebound or _caches(as_view)
    cls_guards = [] if rebound else _unique(cls_guards + ([] if cached else more))
    cls_unguards += fewer
    cached = cached or _caches(dispatch)
    base_guards: list[str] = []
    verbs = [v for v in methods if v != "dispatch_request"] or (
        ["dispatch_request"] if "dispatch_request" in methods else []
    )
    # a library base may answer methods of its own (`GraphQLView`, a library `Resource`)
    known_bases = {"MethodView", "View", "Resource", "MethodResource", "object"}
    unread = any(
        index.class_named(b, c.path) is None and _last(b) not in known_bases
        for c in chain
        for b in c.bases
    )
    if unread or not verbs:
        verbs.append("dispatch_request")
    rows = []
    for verb in verbs:
        fn = methods.get(verb, _Function(chain[0].path, chain[0].line, []))
        guards, unguards = _flask_split(fn.decos, reader)
        pv_guards, pv_unguards = _flask_split(per_verb.get(verb, []), reader, outer_first=False)
        owner = next((c for c in chain if verb in c.methods), chain[0])
        # a class decorator wraps the methods of its own class only
        own_guards, own_unguards = _flask_split(owner.class_decos, reader)
        guards, unguards = _unique(guards + own_guards), unguards + own_unguards
        if cached:
            guards, pv_guards = [], []
        elif _caches(per_verb.get(verb, [])):
            guards = []
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
            row.handler_path, row.handler_line = owner.path, fn.line
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
    guards, unguards = _flask_split(
        fn.decos if fn else [], index.reader(fn.path if fn else reg_path)
    )
    row = _row(
        RouteFamily.FLASK,
        ",".join(methods) if methods else "GET",
        pattern,
        name,
        reg_path,
        reg_line,
        guards,
        [],
        unguards,
    )
    if fn:
        row.handler_path, row.handler_line = fn.path, fn.line
    return _mark(row, receiver, dynamic, reg_path)


def _view_target(view: ast.AST, deco: Callable[[ast.AST], str]) -> tuple[str, list[str]]:
    """(handler, names wrapped around it) for `f`, `guard(f)`, `lambda: f(...)`, `mod.f`."""
    if isinstance(view, ast.Lambda):
        body = view.body
        return (_dotted(body.func) if isinstance(body, ast.Call) else _dotted(body)), []
    if isinstance(view, ast.Call) and view.args:
        inner, wraps = _view_target(view.args[0], deco)
        return inner, [deco(view.func), *wraps]
    return _dotted(view), []


class _FlaskFile:
    """One file's flask registrations. A file also importing fastapi spells verb decorators the
    same way, so there only route / add_url_rule / add_resource on known flask receivers count,
    and a name it binds to a non-flask constructor shadows the global one."""

    def __init__(self, src: _Source, index: _FlaskIndex, consts: dict[str, str]) -> None:
        self.src, self.index, self.consts = src, index, consts
        self.rel = src.file.rel
        self.deco = partial(_deco_name, renamed=index.renamed.get(self.rel, {}))
        self.chain: tuple[ast.AST, ...] = ()  # the functions the node being read sits in
        self.unplaced = False  # it registers on a receiver handed to a helper nothing calls
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
        # `def register(application): @application.route(..)`: an app handed to a helper
        owner = next((f for f in reversed(self.chain) if recv in _param_names(f)), None)
        handed = owner is not None and _last(dotted) in ("route", "add_url_rule")
        if handed and not self._called(owner):
            self.unplaced = True  # where a helper nothing calls mounts is unknown
        return recv if (recv in self.index.receivers or self.src.imports_flask or handed) else None

    def _called(self, fn: ast.AST | None) -> bool:
        """Something calls THIS function — the resolved definition, not any function sharing
        its bare name — or pytest does (a test or a fixture)."""
        name = getattr(fn, "name", "")
        tested = _test_module(self.rel) and (
            name.startswith("test")
            or any(_last(_dotted(d)).endswith("fixture") for d in getattr(fn, "decorator_list", []))
        )
        return tested or (fn is not None and id(fn) in self.index.called_defs)

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        # `ast.walk`'s order, with the functions each node sits in
        todo: deque[tuple[ast.AST, tuple[ast.AST, ...]]] = deque([(self.src.tree, ())])
        while todo:
            node, self.chain = todo.popleft()
            self.unplaced = False
            found: list[_Row] = []
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                found += self._decorated(node)
            if isinstance(node, ast.Call):
                found += self._call(node)
            for r in found:
                r.dynamic = r.dynamic or self.unplaced
            rows += found
            inner = (
                (*self.chain, node)
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                else self.chain
            )
            todo.extend((child, inner) for child in ast.iter_child_nodes(node))
        return rows

    def _decorated(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[_Row]:
        rows: list[_Row] = []
        for i, d in enumerate(node.decorator_list):
            if not isinstance(d, ast.Call):
                continue
            dn = _dotted(d.func)
            attr, recv = _last(dn), self.receiver(dn)
            if recv is None or attr not in ("route", *FLASK_VERBS):
                continue
            if attr != "route" and (self.mixed or recv not in self.index.receivers):
                continue
            # flask-restx's `@ns.route("/", "/<int:id>")` takes several URLs
            rules = (d.args if isinstance(node, ast.ClassDef) else d.args[:1]) or [
                _kwarg(d, "rule")
            ]
            patterns = [
                (p, dynamic)
                for p, dynamic in (_pattern(r, self.consts) for r in rules)
                if p is not None
            ]
            if not patterns:
                continue
            if isinstance(node, ast.ClassDef):
                rows += _class_rows(node.name, patterns, recv, self.rel, d.lineno, self.index)
                continue
            methods = [attr.upper()] if attr != "route" else self.methods(_kwarg(d, "methods"))
            # the route registers the function as the decorators below it leave it
            below = [self.deco(x) for x in node.decorator_list[i + 1 :]]
            fn = _Function(self.rel, node.lineno, below)
            rows += [
                _function_row(
                    node.name, fn, pattern, dynamic, methods, recv, self.rel, d.lineno, self.index
                )
                for pattern, dynamic in patterns
            ]
        return rows

    def methods(self, value: ast.AST | None) -> list[str]:
        """A route's `methods=`: a literal list, a module constant, else unknown (`ANY`)."""
        if value is None:
            return []
        if isinstance(value, ast.Name):
            value = next(
                (
                    n.value
                    for n in self.src.tree.body
                    if isinstance(n, ast.Assign) and value.id in {_dotted(t) for t in n.targets}
                ),
                value,
            )
        if isinstance(value, ast.List | ast.Tuple | ast.Set):
            return [m.upper() for m in _str_list(value)] or ["ANY"]
        return ["ANY"]

    def bound(self, name: str) -> ast.AST | None:
        """What a name in this file is bound to, when that is one value: `view = X.as_view()`."""
        values = [
            n.value
            for n in ast.walk(self.src.tree)
            if isinstance(n, ast.Assign) and name in {_dotted(t) for t in n.targets}
        ]
        return values[0] if len(values) == 1 else None

    def _library_call(self, call: ast.Call) -> bool:
        """A call to no checkout function or class, nor a Flask constructor: a library builds it."""
        name = _dotted(call.func)
        return (
            _last(name) not in FLASK_RECEIVER_CTORS
            and self.index.resolve_fn(name, self.rel) is None
            and self.index.class_named(name, self.rel) is None
        )

    def _library_routes(
        self,
        node: ast.Call,
        prefix: ast.AST | None,
        default: str,
        what: str,
        recv: str | None = None,
    ) -> list[_Row]:
        """A placeholder for the routes a library mounts (a blueprint it builds, Flask-Admin's
        views): their paths and guards aren't in the checkout."""
        mount = _pattern(prefix, self.consts)[0] if prefix is not None else default
        pattern = _flask_join(mount or "", f"[{what[:80]}]")
        row = _row(RouteFamily.FLASK, "ANY", pattern, what[:200], self.rel, node.lineno, [], [], [])
        return [_mark(row, recv, True, self.rel)]

    def _call(self, node: ast.Call) -> list[_Row]:
        if isinstance(node.func, ast.Call) and node.args:
            # `app.route("/export", methods=["POST"])(export)`, `bp.delete("/wipe")(wipe)`
            inner = node.func
            name = _dotted(inner.func)
            attr, recv = _last(name), self.receiver(name)
            if recv is None or attr not in ("route", *FLASK_VERBS) or not inner.args:
                return []
            pattern, dynamic = _pattern(inner.args[0], self.consts)
            if pattern is None:
                return []
            target, wraps = _view_target(node.args[0], self.deco)
            methods = [attr.upper()] if attr != "route" else self.methods(_kwarg(inner, "methods"))
            row = _function_row(
                target or "<view>",
                self.index.resolve_fn(target, self.rel) if target else None,
                pattern,
                dynamic,
                methods,
                recv,
                self.rel,
                node.lineno,
                self.index,
            )
            more, fewer = _flask_split(wraps, self.index.reader(self.rel))
            row.guards, row.unguards = _unique(more + row.guards), sorted({*fewer, *row.unguards})
            row.judge()
            return [row]
        fn = _dotted(node.func)
        attr = _last(fn)
        if attr == "Admin" and self.index.imported.get(self.rel, {}).get(attr, fn).startswith(
            "flask_admin"
        ):
            app = _dotted(node.args[0]) if node.args else None
            return self._library_routes(node, _kwarg(node, "url"), "/admin", "Flask-Admin", app)
        recv = (
            self.receiver(fn)
            if attr in ("add_url_rule", "add_resource", "register_blueprint")
            else None
        )
        if recv is None:
            return []
        if attr == "register_blueprint":
            arg = node.args[0] if node.args else None
            built = self.bound(arg.id) if isinstance(arg, ast.Name) else arg
            if not (isinstance(built, ast.Call) and self._library_call(built)):
                return []
            prefix = _kwarg(node, "url_prefix")
            return self._library_routes(node, prefix, "", ast.unparse(arg), recv)
        if attr == "add_resource":
            if not node.args:
                return []
            cls = _dotted(node.args[0])
            patterns = [
                (p, dynamic)
                for p, dynamic in (_pattern(a, self.consts) for a in node.args[1:])
                if p
            ]
            return (
                _class_rows(cls, patterns, recv, self.rel, node.lineno, self.index) if cls else []
            )
        pattern, dynamic = _pattern(
            node.args[0] if node.args else _kwarg(node, "rule"), self.consts
        )
        if pattern is None:
            return []
        view = _kwarg(node, "view_func")
        if view is None and len(node.args) >= 3:
            view = node.args[2]
        methods = self.methods(_kwarg(node, "methods"))
        if view is None:
            # `add_url_rule("/x", "export")` with the view bound by `@app.endpoint("export")`
            endpoint = _const_str(node.args[1] if len(node.args) > 1 else _kwarg(node, "endpoint"))
            found = next(
                (
                    n
                    for n in ast.walk(self.src.tree)
                    if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                    and any(
                        isinstance(d, ast.Call)
                        and _last(_dotted(d.func)) == "endpoint"
                        and d.args
                        and _const_str(d.args[0]) == endpoint
                        for d in n.decorator_list
                    )
                ),
                None,
            )
            decos = [self.deco(d) for d in found.decorator_list] if found else []
            fn_info = _Function(self.rel, found.lineno, decos) if found else None
            name = found.name if found else endpoint or "<view>"
            return [
                _function_row(
                    name,
                    fn_info,
                    pattern,
                    dynamic,
                    methods,
                    recv,
                    self.rel,
                    node.lineno,
                    self.index,
                )
            ]
        if isinstance(view, ast.Name) and (value := self.bound(view.id)) is not None:
            view = value  # the register_api pattern: `view = ItemAPI.as_view("item")`
        # `login_required(ItemAPI.as_view("item"))`
        wrappers: list[str] = []
        inner_view = view
        while (
            isinstance(inner_view, ast.Call)
            and not (
                isinstance(inner_view.func, ast.Attribute) and inner_view.func.attr == "as_view"
            )
            and len(inner_view.args) == 1
        ):
            wrappers.append(self.deco(inner_view.func))
            inner_view = inner_view.args[0]
        if (
            isinstance(inner_view, ast.Call)
            and isinstance(inner_view.func, ast.Attribute)
            and inner_view.func.attr == "as_view"
        ):
            cls = _dotted(inner_view.func.value)
            rows = _class_rows(cls, [(pattern, dynamic)], recv, self.rel, node.lineno, self.index)
            more, fewer = _flask_split(wrappers, self.index.reader(self.rel))
            for row in rows:
                row.guards, row.unguards = (
                    _unique(more + row.guards),
                    sorted({*fewer, *row.unguards}),
                )
                row.judge()
            return rows
        target, wraps = _view_target(view, self.deco)
        row = _function_row(
            target or "<view>",
            self.index.resolve_fn(target, self.rel) if target else None,
            pattern,
            dynamic,
            methods,
            recv,
            self.rel,
            node.lineno,
            self.index,
        )
        wrap_guards, wrap_unguards = _flask_split(wraps, self.index.reader(self.rel))
        if wrap_guards or wrap_unguards:
            row.guards = _unique(wrap_guards + row.guards)
            row.unguards = sorted(set(wrap_unguards + row.unguards))
            row.judge()
        return [row]


def _flask(
    sources: list[_Source],
    files: list[TreeFile],
    config: list[TreeFile],
    modules: _Modules | None = None,
) -> tuple[list[_Row], bool]:
    """The flask rows, and whether the tree uses flask at all (so no rows is a gap, not clean);
    `config` also holds the config files that may set `LOGIN_DISABLED`."""
    if not any(s.imports_flask for s in sources):
        return [], False
    index = _flask_index(sources, config, modules)
    shared, own = _string_constants(files), file_constants(files)
    modules = [s.file.rel for s in sources]
    seen: dict[str, dict[str, str]] = {}

    def consts(rel: str) -> dict[str, str]:
        # each module's constants, its imported ones (`from .paths import EXPORT_PATH`) first
        if rel not in seen:
            imported = {
                name: f"{module}.{index.renamed.get(rel, {}).get(name, name)}"
                for name, module in index.imported.get(rel, {}).items()
            }
            seen[rel] = constants_for(
                rel,
                own,
                imported,
                lambda m: next((f for f in modules if _same_module(f, m)), None),
                shared,
            )
        return seen[rel]

    rows = [
        part
        for s in sources
        for r in _FlaskFile(s, index, consts(s.file.rel)).rows()
        for part in _options_apart(r)
    ]
    prefix_of = _flask_prefixes(sources, consts, index)
    for row in rows:
        if (found := prefix_of(row.path, row.receiver)) is not None:
            prefix, dynamic = found
            row.pattern = _flask_join(prefix, row.pattern)
            row.dynamic = row.dynamic or dynamic
    return rows, True


def _options_apart(row: _Row) -> list[_Row]:
    """Flask's auth decorators let OPTIONS through unchecked (flask-login, flask-jwt-extended,
    flask-httpauth): a route serving OPTIONS itself has an OPTIONS row with no guard."""
    verbs = row.method.split(",")
    if "OPTIONS" not in verbs or not row.guarded:
        return [row]
    options = replace(
        row,
        method="OPTIONS",
        guards=[],
        scope_guards=[],
        unguards=list(row.unguards),
        family_gaps=list(row.family_gaps),
        options_exempt=True,
    )
    rest = ",".join(v for v in verbs if v != "OPTIONS")
    return [replace(row, method=rest), options] if rest else [options]


def _flask_join(prefix: str, rule: str) -> str:
    """Flask's join of a mount's prefix and a rule: one `/` between them."""
    if not prefix:
        return rule
    return f"{prefix.rstrip('/')}/{rule.lstrip('/')}" if rule else prefix


_ROOT: _Key = ("", "")  # what a WSGI dispatcher mounts apps under


def _flask_prefixes(
    sources: list[_Source], consts: Callable[[str], dict[str, str]], index: _FlaskIndex
) -> Callable[[str, str | None], tuple[str, bool] | None]:
    """The prefix each blueprint, flask-restful `Api` and flask-restx `Namespace` mounts its
    routes under (`url_prefix=`, `register_blueprint`, `Api(bp, prefix=)`, `add_namespace`),
    and whether it's computed; by the (module, name) a receiver is bound at, through imports
    and aliases. One bound or mounted more than one way has no prefix known."""
    own: dict[_Key, set[tuple[str, bool]]] = {}
    mounts: dict[_Key, set[tuple[_Key | None, str | None, bool]]] = {}
    # a namespace's own path, which applies only once an `Api` adds it
    namespaces: dict[_Key, set[tuple[str, bool]]] = {}
    files = [s.file.rel for s in sources]

    def key(rel: str, name: str) -> _Key | None:
        """Where a receiver named in `rel` is bound: here, or the module it is imported from."""
        if (rel, name) in own or (rel, name) in namespaces:
            return rel, name
        module = index.imported.get(rel, {}).get(name)
        if module is None:
            return (rel, name) if "." not in name else None
        original = index.renamed.get(rel, {}).get(name, name)
        where = [f for f in files if _same_module(f, module)]
        return (where[0], original) if len(where) == 1 else None

    unplaced = False  # a registration whose blueprint we can't name
    calls: list[tuple[str, ast.Call, str, dict[str, list[str]]]] = []
    for src in sources:
        rel = src.file.rel
        loops = {
            _dotted(n.target): [_dotted(e) for e in n.iter.elts]
            for n in ast.walk(src.tree)
            if isinstance(n, ast.For)
            and isinstance(n.target, ast.Name)
            and isinstance(n.iter, ast.List | ast.Tuple | ast.Set)
        }
        assigned = {
            id(n.value): [_last(_dotted(t)) for t in _targets(n)]
            for n in ast.walk(src.tree)
            if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None
        }
        renamed = index.renamed.get(rel, {})

        def text(node: ast.AST | None, rel: str = rel) -> tuple[str | None, bool]:
            return _pattern(node, consts(rel)) if node is not None else (None, False)

        for node in ast.walk(src.tree):
            if not isinstance(node, ast.Call):
                continue
            fn = _dotted(node.func)
            ctor = written = renamed.get(_last(fn), _last(fn))
            ctor = {"blueprint": "Blueprint", "app": "Flask"}.get(index.kind(fn, rel) or "", ctor)
            library = (index.modules.full(fn, rel) if index.modules else "").split(".")[0]
            at = _PREFIX_AT.get((library, written))

            targets = [(rel, t) for t in assigned.get(id(node), [])]
            if ctor == "namespace" and "." in fn and targets and node.args:
                # flask-restx's `ns = api.namespace("todos")`: added to that Api
                path, dynamic = text(_kwarg(node, "path") or (node.args[2:3] or [None])[0])
                name, name_dynamic = text(node.args[0])
                for t in targets:
                    namespaces.setdefault(t, set()).add(
                        (path if path is not None else f"/{name or ''}", dynamic or name_dynamic)
                    )
                calls.append((rel, node, "namespace", loops))
                continue
            if ctor == "Blueprint" and targets:
                prefix, dynamic = text(_prefix_arg(node, "url_prefix", at))
                for t in targets:
                    own.setdefault(t, set()).add((prefix or "", dynamic))
            elif ctor == "Namespace" and targets and node.args:
                path, dynamic = text(_prefix_arg(node, "path", at))
                name, name_dynamic = text(node.args[0])
                for t in targets:
                    namespaces.setdefault(t, set()).add(
                        (path if path is not None else f"/{name or ''}", dynamic or name_dynamic)
                    )
            elif ctor == "Api" and targets:
                prefix, dynamic = text(_prefix_arg(node, "prefix", at))
                for t in targets:
                    own.setdefault(t, set()).add((prefix or "", dynamic))
                calls.append((rel, node, "Api", loops))
            elif ctor == "DispatcherMiddleware" or (
                ctor in ("register_blueprint", "add_namespace", "init_app") and "." in fn
            ):
                calls.append((rel, node, ctor, loops))
    # mounts, once every receiver's binding is known
    for rel, node, ctor, loops in calls:
        fn = _dotted(node.func)
        if ctor == "Api":
            app = node.args[0] if node.args else _kwarg(node, "app")
            targets = [
                (rel, _last(_dotted(t)))
                for n in ast.walk(next(s.tree for s in sources if s.file.rel == rel))
                if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is node
                for t in _targets(n)
            ]
            parent = key(rel, _dotted(app)) if app is not None else None
            for t in targets if app is not None else ():
                mounts.setdefault(t, set()).add((parent, None, False))
            continue
        if ctor == "DispatcherMiddleware":
            # werkzeug's `DispatcherMiddleware(front, {"/api": api.wsgi_app})` mounts apps
            apps = node.args[1] if len(node.args) > 1 else _kwarg(node, "mounts")
            pairs = zip(apps.keys, apps.values, strict=True) if isinstance(apps, ast.Dict) else []
            for k, v in pairs:
                child = key(rel, _dotted(v).removesuffix(".wsgi_app")) if k is not None else None
                if child is not None:
                    mounts.setdefault(child, set()).add((_ROOT, *_pattern(k, consts(rel))))
            continue
        receiver = key(rel, _last(fn.rsplit(".", 1)[0]))
        if ctor == "namespace":
            for n in ast.walk(next(s.tree for s in sources if s.file.rel == rel)):
                if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is node:
                    for t in _targets(n):
                        mounts.setdefault((rel, _last(_dotted(t))), set()).add(
                            (receiver, None, False)
                        )
            continue
        if ctor == "init_app":
            if node.args and receiver is not None:
                mounts.setdefault(receiver, set()).add(
                    (key(rel, _dotted(node.args[0])), None, False)
                )
            continue
        if not node.args:
            continue
        path_node = _kwarg(node, "url_prefix" if ctor == "register_blueprint" else "path")
        if path_node is None and ctor == "add_namespace" and len(node.args) > 1:
            path_node = node.args[1]
        path, dynamic = _pattern(path_node, consts(rel)) if path_node is not None else (None, False)
        child = _dotted(node.args[0])
        # `for bp in (users, orders): app.register_blueprint(bp, ..)`
        children = (
            loops.get(child, [child]) if isinstance(node.args[0], ast.Name | ast.Attribute) else []
        )
        keys = [key(rel, c) for c in children]
        unplaced |= not keys or None in keys
        for k in keys:
            if k is not None:
                mounts.setdefault(k, set()).add((receiver, path, dynamic))

    def resolve(name: _Key, seen: frozenset[_Key]) -> tuple[str, bool]:
        up = mounts.get(name, set())
        mine = own.get(name) or (namespaces.get(name) if up else None) or {("", False)}
        prefix, dynamic = min(mine)
        dynamic = dynamic or len(mine) > 1
        if not up or name in seen:
            # a blueprint some registration we can't read may mount
            return prefix, dynamic or name in seen or (unplaced and name in own)
        parent, path, path_dynamic = min(up, key=repr)
        above, above_dynamic = resolve(parent, seen | {name}) if parent else ("", True)
        # `register_blueprint(bp, url_prefix=..)` replaces the blueprint's own prefix
        joined = _flask_join(above, path if path is not None else prefix) or ""
        return joined, dynamic or path_dynamic or above_dynamic or len(up) > 1

    resolved = {k: resolve(k, frozenset()) for k in {*own, *mounts}}

    def prefix_of(rel: str, receiver: str | None) -> tuple[str, bool] | None:
        k = key(rel, receiver) if receiver else None
        return resolved.get(k) if k is not None else None

    return prefix_of


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
_OPTIONAL = "optional:"
# methods that write into the object they are called on
_MUTATORS = re.compile(r"^(set\w*|update|pop|clear|setdefault|__setitem__|append|extend|insert)$")
# a dependency named for the authenticated caller
_CALLER_DEPENDENCY = re.compile(
    r"(?i)(^|_)(current|authenticated|logged_?in|signed_?in)(_[a-z]+)*_?"
    r"(user|account|member|principal|identity|subject|superuser|admin)s?"
    r"(_(authorizer|dependency|dep))?$"
)
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
    # a returned name passes the request on only when every assignment to it (in this
    # scope — nested scopes keep their own bindings) stores the onward call's response:
    # a branch assigning a rejection response to that same name can be the returned value
    passed_through: set[str] = set()
    reassigned: set[str] = set()
    for n in _own_nodes(fn):
        if not isinstance(n, ast.Assign):
            continue
        names = [t.id for t in n.targets if isinstance(t, ast.Name)]
        onward_call = (
            isinstance(n.value, ast.Await)
            and isinstance(n.value.value, ast.Call)
            and _dotted(n.value.value.func) == onward
        )
        if onward_call:
            passed_through.update(names)
        else:
            reassigned.update(names)
    passed_through -= reassigned
    for n in _own_nodes(fn):
        if isinstance(n, ast.Raise):
            return True
        if isinstance(n, ast.Return) and n.value is not None:
            value = n.value.value if isinstance(n.value, ast.Await) else n.value
            if isinstance(value, ast.Name) and value.id in passed_through:
                continue  # returning the stored onward response passes the request on
            if not (isinstance(value, ast.Call) and _dotted(value.func) == onward):
                return True
    return False


def _terminates(body: list[ast.stmt]) -> bool:
    """Every path through `body` ends in a return or a raise (never falls off its end)."""
    last = body[-1] if body else None
    if isinstance(last, ast.Return | ast.Raise):
        return True
    if isinstance(last, ast.If):
        return _terminates(last.body) and _terminates(last.orelse)
    if isinstance(last, ast.With | ast.AsyncWith):
        return _terminates(last.body)
    if isinstance(last, ast.Try):
        if _terminates(last.finalbody):
            return True
        normal = last.orelse or last.body
        return _terminates(normal) and all(_terminates(h.body) for h in last.handlers)
    return False


def _pos_of(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _depends_calls(node: ast.AST | None, rel: str) -> list[tuple[str, ast.AST]]:
    """The `Depends(…)` calls of a `dependencies=[…]` argument, with the file they are in."""
    calls = node.elts if isinstance(node, ast.List | ast.Tuple) else []
    return [
        (rel, c) for c in calls if isinstance(c, ast.Call) and _last(_dotted(c.func)) in _DEPENDS
    ]


def _lets_missing_in(call: ast.Call) -> bool:
    """`Authenticator(required=False)`, `HTTPBearer(auto_error=False)`, `optional=True`."""
    return any(
        isinstance(k.value, ast.Constant)
        and (
            (k.arg in ("required", "auto_error") and k.value.value is False)
            or (k.arg == "optional" and k.value.value is True)
        )
        for k in call.keywords
    )


def _db_session_middleware(name: str) -> bool:
    return bool(_DB_SESSION_RX.match(re.sub(r"(?i)_?middleware$", "", name)))


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
    if not _guard_named(_last(name)) or _db_session_middleware(_last(name)):
        return False
    fn = modules.function(name, rel, functions)
    return fn is None or fn.node is None or _middleware_rejects(fn.node)


@dataclass
class _Mount:
    parent: _Key
    prefix: str
    guards: list[str]
    unguards: list[str]
    calls: list[tuple[str, ast.AST]] = field(default_factory=list)  # its `Depends(…)` nodes


@dataclass
class _Receiver:
    prefix: str = ""
    guards: list[str] = field(default_factory=list)
    unguards: list[str] = field(default_factory=list)
    calls: list[tuple[str, ast.AST]] = field(default_factory=list)


@dataclass
class _Scope:
    prefix: str
    guards: list[str]
    unguards: list[str]
    calls: list[tuple[str, ast.AST]] = field(default_factory=list)


def _chains(
    key: _Key,
    receivers: dict[_Key, _Receiver],
    mounts: dict[_Key, list[_Mount]],
    middleware: dict[_Key, list[str]],
    seen: frozenset[_Key] = frozenset(),
) -> list[_Scope]:
    """Every way a receiver's routes are reached: each mount's prefix and the guards it adds."""
    recv = receivers[key]
    own = _Scope(
        recv.prefix, [*recv.guards, *middleware.get(key, [])], list(recv.unguards), recv.calls
    )
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
                    [*up.calls, *m.calls, *own.calls],
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
        self.guard_instances: set[_Key] = set()
        self._identities: dict[int, bool] = {}
        self.fail_open_instances: set[_Key] = set()
        self.fail_open: set[str] = set()  # schemes built with auto_error=False: a missing
        # credential yields None, not a 401
        self.receivers: dict[_Key, _Receiver] = {}
        self.mounts: dict[_Key, list[_Mount]] = {}
        self.middleware: dict[_Key, list[str]] = {}
        self._bind()
        self._ownership: PyOwnership | None = None
        self._facts: dict[tuple[int, frozenset[str]], HandlerFacts] = {}

    def ownership(self) -> PyOwnership:
        """The handlers' ownership reader, built on first use over the same parsed tree."""
        if self._ownership is None:
            from traust_core.v1.providers.python_ownership import PyCode, PyOwnership

            trees = {s.file.rel: s.tree for s in self.index.sources}
            texts = {s.file.rel: s.file.text for s in self.index.sources}
            code = PyCode(trees, self.modules, texts)
            self._ownership = PyOwnership(code, self._callers, self._depends_on)
        return self._ownership

    def _param_dependencies(
        self, fn: ast.AST, rel: str
    ) -> list[tuple[str, ast.Call, str, ast.AST | None]]:
        """Each parameter's `Depends(...)` (in its default or `Annotated` alias), with the file it
        is resolved from and the parameter's annotation."""
        args = getattr(fn, "args", None)
        if args is None:
            return []
        positional = [*args.posonlyargs, *args.args]
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = [
            *zip(positional, defaults, strict=True),
            *zip(args.kwonlyargs, args.kw_defaults, strict=True),
        ]
        out = []
        for param, default in pairs:
            ann, where = _unquoted(param.annotation), rel
            if isinstance(ann, ast.Name | ast.Attribute) and (
                found := self.index.alias(_dotted(ann), rel)
            ):
                ann, where = found
            if isinstance(ann, ast.Subscript) and _last(_dotted(ann.value)) == "Annotated":
                parts = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
                out += [
                    (param.arg, e, where, parts[0])
                    for e in parts[1:]
                    if isinstance(e, ast.Call) and _last(_dotted(e.func)) in _DEPENDS
                ]
            if isinstance(default, ast.Call) and _last(_dotted(default.func)) in _DEPENDS:
                out.append((param.arg, default, rel, ann))
        return out

    def _callers(self, target: Target) -> tuple[set[str], set[str]]:
        """The parameters a refusing authentication dependency fills (the caller), and the
        `Request` ones (whose `.user` is the caller)."""
        callers = set()
        for name, call, where, ann in self._param_dependencies(target.fn, target.rel):
            dependency = self._dependency(call, ann)
            guards, unguards = self._classify([(dependency, where)])
            bare = dependency.removeprefix("Security:").split("[")[0]
            # the authentication dependency itself, not one that merely depends on it
            # (`requested_owner(owner = Query(…), user = Depends(get_current_user))`)
            if (
                guards
                and not unguards
                and not dependency.startswith(_OPTIONAL)
                and (self._guard_factory(call) or self._identifies(bare, where))
            ):
                callers.add(name)
        args = target.fn.args
        requests = {
            a.arg
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
            if _last(_dotted(_unquoted(a.annotation))) in ("Request", "HTTPConnection")
        }
        return callers, requests

    def _guard_factory(self, call: ast.AST) -> bool:
        """`Depends(OrgPolicyGuard(…))`: a guard built inline by a checkout guard class or
        factory, trusted as a module-level guard instance is."""
        if not isinstance(call, ast.Call):
            return False
        target = call.args[0] if call.args else _kwarg(call, "dependency")
        if not isinstance(target, ast.Call):
            return False
        ctor = _last(_dotted(target.func))
        return (
            (ctor in self.index.classes or ctor in self.functions)
            and bool(GUARD_RX.search(ctor))
            and not NON_ENFORCING_RX.search(ctor)
            and not _lets_missing_in(target)
        )

    def _identifies(self, bare: str, rel: str) -> bool:
        """Whether a dependency's value is who is calling: a security scheme or guard instance
        (its credential), or a function whose every return is built from credentials."""
        if (
            _FASTAPI_SECURITY.match(_last(bare))
            or _last(bare) in self.security
            or self.modules.key(bare, rel, self.guard_instances) is not None
        ):
            return True
        fn = self.index.callee(bare, rel) if bare else None
        return fn is not None and fn.node is not None and self._identity(fn.node, fn.path)

    def _identity(self, fn: ast.AST, rel: str, depth: int = 0) -> bool:
        """`fn` returns the caller: every return is built from its credentials (an authenticating
        dependency's value; for a caller-named function, its `Request`), never from request data
        (`return owner` with `owner = Query(…)`), and is never `None`."""
        if id(fn) in self._identities:
            return self._identities[id(fn)]
        self._identities[id(fn)] = False  # a cycle identifies nothing
        deps = {
            name: (call, where, ann) for name, call, where, ann in self._param_dependencies(fn, rel)
        }
        named = bool(_CALLER_DEPENDENCY.search(getattr(fn, "name", "")))
        trusted: set[str] = set()
        untrusted: set[str] = set()
        args = fn.args  # type: ignore[attr-defined]
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            if a.arg in ("self", "cls"):
                continue
            if a.arg in deps:
                call, where, ann = deps[a.arg]
                dependency = self._dependency(call, ann)
                bare = dependency.removeprefix("Security:").split("[")[0]
                if dependency.startswith(_OPTIONAL):
                    untrusted.add(a.arg)
                elif self._guard_factory(call) or (
                    depth < _DEPTH and self._credential(bare, where, depth + 1)
                ):
                    trusted.add(a.arg)
            elif _last(_dotted(_unquoted(a.annotation))) in ("Request", "HTTPConnection"):
                (trusted if named else untrusted).add(a.arg)
            else:
                untrusted.add(a.arg)  # a path, query or body value
        own = list(_own_nodes(fn))
        aliases: dict[str, set[str]] = {}  # names bound to one object (`u = user`)

        def group(name: str) -> set[str]:
            return aliases.setdefault(name, {name})

        def untrust(names: set[str]) -> None:
            for name in names:
                untrusted.update(group(name))
                trusted.difference_update(group(name))

        def names_in(node: ast.AST | None) -> set[str]:
            return {x.id for x in ast.walk(node) if isinstance(x, ast.Name)} if node else set()

        for n in sorted((n for n in own if isinstance(n, ast.Assign | ast.AnnAssign)), key=_pos_of):
            if n.value is None:
                continue
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            names = {x.id for t in targets if isinstance(t, ast.Name) for x in [t]}
            used = names_in(n.value)
            if isinstance(n.value, ast.Name):
                joined = group(n.value.id) | set().union(*(group(x) for x in names))
                for x in joined:
                    aliases[x] = joined
            if used & untrusted:
                untrust(names)
            elif used & trusted:
                trusted |= names
        # writing request data into a trusted object (`user.update(owner=owner)`,
        # `user["owner"] = owner`, `setattr(user, …)`) makes it no longer the caller
        for n in own:
            written: set[str] = set()
            value: ast.AST | None = None
            if isinstance(n, ast.Assign | ast.AugAssign):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    base = t
                    while isinstance(base, ast.Attribute | ast.Subscript):
                        base = base.value
                    if base is not t and isinstance(base, ast.Name):
                        written.add(base.id)
                value = n.value
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                base = n.func.value
                if isinstance(base, ast.Name) and _MUTATORS.match(n.func.attr):
                    written.add(base.id)
                    value = n
            elif isinstance(n, ast.Call) and _dotted(n.func) in ("setattr", "object.__setattr__"):
                if n.args and isinstance(n.args[0], ast.Name):
                    written.add(n.args[0].id)
                    value = n
            if written and names_in(value) - written & untrusted:
                untrust(written)
            elif written and names_in(value) - written - trusted:
                untrust(written)  # anything but credentials written in
        returns = [n for n in own if isinstance(n, ast.Return | ast.Yield)]
        generator = any(isinstance(n, ast.Yield | ast.YieldFrom) for n in own)
        body = getattr(fn, "body", [])
        ok = (
            bool(returns)
            and (generator or _terminates(body))
            and all(
                r.value is not None
                and not (isinstance(r.value, ast.Constant) and r.value.value is None)
                and not ({x.id for x in ast.walk(r.value) if isinstance(x, ast.Name)} & untrusted)
                and bool({x.id for x in ast.walk(r.value) if isinstance(x, ast.Name)} & trusted)
                for r in returns
            )
        )
        self._identities[id(fn)] = ok
        return ok

    def _credential(self, bare: str, rel: str, depth: int) -> bool:
        """A dependency whose value is a credential or the caller."""
        if (
            _FASTAPI_SECURITY.match(_last(bare))
            or _last(bare) in self.security
            or self.modules.key(bare, rel, self.guard_instances) is not None
        ):
            return True
        fn = self.index.callee(bare, rel) if bare else None
        return fn is not None and fn.node is not None and self._identity(fn.node, fn.path, depth)

    def _depends_on(self, target: Target) -> tuple[list[tuple[str | None, Target]], list[Opaque]]:
        """What `target`'s parameters depend on, each with the parameter it fills: the checkout
        functions, resolved exactly, and the checkout code we can't follow."""
        return self._resolve_dependencies(
            [
                (where, call, ann, name)
                for name, call, where, ann in self._param_dependencies(target.fn, target.rel)
            ]
        )

    def _resolve_dependencies(
        self, calls: list[tuple[str, ast.AST, ast.AST | None, str | None]]
    ) -> tuple[list[tuple[str | None, Target]], list[Opaque]]:
        code = self.ownership().code
        found: list[tuple[str | None, Target]] = []
        opaque: list[Opaque] = []
        for where, call, ann, param in calls:
            if not isinstance(call, ast.Call):
                continue
            dependency = call.args[0] if call.args else _kwarg(call, "dependency")
            resolved = code.dependency(where, dependency if dependency is not None else ann)
            if isinstance(resolved, list):
                found += [(param, r) for r in resolved]
            elif resolved is not None:
                opaque.append(resolved)
        return found, opaque

    def _ownership_facts(
        self, call: ast.Call, fn: ast.AST, rel: str, pattern: str, scope: _Scope
    ) -> HandlerFacts:
        """Per route: its handler with the route's and its routers' own dependencies."""
        ids = frozenset(path_params(pattern))
        calls = [*_depends_calls(_kwarg(call, "dependencies"), rel), *scope.calls]
        key = (id(fn), ids, id(call), tuple(id(c) for _, c in calls))
        if key not in self._facts:
            from traust_core.v1.providers.python_ownership import Target

            own = self.ownership()
            handler = Target(self.index.paths.get(id(fn), rel), fn)  # type: ignore[arg-type]
            deps, opaque = self._resolve_dependencies(
                [(where, c, None, None) for where, c in calls]
            )
            self._facts[key] = own.handler(handler, set(ids), deps, opaque)
        return self._facts[key]

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
        module_level = {id(s) for src in self.index.sources for s in src.tree.body}
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
                elif (
                    id(node) in module_level
                    and (ctor in self.index.classes or ctor in self.functions)
                    and GUARD_RX.search(ctor)
                    and not NON_ENFORCING_RX.search(ctor)
                ):
                    # a module-level guard built by a checkout class or factory (`Authenticator(…)`)
                    keys = {(rel, n) for n in names}
                    self.guard_instances |= keys
                    if _lets_missing_in(node.value):
                        self.fail_open_instances |= keys
                if ctor not in ctors:
                    continue
                guards, unguards = self._dependencies(_kwarg(node.value, "dependencies"), rel)
                prefix = _const_str(_kwarg(node.value, "prefix")) or ""
                for name in names:
                    calls = _depends_calls(_kwarg(node.value, "dependencies"), rel)
                    self.receivers[(rel, name)] = _Receiver(prefix, guards, unguards, calls)
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
        if _guard_named(name) and not _db_session_middleware(name) and _middleware_rejects(fn):
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
                    _Mount(
                        parent,
                        _const_str(prefix_node) or "",
                        guards,
                        unguards,
                        _depends_calls(_kwarg(node, "dependencies"), rel),
                    )
                )

    def _dependency(self, call: ast.Call, annotation: ast.AST | None) -> str:
        target = call.args[0] if call.args else _kwarg(call, "dependency")
        name = _dotted(target if target is not None else annotation)
        if isinstance(target, ast.Call) and _lets_missing_in(target):
            return f"{_OPTIONAL}{name}"  # `get_user(required=False)` lets a missing caller in
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
            if name.startswith(_OPTIONAL):
                guards.append(name.removeprefix(_OPTIONAL))
                unguards.append(f"{FAIL_OPEN}:{name.removeprefix(_OPTIONAL)}")
                continue
            bare = name.removeprefix("Security:").split("[")[0]
            if UNGUARD_RX.search(bare):
                unguards.append(name)
            elif (
                name.startswith("Security:")
                or (GUARD_RX.search(bare) and not _DB_SESSION_RX.match(_last(bare)))
                or _FASTAPI_SECURITY.match(_last(bare))
                or _last(bare) in self.security
                or self.modules.key(bare, rel, self.guard_instances) is not None
            ):
                guards.append(name)
                if _last(bare) in self.fail_open or (
                    self.modules.key(bare, rel, self.fail_open_instances) is not None
                ):
                    unguards.append(f"{FAIL_OPEN}:{name}")
            elif depth < _DEPTH and bare not in seen:
                fn = self.index.callee(bare, rel) if bare else None
                if fn is not None and fn.node is not None:
                    g, u = self._classify(self._params(fn.node, fn.path), depth + 1, seen | {bare})
                    raises = _raises(fn.node)
                    if raises:
                        # it refuses the missing credential itself
                        u = [x for x in u if not x.startswith(f"{FAIL_OPEN}:")]
                    if (
                        not g
                        and raises
                        and _CALLER_DEPENDENCY.search(_last(bare))
                        and self._identity(fn.node, fn.path)
                    ):
                        # `get_current_user(request)`: refuses, and returns who is calling
                        guards.append(bare)
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
                if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                    facts = self._ownership_facts(call, fn, rel, row.pattern, scope)
                    row.own(facts, self.ownership().code.fields)
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
        bare = [r for r in members if not r.guarded and not r.options_exempt]
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
    """Every family a guard string matches — one guard can carry several (a role check
    is also a permission check), and each counts toward its own asymmetry."""
    return {
        fam for g in row.guards + row.scope_guards for fam, rx in GUARD_FAMILIES if rx.search(g)
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
    # a Python file named like a test (`ab_test.py`) may still serve routes: kept, flagged
    tests = {f.rel for f in files if _TEST_NAME.search(f.name.lower())}
    files = [f for f in files if f.rel not in tests or f.path.suffix == ".py"]
    py = [f for f in files if f.path.suffix == ".py"]
    sources, unparsed = _parsed(py)
    index, consts = _PyIndex.of(sources, unparsed), _string_constants(py)
    flask_rows, uses_flask = _flask(sources, py, files, index.modules)
    fastapi_rows, uses_fastapi = _fastapi(index, consts)
    aiohttp_rows, uses_aiohttp = _aiohttp(index, consts)
    # they build on this module
    from traust_core.v1.providers.django_routes import django_rows
    from traust_core.v1.providers.express_routes import express_rows
    from traust_core.v1.providers.java_routes import java_rows
    from traust_core.v1.providers.ruby_routes import callback_asymmetries, ruby_rows
    from traust_core.v1.providers.rust_routes import rust_rows

    js_rows, uses_express, parsed = express_rows(files)
    java, rust, ruby = java_rows(files), rust_rows(files), ruby_rows(files)
    rows = [
        *_go(files),
        *django_rows(index, consts),
        *flask_rows,
        *fastapi_rows,
        *aiohttp_rows,
        *js_rows,
        *java.rows,
        *rust.rows,
        *ruby.rows,
    ]
    for r in rows:
        r.test_path = r.test_path or r.path in tests
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
    gaps += _unclassified_ownership(rows)
    rows.sort(
        key=lambda r: (
            not r.judgement_required,
            not r.asymmetry,
            rank(r.ownership, r.ownership_evidence),
            r.path,
            r.line,
        )
    )
    return RouteGuardFact(
        routes=tuple(r.model() for r in rows),
        asymmetries=tuple(asymmetries),
        coverage_gaps=tuple(gaps),
    )


# Frameworks with an ownership reader: an unclassified route there is a handler it couldn't read.
_OWNERSHIP_READ = frozenset(
    {RouteFamily.SPRING, RouteFamily.JAX_RS, RouteFamily.FASTAPI, RouteFamily.EXPRESS,
     RouteFamily.RAILS, RouteFamily.AXUM, RouteFamily.ACTIX}
)  # fmt: skip
_OWNERSHIP_GAP = " ownership"


def ownership_gap(gap: CoverageGap) -> bool:
    """A gap in classifying the ownership of enumerated routes, not in enumerating them."""
    return gap.system.endswith(_OWNERSHIP_GAP)


def _authenticates(guard: str) -> bool:
    """A guard name that still names a guard once state-only words (session, cookie) are gone."""
    return bool(GUARD_RX.search(NON_ENFORCING_RX.sub("", guard)))


def _unclassified_ownership(rows: Sequence[_Row]) -> list[CoverageGap]:
    """Live authenticated id routes no ownership reader classified, named per family:
    unclassified is a gap, never a blank that reads as nothing to flag."""
    by_family: dict[str, list[_Row]] = {}
    for r in rows:
        guards = [] if r.unguards else [*r.guards, *r.scope_guards]
        if (
            r.ownership is None
            and not r.test_path
            and any(_authenticates(g) for g in guards)
            and not any(privileged_only(g) for g in guards)
            and path_params(r.pattern)
        ):
            by_family.setdefault(r.family, []).append(r)
    return [
        CoverageGap(
            system=f"{family}{_OWNERSHIP_GAP}",
            reason=f"{family}: object ownership is UNCLASSIFIED on {len(unread)} authenticated "
            "id route(s), "
            + (
                "whose handler the ownership reader couldn't resolve"
                if family in _OWNERSHIP_READ
                else "with no ownership reader for this framework yet"
            )
            + "; check by hand that each ties the object it acts on to the caller (CWE-639)",
            count=len(unread),
            paths=tuple(dict.fromkeys(RepoPath(r.path) for r in unread))[:20],
            evidence=RepoPath(unread[0].path),
        )
        for family, unread in by_family.items()
    ]


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
