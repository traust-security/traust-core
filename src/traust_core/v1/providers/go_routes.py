"""Go HTTP routes and the guards on each, parsed with tree-sitter: net/http's `ServeMux`,
gorilla/mux, chi, gin, echo and fiber. A route's router is followed through groups, sub-routers,
mounts and the functions it is passed to; middleware a router `Use`s guards the routes it covers
(gin, fiber and echo groups: only those registered after it)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.route_plumbing import (
    _guards_in,
    _mark,
    _Row,
    _row,
    _unguards_in,
    _unique,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import go_parser as parser
from traust_core.v1.providers.tree import TreeFile

_FRAMEWORKS = (
    ("gin", re.compile(r"^github\.com/gin-gonic/gin$")),
    ("echo", re.compile(r"^github\.com/labstack/echo(/v\d+)?$")),
    ("chi", re.compile(r"^github\.com/go-chi/chi(/v\d+)?$")),
    ("mux", re.compile(r"^github\.com/gorilla/mux$")),
    ("fiber", re.compile(r"^github\.com/gofiber/fiber(/v\d+)?$")),
    ("http", re.compile(r"^net/http$")),
)
_CONSTRUCTORS = {
    "gin": {"New", "Default"},
    "echo": {"New"},
    "chi": {"NewRouter", "NewMux"},
    "mux": {"NewRouter"},
    "fiber": {"New"},
    "http": {"NewServeMux"},
}
# `Use` covers only the routes added after it: gin and fiber build each route's chain as it is
# added, and so does an echo group (the root `Echo`'s `Use` runs for every request)
_ORDERED = {"gin", "fiber", "echo"}
# what adds middleware to a router: `Use` everywhere, `Bind`/`BindFunc` in PocketBase's router
_USES = {"Use", "Bind", "BindFunc"}
_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "connect", "trace"}
_ANY = {"any", "all"}
_TYPED = re.compile(
    r"\b(?P<pkg>gin|echo|chi|mux|fiber|http)\.(?P<type>Engine|RouterGroup|IRouter|IRoutes|Echo|"
    r"Group|Router|Mux|App|ServeMux)\b"
)
_METHOD_PATTERN = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S.*)$")
_CONVERSIONS = {"http.HandlerFunc", "http.Handler", "echo.WrapHandler", "gin.WrapF", "gin.WrapH"}
# middleware that loads or reads the caller without refusing anyone (`loadAuthToken`,
# `OptionalAdmin`): no guard, whatever else its name says
_LOADS = re.compile(r"(?i)^(load|parse|extract|attach|populate|optional|maybe|try|lookup)")
_PATHS = ("interpreted_string_literal", "raw_string_literal", "identifier", "selector_expression",
          "binary_expression", "call_expression")  # fmt: skip
_FUNCS = ("function_declaration", "method_declaration", "func_literal")
_MAX_DEPTH = 8
_MAX_CONTEXTS = 32
_MAX_FIELD_SITES = 8  # a field assigned in more places than this is no single router


@dataclass(frozen=True)
class _Ctx:
    """Where a router puts its routes: the prefix, the guards over them, its framework."""

    prefix: str = ""
    guards: tuple[str, ...] = ()
    unguards: tuple[str, ...] = ()
    kind: str = ""
    known: bool = False
    dynamic: bool = False
    # `app.Use("/api", mw)` (fiber): a guard over the routes under a path only
    scoped: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def under(
        self, prefix: str = "", guards: list[str] | None = None, unguards: list[str] | None = None
    ) -> _Ctx:
        return replace(
            self,
            prefix=_join(self.prefix, prefix),
            guards=tuple(_unique([*self.guards, *(guards or [])])),
            unguards=tuple(sorted({*self.unguards, *(unguards or [])})),
        )


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path
    if not path:
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")


class _Source(Parsed):
    def __init__(self, file: TreeFile, root: Node, data: bytes) -> None:
        super().__init__(file, root, data)
        self.dir = str(PurePosixPath(file.rel).parent)
        self.imports: dict[str, str] = {}
        for spec in walk(root):
            if spec.type != "import_spec":
                continue
            path = self.string(spec.child_by_field_name("path")) or ""
            name = spec.child_by_field_name("name")
            alias = self.text(name) if name is not None else _package_name(path)
            if alias not in ("_", "."):
                self.imports[alias] = path
        self.kinds = {
            alias: kind
            for alias, path in self.imports.items()
            for kind, rx in _FRAMEWORKS
            if rx.match(path)
        }

    def string(self, node: Node | None) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "interpreted_string_literal":
            return "".join(
                self.text(c)
                for c in node.named_children
                if c.type in ("interpreted_string_literal_content", "escape_sequence")
            )
        if node.type == "raw_string_literal":
            return self.text(node)[1:-1]
        return None


def _package_name(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]):
        return parts[-2]
    return parts[-1] if parts else ""


def _unwrap(node: Node | None) -> Node | None:
    """The expression inside `(x)`, `&x` and `*x`."""
    while node is not None and node.type in ("parenthesized_expression", "unary_expression"):
        if node.type == "unary_expression" and node.child_by_field_name("operator") is not None:
            op = node.child_by_field_name("operator")
            if op is not None and op.type not in ("&", "*"):
                break
        node = node.child_by_field_name("operand") or (
            node.named_children[0] if node.named_children else None
        )
    return node


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args else []


def _field(src: _Source, call: Node) -> tuple[Node | None, str]:
    fn = call.child_by_field_name("function")
    if fn is None or fn.type != "selector_expression":
        return None, ""
    return fn.child_by_field_name("operand"), src.text(fn.child_by_field_name("field"))


def _enclosing(node: Node | None) -> Node | None:
    node = node.parent if node is not None else None
    while node is not None and node.type not in _FUNCS:
        node = node.parent
    return node


def _params(src: _Source, fn: Node) -> list[tuple[str, str]]:
    """(name, type text) of each parameter, in order."""
    plist = fn.child_by_field_name("parameters")
    out = []
    for p in plist.named_children if plist is not None else []:
        if p.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        kind = src.text(p.child_by_field_name("type"))
        names = [src.text(c) for c in p.named_children if c.type == "identifier"]
        out += [(n, kind) for n in names] or [("", kind)]
    return out


@dataclass
class _Checkout:
    sources: list[_Source]
    modules: dict[str, str] = field(default_factory=dict)  # module path -> directory
    functions: dict[tuple[str, str], tuple[_Source, Node]] = field(default_factory=dict)
    methods: dict[str, list[tuple[_Source, Node, str]]] = field(default_factory=dict)
    calls: dict[tuple[str, str], list[tuple[_Source, Node]]] = field(default_factory=dict)
    fields: dict[tuple[str, str], list[tuple[_Source, Node]]] = field(default_factory=dict)
    package_values: dict[tuple[str, str], tuple[_Source, Node]] = field(default_factory=dict)

    def index(self, files: list[TreeFile]) -> None:
        for f in files:
            if f.name == "go.mod" and (m := re.search(r"(?m)^module\s+(\S+)", f.text)):
                self.modules[m[1]] = str(PurePosixPath(f.rel).parent)
        for src in self.sources:
            for n in walk(src.root):
                if n.type == "function_declaration" and (name := n.child_by_field_name("name")):
                    self.functions.setdefault((src.dir, src.text(name)), (src, n))
                elif n.type == "method_declaration" and (name := n.child_by_field_name("name")):
                    recv = src.text(n.child_by_field_name("receiver"))
                    kind = re.findall(r"\w+", recv)[-1] if re.findall(r"\w+", recv) else ""
                    self.methods.setdefault(src.text(name), []).append((src, n, kind))
                elif n.type == "call_expression":
                    fn = n.child_by_field_name("function")
                    if fn is not None and fn.type == "identifier":
                        self.calls.setdefault((src.dir, src.text(fn)), []).append((src, n))
                    elif fn is not None and fn.type == "selector_expression":
                        operand = fn.child_by_field_name("operand")
                        name = src.text(fn.child_by_field_name("field"))
                        alias = src.text(operand) if operand is not None else ""
                        if (
                            operand is not None
                            and operand.type == "identifier"
                            and (alias in src.imports)
                        ):
                            where = self.directory(src.imports[alias])
                            if where is not None:
                                self.calls.setdefault((where, name), []).append((src, n))
                        self.calls.setdefault(("method", name), []).append((src, n))
                elif n.type == "assignment_statement":
                    left = n.child_by_field_name("left")
                    right = n.child_by_field_name("right")
                    for i, t in enumerate(left.named_children if left is not None else []):
                        values = right.named_children if right is not None else []
                        if t.type == "selector_expression" and i < len(values):
                            key = (src.dir, src.text(t.child_by_field_name("field")))
                            self.fields.setdefault(key, []).append((src, values[i]))
                elif n.type == "keyed_element":
                    kids = n.named_children
                    if len(kids) == 2:
                        key = (src.dir, src.text(_unwrap(kids[0]) or kids[0]))
                        self.fields.setdefault(key, []).append((src, kids[1]))
            for decl in src.root.named_children:
                if decl.type not in ("var_declaration", "const_declaration"):
                    continue
                for spec in walk(decl):
                    if spec.type not in ("var_spec", "const_spec"):
                        continue
                    names = [c for c in spec.named_children if c.type == "identifier"]
                    value = spec.child_by_field_name("value")
                    values = value.named_children if value is not None else []
                    for i, name in enumerate(names):
                        if i < len(values):
                            self.package_values[(src.dir, src.text(name))] = (src, values[i])

    def directory(self, import_path: str) -> str | None:
        """The checkout directory an import path names, through the go.mod module paths."""
        best = max((m for m in self.modules if import_path == m or import_path.startswith(m + "/")),
                   key=len, default=None)  # fmt: skip
        if best is None:
            return None
        rest = import_path[len(best) :].lstrip("/")
        base = self.modules[best]
        return str(PurePosixPath(base) / rest) if rest else base

    def function(self, src: _Source, expr: Node | None) -> tuple[_Source, Node] | None:
        """The checkout function or method an expression names: `listNotes`, `api.ListNotes`,
        `h.GetNote` (a method by name, narrowed by the value's type when more share it)."""
        expr = _unwrap(expr)
        if expr is None:
            return None
        if expr.type == "func_literal":
            return src, expr
        if expr.type == "identifier":
            return self.functions.get((src.dir, src.text(expr)))
        if expr.type != "selector_expression":
            return None
        operand = expr.child_by_field_name("operand")
        name = src.text(expr.child_by_field_name("field"))
        alias = src.text(operand) if operand is not None else ""
        if operand is not None and operand.type == "identifier" and alias in src.imports:
            where = self.directory(src.imports[alias])
            return self.functions.get((where, name)) if where is not None else None
        found = self.methods.get(name, [])
        if len(found) > 1 and operand is not None:
            kind = self.type_of(src, operand)
            found = [m for m in found if m[2] == kind] if kind else found
        return (found[0][0], found[0][1]) if len(found) == 1 else None

    def type_of(self, src: _Source, value: Node) -> str:
        """The named type a value has, where the code says so: a parameter's or receiver's type,
        or a `&T{..}` / `NewT(..)` it is bound to."""
        value = _unwrap(value) or value
        if value.type != "identifier":
            return ""
        name = src.text(value)
        fn = _enclosing(value)
        while fn is not None:
            for p, kind in _params(src, fn):
                if p == name:
                    words = re.findall(r"\w+", kind)
                    return words[-1] if words else ""
            recv = fn.child_by_field_name("receiver")
            if recv is not None and re.search(rf"\b{re.escape(name)}\b", src.text(recv)):
                words = re.findall(r"\w+", src.text(recv))
                return words[-1] if words else ""
            bound = self.binding(src, value, name, fn)
            if bound is not None:
                text = src.text(bound[1])
                if m := re.match(r"&?\s*(?:\w+\.)?(\w+)\s*\{", text):
                    return m[1]
                if m := re.match(r"(?:\w+\.)?New(\w+)\s*\(", text):
                    return m[1]
                return ""
            fn = _enclosing(fn)
        return ""

    def binding(
        self, src: _Source, at: Node, name: str, fn: Node
    ) -> tuple[_Source, Node, Node] | None:
        """(source, statement, value) of the latest `name := ..` / `name = ..` in `fn` before
        `at`, in a block that encloses `at`."""
        body = fn.child_by_field_name("body")
        found = None
        for n in walk(body) if body is not None else []:
            if n.start_byte >= at.start_byte:
                break
            if n.type not in ("short_var_declaration", "assignment_statement", "var_spec"):
                continue
            if n.type != "var_spec" and n.end_byte > at.start_byte:
                continue  # `r := r.Group(..)`: its own value names the one before
            if _enclosing(n) != fn:
                continue
            scope = n.parent
            while scope is not None and scope.type not in ("block", "statement_list"):
                scope = scope.parent
            if scope is not None and not (scope.start_byte <= at.start_byte < scope.end_byte):
                continue
            if n.type == "var_spec":
                names = [src.text(c) for c in n.named_children if c.type == "identifier"]
                value = n.child_by_field_name("value")
                values = value.named_children if value is not None else []
            else:
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                names = [src.text(c) for c in (left.named_children if left is not None else [])]
                values = right.named_children if right is not None else []
            if name in names and names.index(name) < len(values):
                found = (src, n, values[names.index(name)])
        return found

    def returned(self, src: _Source, fn: Node) -> list[Node]:
        return [
            r.named_children[0].named_children[0]
            if r.named_children and r.named_children[0].type == "expression_list"
            else r.named_children[0]
            for r in walk(fn.child_by_field_name("body") or fn)
            if r.type == "return_statement" and r.named_children and _enclosing(r) == fn
        ]

    def string(self, src: _Source, node: Node | None, depth: int = 0) -> str | None:
        """A path as a literal, a constant, or a `+` of those."""
        node = _unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return None
        if (literal := src.string(node)) is not None:
            return literal
        if (
            node.type == "binary_expression"
            and src.text(node.child_by_field_name("operator")) == "+"
        ):
            left = self.string(src, node.child_by_field_name("left"), depth + 1)
            right = self.string(src, node.child_by_field_name("right"), depth + 1)
            return left + right if left is not None and right is not None else None
        if node.type == "call_expression" and _callee(src, node) == "path.Join":
            parts = [self.string(src, a, depth + 1) for a in _args(node)]
            if not parts or any(p is None for p in parts):
                return None
            joined = re.sub(r"/+", "/", "/".join(p for p in parts if p))  # type: ignore[misc]
            return joined.rstrip("/") or ("/" if joined else "")
        key: tuple[str, str] | None = None
        if node.type == "identifier":
            key = (src.dir, src.text(node))
        elif node.type == "selector_expression":
            operand = node.child_by_field_name("operand")
            alias = src.text(operand) if operand is not None else ""
            where = self.directory(src.imports[alias]) if alias in src.imports else None
            key = (where, src.text(node.child_by_field_name("field"))) if where else None
        if key is not None and key in self.package_values:
            vsrc, value = self.package_values[key]
            return self.string(vsrc, value, depth + 1)
        return None


@dataclass
class _Reg:
    """One registration call: the receiver it is on, its methods, path, handler and middleware."""

    call: Node
    receiver: Node
    methods: list[str]
    path: Node | None
    handler: Node
    middleware: list[Node]


class _Matrix:
    def __init__(self, checkout: _Checkout) -> None:
        self.co = checkout
        self.identities: dict[int, set[int]] = {}
        self.resolved: dict[tuple[int, int], list[_Ctx]] = {}
        self.mounts: dict[int, list[tuple[_Source, Node, Node, Node]]] = {}
        self.wrappers: dict[int, list[tuple[_Source, Node]]] = {}
        self.regs: list[tuple[_Source, _Reg]] = []
        for src in checkout.sources:
            for n in walk(src.root):
                if n.type == "call_expression" and (reg := self.registration(src, n)):
                    self.regs.append((src, reg))
        for src, reg in self.regs:
            inner = self.inner(src, reg.handler)
            for ident in self.identity(src, inner):
                self.mounts.setdefault(ident, []).append((src, reg.call, reg.receiver, reg.handler))
        for src in checkout.sources:
            for n in walk(src.root):
                if n.type != "call_expression" or not self.used(n):
                    continue
                _, name = _field(src, n)
                if name in ("Group", "With", "Route", "Mount", "Unbind", *_USES):
                    continue
                for a in _args(n):
                    for ident in self.identity(src, a):
                        self.wrappers.setdefault(ident, []).append((src, n))

    # ---- registrations
    def registration(self, src: _Source, call: Node) -> _Reg | None:
        receiver, name = _field(src, call)
        if receiver is None or not name:
            return None
        args = _args(call)
        lower = name.lower()
        kind = self.kind_hint(src, receiver)
        if name in ("HandleFunc", "Handle", "Mount") and len(args) == 2:
            return _Reg(call, receiver, self.gorilla_methods(src, call), args[0], args[1], [])
        if name in ("HandlerFunc", "Handler") and len(args) == 1:
            path = self.chained(src, receiver, "Path")
            if path is None:
                return None
            return _Reg(call, receiver, self.gorilla_methods(src, call), path, args[0], [])
        if name in ("Method", "MethodFunc") and len(args) == 3:  # chi
            verb = (src.string(args[0]) or "ANY").upper()
            return _Reg(call, receiver, [verb], args[1], args[2], [])
        if name in ("Handle", "Add") and len(args) >= 3 and src.string(args[0]) is not None:
            verb = (src.string(args[0]) or "ANY").upper()  # gin `Handle`, echo/fiber `Add`
            return self.verbs(kind, call, receiver, [verb], args[1:])
        if name == "Match" and len(args) >= 3:
            verbs = [s for a in walk(args[0]) if (s := src.string(a)) is not None] or ["ANY"]
            return self.verbs(kind, call, receiver, [v.upper() for v in verbs], args[1:])
        if lower in _VERBS | _ANY and len(args) >= 2:
            return self.verbs(
                kind, call, receiver, ["ANY" if lower in _ANY else name.upper()], args
            )
        return None

    def verbs(
        self, kind: str, call: Node, receiver: Node, methods: list[str], args: list[Node]
    ) -> _Reg:
        """`r.GET(path, mw.., h)` (gin, fiber: the handler last), `e.GET(path, h, mw..)` (echo)."""
        path, rest = args[0], args[1:]
        if kind == "echo":
            return _Reg(call, receiver, methods, path, rest[0], rest[1:])
        return _Reg(call, receiver, methods, path, rest[-1], rest[:-1])

    def bound(self, src: _Source, call: Node) -> list[Node]:
        """Middleware chained onto a route: PocketBase's `rg.GET(..).Bind(RequireAuth())`."""
        out = []
        node = call
        while (
            node.parent is not None
            and node.parent.type == "selector_expression"
            and node.parent.parent is not None
            and node.parent.parent.type == "call_expression"
        ):
            node = node.parent.parent
            if _field(src, node)[1] in ("Bind", "BindFunc"):
                out += _args(node)
        return out

    def gorilla_methods(self, src: _Source, call: Node) -> list[str]:
        """`.Methods("GET", "POST")` anywhere along a gorilla chain; else every method."""
        methods: list[str] = []
        top = call
        while (
            top.parent is not None
            and top.parent.type == "selector_expression"
            and top.parent.parent is not None
            and top.parent.parent.type == "call_expression"
        ):
            top = top.parent.parent
        for n in walk(top):
            if n.type == "call_expression" and _field(src, n)[1] == "Methods":
                methods += [s.upper() for a in _args(n) if (s := src.string(a)) is not None]
        return _unique(methods) or ["ANY"]

    def chained(self, src: _Source, node: Node | None, step: str) -> Node | None:
        """The argument of `.Path(..)` (or another step) in a receiver chain."""
        while node is not None and node.type == "call_expression":
            operand, name = _field(src, node)
            if name == step and _args(node):
                return _args(node)[0]
            node = operand
        return None

    def kind_hint(self, src: _Source, receiver: Node) -> str:
        kinds = set(src.kinds.values()) - {"http"}
        return next(iter(kinds)) if len(kinds) == 1 else ""

    # ---- what a handler expression wraps
    def inner(self, src: _Source, handler: Node) -> Node:
        """The handler inside wrappers: `auth(http.HandlerFunc(h))` is `h`."""
        node = _unwrap(handler) or handler
        for _ in range(_MAX_DEPTH):
            if node.type != "call_expression":
                break
            args = [a for a in _args(node) if (_unwrap(a) or a).type in _HANDLERISH]
            if not args:
                break
            node = _unwrap(args[-1]) or args[-1]
        return node

    def wrapped(self, src: _Source, handler: Node) -> tuple[list[str], list[str]]:
        """Guards and unguards the wrappers around a handler are named for."""
        names = []
        node = _unwrap(handler) or handler
        for _ in range(_MAX_DEPTH):
            if node.type != "call_expression":
                break
            args = [a for a in _args(node) if (_unwrap(a) or a).type in _HANDLERISH]
            if not args:
                break  # `adminRouter()`: builds a router, wraps no handler
            callee = src.text(node.child_by_field_name("function"))
            if callee not in _CONVERSIONS:
                names.append(callee)
            node = _unwrap(args[-1]) or args[-1]
        return _named(names)

    def middleware(self, src: _Source, nodes: list[Node]) -> tuple[list[str], list[str]]:
        return _named([_middleware_name(src, n) for n in nodes])

    # ---- router identity: the constructor a router value comes from
    def identity(self, src: _Source, expr: Node | None, depth: int = 0) -> set[int]:
        expr = _unwrap(expr)
        if expr is None or depth > _MAX_DEPTH:
            return set()
        key = _id(src, expr)
        if key not in self.identities:
            self.identities[key] = set()  # a cycle reads as no router
            self.identities[key] = self._identity(src, expr, depth)
        return self.identities[key]

    def _identity(self, src: _Source, expr: Node, depth: int) -> set[int]:
        if expr.type == "call_expression":
            if self.constructor(src, expr):
                return {_id(src, expr)}
            found = self.co.function(src, expr.child_by_field_name("function"))
            if found is not None and found[1].type != "func_literal":
                fsrc, fn = found
                return {
                    i for r in self.co.returned(fsrc, fn) for i in self.identity(fsrc, r, depth + 1)
                }
            return set()
        if expr.type == "identifier":
            fn = _enclosing(expr)
            while fn is not None:
                bound = self.co.binding(src, expr, src.text(expr), fn)
                if bound is not None:
                    return self.identity(bound[0], bound[2], depth + 1)
                if any(p == src.text(expr) for p, _ in _params(src, fn)):
                    return set()
                fn = _enclosing(fn)
            value = self.co.package_values.get((src.dir, src.text(expr)))
            return self.identity(value[0], value[1], depth + 1) if value else set()
        if expr.type == "selector_expression":
            name = src.text(expr.child_by_field_name("field"))
            operand = expr.child_by_field_name("operand")
            sites = self.co.fields.get((src.dir, name), [])
            if (operand is not None and src.text(operand) in src.imports) or len(
                sites
            ) > _MAX_FIELD_SITES:
                return set()
            return {i for vsrc, v in sites for i in self.identity(vsrc, v, depth + 1)}
        return set()

    def constructor(self, src: _Source, call: Node) -> str:
        """The framework a router constructor builds (`gin.Default()`), else ""."""
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "selector_expression":
            return ""
        operand = fn.child_by_field_name("operand")
        alias = src.text(operand) if operand is not None else ""
        kind = src.kinds.get(alias) or (alias if alias in _CONSTRUCTORS else "")
        name = src.text(fn.child_by_field_name("field"))
        return kind if name in _CONSTRUCTORS.get(kind, set()) else ""

    def used(self, call: Node) -> bool:
        """The call's value is used (an argument, a binding, a returned or keyed value)."""
        parent = call.parent
        return parent is not None and parent.type in (
            "argument_list",
            "expression_list",
            "keyed_element",
            "literal_element",
            "return_statement",
        )

    # ---- router contexts
    def contexts(self, src: _Source, expr: Node | None, at: Node, depth: int = 0) -> list[_Ctx]:
        """Each place a router expression's routes end up: prefix, guards, framework."""
        expr = _unwrap(expr)
        if expr is None or depth > _MAX_DEPTH:
            return [_Ctx(dynamic=True)]
        key = (_id(src, expr), _id(src, at))
        if key not in self.resolved:
            self.resolved[key] = [_Ctx(dynamic=True)]  # a cycle reads as an unknown router
            out = self._contexts(src, expr, at, depth)
            self.resolved[key] = list(dict.fromkeys(out))[:_MAX_CONTEXTS] or [_Ctx()]
        return self.resolved[key]

    def _contexts(self, src: _Source, expr: Node, at: Node, depth: int) -> list[_Ctx]:
        if expr.type == "call_expression":
            return self.call_contexts(src, expr, depth)
        if expr.type == "identifier":
            return self.name_contexts(src, expr, at, depth)
        if expr.type == "selector_expression":
            operand = expr.child_by_field_name("operand")
            name = src.text(expr.child_by_field_name("field"))
            alias = src.text(operand) if operand is not None else ""
            if alias in src.imports:
                kind = src.kinds.get(alias, "")
                return [_Ctx(kind=kind, known=bool(kind) and name == "DefaultServeMux")]
            assigned = self.co.fields.get((src.dir, name), [])
            if len(assigned) > _MAX_FIELD_SITES:
                assigned = []
            out = [
                c
                for vsrc, v in assigned[:_MAX_CONTEXTS]
                for c in self.contexts(vsrc, v, v, depth + 1)
            ]
            return out or [_Ctx(kind=self.kind_hint(src, expr))]
        return [_Ctx(dynamic=True)]

    def call_contexts(self, src: _Source, call: Node, depth: int) -> list[_Ctx]:
        if kind := self.constructor(src, call):
            return self.mounted(src, call, kind, depth)
        receiver, name = _field(src, call)
        args = _args(call)
        if receiver is not None and name in ("Group", "Route") and args:
            prefix = self.co.string(src, args[0])
            mws = args[1:] if prefix is not None else []
            g, u = self.middleware(src, [m for m in mws if m.type != "func_literal"])
            return [
                replace(
                    c, dynamic=c.dynamic or (prefix is None and args[0].type != "func_literal")
                ).under(prefix or "", g, u)
                for c in self.contexts(src, receiver, call, depth + 1)
            ]
        if receiver is not None and name in ("With", *_USES, "Unbind"):
            g, u = self.middleware(src, args)
            g, u = ([], [*u, *g]) if name == "Unbind" else (g, u)  # an unbound guard: judged
            return [c.under("", g, u) for c in self.contexts(src, receiver, call, depth + 1)]
        if receiver is not None and name == "Subrouter":
            prefix_node = self.chained(src, receiver, "PathPrefix")
            prefix = self.co.string(src, prefix_node) if prefix_node is not None else ""
            root = receiver
            while root.type == "call_expression" and _field(src, root)[0] is not None:
                root = _field(src, root)[0]  # type: ignore[assignment]
            return [
                replace(c, dynamic=c.dynamic or prefix is None).under(prefix or "")
                for c in self.contexts(src, root, call, depth + 1)
            ]
        found = self.co.function(src, call.child_by_field_name("function"))
        if found is not None and found[1].type != "func_literal":
            fsrc, fn = found
            returns = self.co.returned(fsrc, fn)
            out = [c for r in returns for c in self.contexts(fsrc, r, r, depth + 1)]
            if out:
                return out
        return [_Ctx(kind=self.kind_hint(src, call))]

    def mounted(self, src: _Source, call: Node, kind: str, depth: int) -> list[_Ctx]:
        """A router built here, as mounted (`r.Mount("/api", api)`, `Handle("/api/", ..)`)
        and wrapped (`http.ListenAndServe(addr, auth(mux))`) wherever that happens."""
        ident = _id(src, call)
        base = _Ctx(kind=kind, known=True)
        out: list[_Ctx] = []
        for msrc, mcall, receiver, handler in self.mounts.get(ident, []):
            reg = self.registration(msrc, mcall)
            prefix = (msrc.string(reg.path) if reg and reg.path is not None else "") or ""
            prefix = _strip_prefix(msrc, handler, prefix.rstrip("/").removesuffix("/*"))
            g, u = self.wrapped(msrc, handler)
            out += [c.under(prefix, g, u) for c in self.contexts(msrc, receiver, mcall, depth + 1)]
        for wsrc, wcall in self.wrappers.get(ident, []):
            g, u = _guards_in(_callee(wsrc, wcall)), _unguards_in(_callee(wsrc, wcall))
            if g or u:
                out.append(base.under("", g, u))
        return out or [base]

    def name_contexts(self, src: _Source, name: Node, at: Node, depth: int) -> list[_Ctx]:
        ident = src.text(name)
        fn = _enclosing(at)
        while fn is not None:
            bound = self.co.binding(src, at, ident, fn)
            if bound is not None:
                _, stmt, value = bound
                ctxs = self.contexts(src, value, stmt, depth + 1)
                return self.used_middleware(src, fn, ident, stmt, at, ctxs, value)
            names = [p for p, _ in _params(src, fn)]
            if ident in names:
                ctxs = self.param_contexts(src, fn, names.index(ident), depth)
                return self.used_middleware(src, fn, ident, None, at, ctxs, None)
            fn = _enclosing(fn)
        value = self.co.package_values.get((src.dir, ident))
        if value is not None:
            vsrc, v = value
            ctxs = self.contexts(vsrc, v, v, depth + 1)
            uses = [
                c for s in self.co.sources if s.dir == src.dir for c in self.package_uses(s, ident)
            ]
            g, u = self.middleware(src, uses)
            return [c.under("", g, u) for c in ctxs]
        return [_Ctx(kind=self.kind_hint(src, name))]

    def param_contexts(self, src: _Source, fn: Node, index: int, depth: int) -> list[_Ctx]:
        """A router parameter: what each caller passes, or for a closure `r.Route("/x",
        func(r chi.Router) {..})` / `r.Group(func(r chi.Router) {..})`, the router it is given."""
        if fn.type == "func_literal":
            holder = fn.parent.parent if fn.parent is not None else None
            if holder is not None and holder.type == "call_expression":
                receiver, name = _field(src, holder)
                args = _args(holder)
                if receiver is not None and name in ("Route", "Group") and args:
                    prefix = self.co.string(src, args[0]) if args[0] != fn else ""
                    return [
                        replace(c, dynamic=c.dynamic or prefix is None).under(prefix or "")
                        for c in self.contexts(src, receiver, holder, depth + 1)
                    ]
            return [_Ctx(kind=self.param_kind(src, fn, index))]
        name = src.text(fn.child_by_field_name("name"))
        key = ("method", name) if fn.type == "method_declaration" else (src.dir, name)
        out = []
        for csrc, call in self.co.calls.get(key, [])[:_MAX_CONTEXTS]:
            args = _args(call)
            if index < len(args):
                out += self.contexts(csrc, args[index], call, depth + 1)
        return out or [_Ctx(kind=self.param_kind(src, fn, index), known=True)]

    def param_kind(self, src: _Source, fn: Node, index: int) -> str:
        params = _params(src, fn)
        kind = params[index][1] if index < len(params) else ""
        m = _TYPED.search(kind)
        if m is None:
            return ""
        return src.kinds.get(m["pkg"]) or m["pkg"]

    def used_middleware(
        self,
        src: _Source,
        fn: Node,
        ident: str,
        bound: Node | None,
        at: Node,
        ctxs: list[_Ctx],
        value: Node | None,
    ) -> list[_Ctx]:
        """`r.Use(mw)` on the name in this function: before `at` where order counts."""
        root = (
            value is not None
            and value.type == "call_expression"
            and bool(self.constructor(src, value))
        )
        out = []
        for c in ctxs:
            ordered = c.kind in _ORDERED and not (c.kind == "echo" and root)
            guards: list[str] = []
            unguards: list[str] = []
            scoped = list(c.scoped)
            for n in walk(fn.child_by_field_name("body") or fn):
                if n.type != "call_expression" or _enclosing(n) != fn:
                    continue
                receiver, name = _field(src, n)
                if name not in _USES or receiver is None or src.text(_unwrap(receiver)) != ident:
                    continue
                if bound is not None and n.start_byte < bound.end_byte:
                    continue
                if ordered and n.start_byte > at.start_byte:
                    continue
                args = _args(n)
                path = self.co.string(src, args[0]) if args else None
                if path is not None:  # fiber `app.Use("/api", mw)`
                    g, _ = self.middleware(src, args[1:])
                    scoped.append((_join(c.prefix, path), tuple(g)))
                    continue
                g, u = self.middleware(src, args)
                guards, unguards = guards + g, unguards + u
            out.append(replace(c.under("", guards, unguards), scoped=tuple(scoped)))
        return out

    def package_uses(self, src: _Source, ident: str) -> list[Node]:
        return [
            a
            for n in walk(src.root)
            if n.type == "call_expression" and _field(src, n)[1] in _USES
            and src.text(_unwrap(_field(src, n)[0])) == ident
            for a in _args(n)
        ]  # fmt: skip

    # ---- rows
    def rows(self) -> list[_Row]:
        rows = []
        for src, reg in self.regs:
            if self.identity(src, self.inner(src, reg.handler)):
                continue  # a mount: its routes are the mounted router's
            literal = self.co.string(src, reg.path)
            method_in, pattern = "", literal
            if literal is not None and (m := _METHOD_PATTERN.match(literal)):
                method_in, pattern = m[1], m[2]
            ctxs = self.contexts(src, reg.receiver, reg.call)
            known = any(c.known for c in ctxs)
            path = (
                _unwrap(reg.path)
                if reg.path is not None and reg.path.type != "unary_expression"
                else None
            )
            if path is None or path.type not in _PATHS:
                continue  # `db.Get(&out, query)`: no path, no route
            if not _route_like(pattern, known):
                continue  # `cache.Get("key", v)`: not a route
            guards, unguards = self.wrapped(src, reg.handler)
            mg, mu = self.middleware(src, [*reg.middleware, *self.bound(src, reg.call)])
            handler = src.text(reg.handler)[:200]
            for c in ctxs:
                full = _join(c.prefix, pattern if pattern is not None else src.text(reg.path)[:160])
                scoped = [g for p, gs in c.scoped if full.startswith(p) for g in gs]
                for method in [method_in] if method_in else reg.methods:
                    row = _row(
                        RouteFamily.GO_HTTP,
                        method,
                        full or "/",
                        handler,
                        src.file.rel,
                        src.line(reg.call),
                        _unique([*mg, *guards]),
                        _unique([*c.guards, *scoped]),
                        sorted({*mu, *unguards, *c.unguards}),
                    )
                    found = self.co.function(src, self.inner(src, reg.handler))
                    if (
                        found is None
                        and (_unwrap(reg.handler) or reg.handler).type == "call_expression"
                    ):
                        found = self.co.function(src, reg.handler.child_by_field_name("function"))
                    if found is not None:
                        row.handler_path, row.handler_line = (
                            found[0].file.rel,
                            found[0].line(found[1]),
                        )
                    receiver = src.text(reg.receiver)[:80]
                    rows.append(_mark(row, receiver, pattern is None or c.dynamic, src.file.rel))
        return rows


def _route_like(pattern: str | None, known: bool) -> bool:
    """A path a router takes: from `/`, or for a known router `""`, `*` or `:id` too, or a
    computed one."""
    if pattern is None:
        return known
    return pattern.startswith("/") or (known and (pattern == "" or pattern.startswith(("*", ":"))))


_HANDLERISH = ("identifier", "selector_expression", "func_literal", "call_expression")


def _named(names: list[str]) -> tuple[list[str], list[str]]:
    """The guards and unguards middleware names carry; a loader of the caller is no guard."""
    kept = [n for n in names if not _LOADS.match(n.rsplit(".", 1)[-1])]
    return _guards_in(" ".join(kept)), _unguards_in(" ".join(names))


def _callee(src: _Source, call: Node) -> str:
    return src.text(call.child_by_field_name("function"))


def _middleware_name(src: _Source, node: Node) -> str:
    """What a middleware value is named for: the function a call builds it with, or its name."""
    node = _unwrap(node) or node
    if node.type == "call_expression":
        return _callee(src, node)
    if node.type in ("identifier", "selector_expression"):
        return src.text(node)
    return ""


def _strip_prefix(src: _Source, handler: Node, prefix: str) -> str:
    """`http.StripPrefix("/api", mux)` serves `mux`'s routes under its prefix."""
    for n in walk(handler):
        if n.type == "call_expression" and _callee(src, n).endswith("StripPrefix") and _args(n):
            return src.string(_args(n)[0]) or prefix
    return prefix


def _id(src: _Source, node: Node) -> int:
    return hash((src.file.rel, node.start_byte, node.end_byte))


@dataclass
class GoRoutes:
    rows: list[_Row]
    evidence: str | None  # a Go file that registers routes
    parsed: bool  # whether the Go parser was available


_REGISTERS = re.compile(
    r"\.(HandleFunc|Handle|HandlerFunc|Get|Post|Put|Delete|Patch|GET|POST|PUT|DELETE|PATCH|"
    r"Any|All|Method|Match|Add)\("
)


def go_rows(files: list[TreeFile]) -> GoRoutes:
    """The HTTP routes of a checkout's Go sources."""
    go = [f for f in files if f.path.suffix == ".go"]
    evidence = next((f.rel for f in go if _REGISTERS.search(f.text)), None)
    if evidence is None:
        return GoRoutes([], None, True)
    available = parser()
    if available is None:
        return GoRoutes([], evidence, False)
    sources = []
    for f in go:
        data = f.text.encode("utf-8")
        sources.append(_Source(f, available.parse(data).root_node, data))
    checkout = _Checkout(sources)
    checkout.index(files)
    seen: dict[tuple[object, ...], _Row] = {}
    for r in _Matrix(checkout).rows():
        key = (r.method, r.pattern, r.handler, r.path, r.line, tuple(r.guards),
               tuple(r.scope_guards), tuple(r.unguards))  # fmt: skip
        seen.setdefault(key, r)
    return GoRoutes(list(seen.values()), evidence, True)
