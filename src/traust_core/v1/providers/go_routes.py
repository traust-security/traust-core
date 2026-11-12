"""Go HTTP routes and the guards on each, parsed with tree-sitter: net/http's `ServeMux`,
gorilla/mux, chi, gin, echo and fiber. A route's router is followed through groups, sub-routers,
mounts, the place it is served and the functions it is passed to; middleware a router `Use`s
guards the routes it covers (gin, fiber and echo groups: only those registered after it)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.route_plumbing import (
    GUARD_RX,
    NON_ENFORCING_RX,
    UNGUARD_RX,
    _mark,
    _Row,
    _row,
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
# `Use` covers only the routes added after it: gin builds each group's chain when the group is
# made, fiber orders its stack by registration, and so does an echo group (the root `Echo`'s
# `Use` runs for every request)
_ORDERED = {"gin", "fiber", "echo"}
# what adds middleware to a router: `Use` everywhere, `Bind`/`BindFunc` in PocketBase's router
_USES = {"Use", "Bind", "BindFunc"}
_VERBS = {"get", "post", "put", "delete", "patch", "head", "options", "connect", "trace"}
_ANY = {"any", "all"}
_TYPED = re.compile(
    r"\b(?P<pkg>gin|echo|chi|mux|fiber|http)\.(?P<type>Engine|RouterGroup|IRouter|IRoutes|Echo|"
    r"Group|Router|Mux|App|ServeMux)\b"
)
_HANDLER_TYPE = re.compile(r"\bHandler(Func)?\b|^func\s*\(")
_METHOD_CONST = re.compile(
    r"^(?:\w+\.)?Method(Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace)$"
)
_METHOD_PATTERN = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S.*)$")
_HOST_PATTERN = re.compile(r"^[\w.-]+(:\d+)?/")  # Go 1.22 `api.example.com/notes/{id}`
_CONVERSIONS = {"http.HandlerFunc", "http.Handler", "echo.WrapHandler", "gin.WrapF", "gin.WrapH"}
# where a server's handler sits among its arguments: `ListenAndServeTLS(addr, cert, key, h)`
_SERVES = {
    "ListenAndServe": (2, 1),
    "ListenAndServeTLS": (4, 3),
    "Serve": (2, 1),
    "ServeTLS": (4, 1),
}
_DEFAULT_MUX = hash("net/http.DefaultServeMux")
# a library call that hands the handler it is given on to the request path
_PASSES = re.compile(r"(Handler|HandlerFunc|Strip\w*|Timeout\w*|Wrap\w*|Chain|Then\w*|Use)$")
# middleware that sets response headers, whatever `secure` says
_HEADERS = re.compile(r"(?i)^secure(_?headers?)?$")
# a router's own methods: never a wrapper around it
_ROUTER_STEPS = {"Group", "With", "Route", "Mount", "Unbind", "Subrouter", "PathPrefix", *_USES}
# middleware that loads or reads the caller without refusing anyone (`loadAuthToken`,
# `OptionalAdmin`): no guard, whatever else its name says
_LOADS = re.compile(r"(?i)^(load|parse|extract|attach|populate|optional|maybe|try|lookup)")
_PATHS = ("interpreted_string_literal", "raw_string_literal", "identifier", "selector_expression",
          "binary_expression", "call_expression")  # fmt: skip
_FUNCS = ("function_declaration", "method_declaration", "func_literal")
_MAX_DEPTH = 24
_MAX_CONTEXTS = 128
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
    methods: tuple[str, ...] = ()  # gorilla `r.Methods("GET").Subrouter()`

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
    """The expression inside `(x)`, `&x`, `*x` and a composite literal's element."""
    while node is not None and node.type in (
        "parenthesized_expression",
        "unary_expression",
        "literal_element",
        "variadic_argument",
    ):
        if node.type == "unary_expression":
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


def _callee(src: _Source, call: Node) -> str:
    return src.text(call.child_by_field_name("function"))


def _name(src: _Source, node: Node | None, depth: int = 0) -> str:
    """The dotted name an expression calls or names, without its arguments:
    `cors.New(opts).Handler` is `cors.New.Handler`."""
    node = _unwrap(node)
    if node is None or depth > _MAX_DEPTH:
        return ""
    if node.type in ("identifier", "field_identifier", "package_identifier"):
        return src.text(node)
    if node.type == "selector_expression":
        base = _name(src, node.child_by_field_name("operand"), depth + 1)
        field_ = src.text(node.child_by_field_name("field"))
        return f"{base}.{field_}" if base else field_
    if node.type == "call_expression":
        return _name(src, node.child_by_field_name("function"), depth + 1)
    if node.type in ("index_expression", "generic_type", "type_instantiation_expression"):
        return _name(src, node.named_children[0] if node.named_children else None, depth + 1)
    return ""


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


def _receiver_type(src: _Source, fn: Node) -> str:
    words = re.findall(r"\w+", src.text(fn.child_by_field_name("receiver")))
    return words[-1] if words else ""


def _id(src: _Source, node: Node) -> int:
    return hash((src.file.rel, node.start_byte, node.end_byte))


def _scope(n: Node) -> tuple[int, int]:
    """The byte range a binding statement is visible in: its enclosing block."""
    scope = n.parent
    while scope is not None and scope.type not in ("block", "statement_list", "source_file"):
        scope = scope.parent
    return (scope.start_byte, scope.end_byte) if scope is not None else (0, 1 << 62)


def _named(names: list[str]) -> tuple[list[str], list[str]]:
    """The guards and unguards middleware names carry. A loader of the caller or of a session
    is no guard (`loadAuthToken`, `sessions.Sessions`, `scs.LoadAndSave`)."""
    guards, unguards = [], []
    for name in names:
        if not name:
            continue
        if UNGUARD_RX.search(name):
            unguards.append(name)
            continue
        last = name.rsplit(".", 1)[-1]
        if _LOADS.match(last) or _HEADERS.match(last):
            continue
        if GUARD_RX.search(NON_ENFORCING_RX.sub("", name)):
            guards.append(name)
    return _unique(guards), sorted(set(unguards))


@dataclass
class _Binding:
    stmt: Node
    value: Node
    scope: tuple[int, int]
    own: bool  # declared in the statement (`:=`/`var`), not assigned


@dataclass
class _Checkout:
    sources: list[_Source]
    modules: dict[str, str] = field(default_factory=dict)  # module path -> directory
    functions: dict[tuple[str, str], tuple[_Source, Node]] = field(default_factory=dict)
    methods: dict[str, list[tuple[_Source, Node, str]]] = field(default_factory=dict)
    calls: dict[tuple[str, str], list[tuple[_Source, Node]]] = field(default_factory=dict)
    # a struct field's assigned values: (source, value, the owner's type where told)
    fields: dict[tuple[str, str], list[tuple[_Source, Node, Node | None]]] = field(
        default_factory=dict
    )
    package_values: dict[tuple[str, str], tuple[_Source, Node]] = field(default_factory=dict)
    scopes: dict[int, dict[str, list[_Binding]]] = field(default_factory=dict)
    # a struct type's fields that hold data (not a function or handler): (dir, type) -> names
    data_fields: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    def index(self, files: list[TreeFile]) -> None:
        for f in files:
            if f.name == "go.mod" and (m := re.search(r"(?m)^module\s+(\S+)", f.text)):
                self.modules[m[1]] = str(PurePosixPath(f.rel).parent)
        for src in self.sources:
            for n in walk(src.root):
                if n.type == "function_declaration" and (name := n.child_by_field_name("name")):
                    self.functions.setdefault((src.dir, src.text(name)), (src, n))
                elif n.type == "method_declaration" and (name := n.child_by_field_name("name")):
                    self.methods.setdefault(src.text(name), []).append(
                        (src, n, _receiver_type(src, n))
                    )
                elif n.type == "call_expression":
                    self._call(src, n)
                elif n.type == "type_spec" and (kind := n.child_by_field_name("type")):
                    if kind.type == "struct_type":
                        name = src.text(n.child_by_field_name("name"))
                        fields = self.data_fields.setdefault((src.dir, name), set())
                        for decl in walk(kind):
                            if decl.type != "field_declaration":
                                continue
                            ftype = src.text(decl.child_by_field_name("type"))
                            if _HANDLER_TYPE.search(ftype):
                                continue
                            fields |= {
                                src.text(c)
                                for c in decl.named_children
                                if c.type == "field_identifier"
                            }
                elif n.type == "assignment_statement":
                    left = n.child_by_field_name("left")
                    right = n.child_by_field_name("right")
                    values = right.named_children if right is not None else []
                    for i, t in enumerate(left.named_children if left is not None else []):
                        if t.type == "selector_expression" and i < len(values):
                            key = (src.dir, src.text(t.child_by_field_name("field")))
                            owner = t.child_by_field_name("operand")
                            self.fields.setdefault(key, []).append((src, values[i], owner))
                elif n.type == "keyed_element":
                    kids = n.named_children
                    if len(kids) == 2:
                        key = (src.dir, src.text(_unwrap(kids[0]) or kids[0]))
                        literal = n.parent.parent if n.parent is not None else None
                        self.fields.setdefault(key, []).append((src, kids[1], literal))
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

    def _call(self, src: _Source, n: Node) -> None:
        fn = n.child_by_field_name("function")
        if fn is not None and fn.type == "identifier":
            self.calls.setdefault((src.dir, src.text(fn)), []).append((src, n))
        elif fn is not None and fn.type == "selector_expression":
            operand = fn.child_by_field_name("operand")
            name = src.text(fn.child_by_field_name("field"))
            alias = src.text(operand) if operand is not None else ""
            if operand is not None and operand.type == "identifier" and alias in src.imports:
                where = self.directory(src.imports[alias])
                if where is not None:
                    self.calls.setdefault((where, name), []).append((src, n))
                return
            self.calls.setdefault(("method", name), []).append((src, n))

    def directory(self, import_path: str) -> str | None:
        """The checkout directory an import path names, through the go.mod module paths."""
        best = max((m for m in self.modules if import_path == m or import_path.startswith(m + "/")),
                   key=len, default=None)  # fmt: skip
        if best is None:
            return None
        rest = import_path[len(best) :].lstrip("/")
        base = self.modules[best]
        return str(PurePosixPath(base) / rest) if rest else base

    def bindings(self, src: _Source, fn: Node) -> dict[str, list[_Binding]]:
        """Each name a function binds in its own body (not a nested closure's), in order."""
        key = _id(src, fn)
        if key in self.scopes:
            return self.scopes[key]
        out: dict[str, list[_Binding]] = {}
        body = fn.child_by_field_name("body")
        for n in walk(body) if body is not None else []:
            if n.type not in ("short_var_declaration", "assignment_statement", "var_spec",
                              "range_clause"):  # fmt: skip
                continue
            if _enclosing(n) != fn:
                continue
            if n.type == "range_clause":  # `for _, r := range rs`: shadows, holds no router
                loop = n.parent
                left = n.child_by_field_name("left")
                for name in left.named_children if left is not None else []:
                    if name.type == "identifier" and loop is not None:
                        span = (loop.start_byte, loop.end_byte)
                        out.setdefault(src.text(name), []).append(_Binding(n, n, span, True))
                continue
            if n.type == "var_spec":
                names = [c for c in n.named_children if c.type == "identifier"]
                value = n.child_by_field_name("value")
                values = value.named_children if value is not None else []
            else:
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                names = list(left.named_children if left is not None else [])
                values = right.named_children if right is not None else []
            own = n.type != "assignment_statement"
            for i, name in enumerate(names):
                if name.type == "identifier" and i < len(values):
                    out.setdefault(src.text(name), []).append(
                        _Binding(n, values[i], _scope(n), own)
                    )
        self.scopes[key] = out
        return out

    def binding(self, src: _Source, at: Node, name: str, fn: Node) -> _Binding | None:
        """The latest `name := ..` / `name = ..` in `fn` before `at` that `at` sees."""
        found = None
        for b in self.bindings(src, fn).get(name, []):
            if b.stmt.start_byte >= at.start_byte:
                break
            if b.stmt.type != "var_spec" and b.stmt.end_byte > at.start_byte:
                continue  # `r := r.Group(..)`: its own value names the one before
            if b.scope[0] <= at.start_byte < b.scope[1]:
                found = b
        return found

    def values(self, src: _Source, at: Node, name: str, fn: Node) -> list[_Binding]:
        """Every binding `at` may see: the latest one in scope, and assignments after it in a
        nested block (`if dev { handler = mux }`), which may or may not have run."""
        latest = self.binding(src, at, name, fn)
        out = [latest] if latest is not None else []
        for b in self.bindings(src, fn).get(name, []):
            if b.stmt.start_byte >= at.start_byte or b.own:
                continue
            if b.scope[0] <= at.start_byte < b.scope[1]:
                continue
            if latest is None or b.stmt.start_byte > latest.stmt.start_byte:
                out.append(b)
        return out

    def function(self, src: _Source, expr: Node | None) -> tuple[_Source, Node] | None:
        """The checkout function or method an expression names: `listNotes`, `api.ListNotes`,
        `h.GetNote` (a method by name, of the value's type when the code says it)."""
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
        if operand is not None and self.external(src, operand):
            return None  # `svc := notesvc.New(db)`: a library's type, not a namesake's
        found = self.methods.get(name, [])
        kind = self.type_of(src, operand) if operand is not None else ""
        if kind:
            found = [m for m in found if m[2] == kind]
        return (found[0][0], found[0][1]) if len(found) == 1 else None

    def external(self, src: _Source, value: Node) -> bool:
        """A value a library builds: bound to `pkg.New(..)` of a package outside the checkout."""
        value = _unwrap(value) or value
        if value.type != "identifier":
            return False
        fn = _enclosing(value)
        bound = self.binding(src, value, src.text(value), fn) if fn is not None else None
        call = _unwrap(bound.value) if bound is not None else None
        if call is None or call.type != "call_expression":
            return False
        operand, _ = _field(src, call)
        alias = src.text(operand) if operand is not None else ""
        return alias in src.imports and self.directory(src.imports[alias]) is None

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
                return _receiver_type(src, fn)
            bound = self.binding(src, value, name, fn)
            if bound is not None:
                return self.value_type(src, bound.value)
            fn = _enclosing(fn)
        return ""

    def value_type(self, src: _Source, value: Node) -> str:
        """`&T{..}`, what a checkout function says it returns (`newAdminAPI() *adminAPI`), or a
        library's `NewT(..)`."""
        inner = _unwrap(value) or value
        if inner.type == "call_expression":
            found = self.function(src, inner.child_by_field_name("function"))
            if found is not None and found[1].type != "func_literal":
                words = re.findall(r"\w+", found[0].text(found[1].child_by_field_name("result")))
                return words[-1] if words else ""
        return _literal_type(src, value)

    def returned(self, src: _Source, fn: Node) -> list[Node]:
        return [
            r.named_children[0].named_children[0]
            if r.named_children and r.named_children[0].type == "expression_list"
            else r.named_children[0]
            for r in walk(fn.child_by_field_name("body") or fn)
            if r.type == "return_statement" and r.named_children and _enclosing(r) == fn
        ]

    def string(self, src: _Source, node: Node | None, depth: int = 0) -> str | None:
        """A path as a literal, a constant, a `+` of those, or a `path.Join` of them."""
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


def _literal_type(src: _Source, value: Node) -> str:
    text = src.text(value)
    if m := re.match(r"&?\s*(?:\w+\.)?(\w+)\s*\{", text):
        return m[1]
    if m := re.match(r"(?:\w+\.)?New(\w+)\s*\(", text):
        return m[1]
    return ""


def _method(src: _Source, node: Node | None) -> str | None:
    """A method argument: `"GET"` or `http.MethodGet`."""
    if (text := src.string(node)) is not None:
        return text.upper()
    m = _METHOD_CONST.match(src.text(node)) if node is not None else None
    return m[1].upper() if m else None


@dataclass
class _Reg:
    """One registration call: the receiver it is on, its methods, path and the arguments that
    carry its handler and middleware."""

    call: Node
    receiver: Node
    methods: list[str]
    path: Node | None
    rest: list[Node]  # handler and route middleware, in the call's order
    layout: str  # "fixed" (one handler), else the framework order decides
    mount: bool = False  # `Mount(prefix, router)`: the prefix is stripped


class _Matrix:
    def __init__(self, checkout: _Checkout) -> None:
        self.co = checkout
        self.identities: dict[int, set[int]] = {}
        self.resolved: dict[tuple[int, int], list[_Ctx]] = {}
        self.uses: dict[int, list[Node]] = {}
        self.mounts: dict[int, list[tuple[_Source, _Reg, list[str]]]] = {}
        self.serves: dict[int, list[list[str]]] = {}
        self.regs: list[tuple[_Source, _Reg]] = []
        self.wrapping: dict[int, Node | None] = {}
        self.dir_uses: dict[str, list[tuple[_Source, Node]]] = {}
        # `r.Route("/x", articleRouter)`: a named function given a router (chi, fiber)
        self.route_fns: dict[int, list[tuple[_Source, Node]]] = {}
        for src in checkout.sources:
            for n in walk(src.root):
                if n.type != "call_expression":
                    continue
                if reg := self.registration(src, n):
                    self.regs.append((src, reg))
                receiver, name = _field(src, n)
                if receiver is not None and name in _USES:
                    self.dir_uses.setdefault(src.dir, []).append((src, n))
                if receiver is not None and name in ("Route", "Group"):
                    for a in _args(n):
                        if (_unwrap(a) or a).type in ("identifier", "selector_expression"):
                            found = checkout.function(src, a)
                            if found is not None:
                                self.route_fns.setdefault(_id(*found), []).append((src, n))
        self.traced: dict[int, list[tuple[int, tuple[str, ...]]]] = {}
        for src, reg in self.regs:
            for ident, names in self.trace(src, self.handler(src, reg, "")):
                self.mounts.setdefault(ident, []).append((src, reg, list(names)))
        for src in checkout.sources:
            for served in self.served(src):
                if served.type == "nil":  # `ListenAndServe(addr, nil)`: the default mux
                    self.serves.setdefault(_DEFAULT_MUX, []).append([])
                for ident, names in self.trace(src, served):
                    self.serves.setdefault(ident, []).append(list(names))

    # ---- registrations
    def registration(self, src: _Source, call: Node) -> _Reg | None:
        receiver, name = _field(src, call)
        if receiver is None or not name:
            return None
        args = _args(call)
        lower = name.lower()
        if name in ("HandleFunc", "Handle", "Mount") and len(args) == 2:
            methods = self.gorilla_methods(src, call)
            return _Reg(call, receiver, methods, args[0], [args[1]], "fixed", name == "Mount")
        if name in ("HandlerFunc", "Handler") and len(args) == 1:
            path = self.chained(src, receiver, "Path") or self.chained(src, receiver, "PathPrefix")
            if path is None:
                return None
            return _Reg(call, receiver, self.gorilla_methods(src, call), path, args, "fixed")
        if name in ("Method", "MethodFunc") and len(args) == 3:  # chi
            verb = _method(src, args[0]) or "ANY"
            return _Reg(call, receiver, [verb], args[1], [args[2]], "fixed")
        if name in ("Handle", "Add") and len(args) >= 3 and (verb := _method(src, args[0])):
            return _Reg(call, receiver, [verb], args[1], _spread(args[2:]), "verbs")
        if name == "Match" and len(args) >= 3:
            verbs = [m for a in walk(args[0]) if (m := _method(src, a))] or ["ANY"]
            return _Reg(call, receiver, verbs, args[1], args[2:], "verbs")
        if lower in _VERBS | _ANY and len(args) >= 2:
            verb = "ANY" if lower in _ANY else name.upper()
            return _Reg(call, receiver, [verb], args[0], _spread(args[1:]), "verbs")
        return None

    def handler(self, src: _Source, reg: _Reg, kind: str) -> Node:
        """The handler among a route's arguments: last for gin and fiber (in order), first for
        echo (its middleware follow it)."""
        if reg.layout == "fixed" or len(reg.rest) == 1:
            return reg.rest[0]
        return reg.rest[0] if (kind or self.kind_hint(src)) == "echo" else reg.rest[-1]

    def route_middleware(self, src: _Source, reg: _Reg, kind: str) -> list[Node]:
        if reg.layout == "fixed" or len(reg.rest) == 1:
            return []
        return reg.rest[1:] if (kind or self.kind_hint(src)) == "echo" else reg.rest[:-1]

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
        """`.Methods("GET", http.MethodPost)` anywhere along a gorilla chain; else every method."""
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
                methods += [m for a in _args(n) if (m := _method(src, a))]
        return _unique(methods) or ["ANY"]

    def chained(self, src: _Source, node: Node | None, step: str) -> Node | None:
        """The argument of `.Path(..)` (or another step) in a receiver chain."""
        while node is not None and node.type == "call_expression":
            operand, name = _field(src, node)
            if name == step and _args(node):
                return _args(node)[0]
            node = operand
        return None

    def kind_hint(self, src: _Source) -> str:
        kinds = set(src.kinds.values()) - {"http"}
        return next(iter(kinds)) if len(kinds) == 1 else ""

    # ---- handlers and what wraps them
    def handler_like(self, src: _Source, node: Node, depth: int = 0) -> bool:
        """Whether an argument can be a handler: a function, a method value, a closure, a router,
        a handler-typed value, or a call that builds or wraps one. Data (`db`, `&out`, `-1`, a
        struct literal) is none."""
        if node.type == "unary_expression" or depth > _MAX_DEPTH:
            return False
        node = _unwrap(node) or node
        if node.type == "func_literal":
            return True
        if node.type == "call_expression":
            return True  # `api.ListSessions(db)`, `auth(h)`: a handler built or wrapped
        if node.type == "identifier":
            name = src.text(node)
            fn = _enclosing(node)
            while fn is not None:
                bound = self.co.binding(src, node, name, fn)
                if bound is not None:
                    value = _unwrap(bound.value) or bound.value
                    return value.type in ("func_literal", "call_expression", "identifier") and (
                        value.type != "identifier" or self.handler_like(src, value, depth + 1)
                    )
                kinds = {p: k for p, k in _params(src, fn)}
                if name in kinds:
                    return bool(_HANDLER_TYPE.search(kinds[name]) or _TYPED.search(kinds[name]))
                fn = _enclosing(fn)
            value = self.co.package_values.get((src.dir, name))
            if value is not None:
                v = _unwrap(value[1]) or value[1]
                return v.type in ("func_literal", "call_expression")
            return True  # a function here, or one this checkout can't see
        if node.type == "selector_expression":
            operand = node.child_by_field_name("operand")
            if operand is not None and src.text(operand) in src.imports:
                return True  # `handlers.ListNotes`
            if self.co.function(src, node) is not None:
                return True
            kind = self.co.type_of(src, operand) if operand is not None else ""
            name = src.text(node.child_by_field_name("field"))
            # a data field the value's struct declares (`s.store`): not a method value
            return name not in self.co.data_fields.get((src.dir, kind), set())
        return False

    def wraps(self, src: _Source, call: Node) -> Node | None:
        """The handler a call wraps (`auth(h)`, `alice.New(m).ThenFunc(h)`), or None when it
        builds one from data (`api.ListSessions(db)`)."""
        key = _id(src, call)
        if key not in self.wrapping:
            self.wrapping[key] = None  # a cycle wraps nothing
            self.wrapping[key] = self._wraps(src, call)
        return self.wrapping[key]

    def _wraps(self, src: _Source, call: Node) -> Node | None:
        _, name = _field(src, call)
        if name in _ROUTER_STEPS:
            return None
        args = _args(call)
        for index in range(len(args) - 1, -1, -1):
            a = args[index]
            inner = _unwrap(a) or a
            if a.type == "unary_expression":
                continue
            if inner.type in ("func_literal", "call_expression"):
                return a
            if inner.type not in ("identifier", "selector_expression"):
                continue
            if self.identity(src, inner):
                if self.passes_on(src, call, index):
                    return a
                continue  # `routesHandler(mux)`: the router as data
            if self.co.function(src, inner) is not None or self.bare_function(src, inner):
                if self.co.function(src, call.child_by_field_name("function")) is None or (
                    self.passes_on(src, call, index)
                ):
                    return a  # a checkout factory's data argument (`RevokeToken(store)`) is none
                continue
            if inner.type == "identifier" and self.bound_wrapper(src, inner):
                return a
        return None

    def bound_wrapper(self, src: _Source, node: Node) -> bool:
        """A local bound to a wrapper or a closure: `protected := requireAuth(api)`."""
        fn = _enclosing(node)
        bound = self.co.binding(src, node, src.text(node), fn) if fn is not None else None
        value = _unwrap(bound.value) if bound is not None else None
        if value is None:
            return False
        return value.type == "func_literal" or (
            value.type == "call_expression" and self.wraps(src, value) is not None
        )

    def passes_on(self, src: _Source, call: Node, index: int, depth: int = 0) -> bool:
        """Whether a call puts the handler it is given on the request path: a library's
        wrapper (`cors.Handler(mux)`, `http.StripPrefix`), or a checkout function that serves
        its parameter (`next.ServeHTTP(w, r)`, `next(w, r)`) or hands it to such a wrapper.
        Returning it bare (`return mux`) or reading it (`describe(m)`) interposes nothing."""
        fn_node = call.child_by_field_name("function")
        found = self.co.function(src, fn_node)
        if found is None:
            return fn_node is not None and fn_node.type != "identifier"
        fsrc, fn = found
        params = _params(fsrc, fn)
        if fn.type == "func_literal" or index >= len(params) or not params[index][0]:
            return False
        name = params[index][0]
        body = fn.child_by_field_name("body")
        if re.search(rf"\b{re.escape(name)}(\.ServeHTTP)?\s*\(", fsrc.text(body)):
            return True
        for n in walk(body) if body is not None and depth < _MAX_DEPTH else []:
            if n.type != "call_expression":
                continue
            for i, a in enumerate(_args(n)):
                if fsrc.text(_unwrap(a) or a) != name:
                    continue
                inner = n.child_by_field_name("function")
                if self.co.function(fsrc, inner) is not None:
                    if self.passes_on(fsrc, n, i, depth + 1):
                        return True
                elif _PASSES.search(_name(fsrc, inner)):
                    return True
        return False

    def inner_names(self, src: _Source, call: Node, index: int) -> list[str]:
        """The wrappers a checkout wrapper puts around its parameter: `withMiddleware(next)`
        returning `logRequest(requireAuth(next))` is under `logRequest`, `requireAuth`."""
        found = self.co.function(src, call.child_by_field_name("function"))
        if found is None or found[1].type == "func_literal":
            return []
        fsrc, fn = found
        params = _params(fsrc, fn)
        if index >= len(params):
            return []
        out = []
        for r in self.co.returned(fsrc, fn):
            inner, names = self.peel(fsrc, r)
            if inner.type == "identifier" and fsrc.text(inner) == params[index][0]:
                out += names
        return out

    def bare_function(self, src: _Source, node: Node) -> bool:
        """A name no binding, parameter or package value explains: a function this checkout
        can't see (`requireAuth(handleJobs)`)."""
        if node.type != "identifier":
            return False
        name = src.text(node)
        fn = _enclosing(node)
        while fn is not None:
            if self.co.binding(src, node, name, fn) is not None or name in {
                p for p, _ in _params(src, fn)
            }:
                return False
            fn = _enclosing(fn)
        return (src.dir, name) not in self.co.package_values

    def peel(self, src: _Source, handler: Node) -> tuple[Node, list[str]]:
        """The handler inside its wrappers, and the wrappers' names: `auth(http.HandlerFunc(h))`
        is `h` under `auth`; a local bound to a wrapper (`p := auth(api)`) is followed too."""
        node = _unwrap(handler) or handler
        names: list[str] = []
        for _ in range(_MAX_DEPTH):
            if node.type == "identifier":
                fn = _enclosing(node)
                bound = self.co.binding(src, node, src.text(node), fn) if fn is not None else None
                value = _unwrap(bound.value) if bound is not None else None
                if value is not None and value.type == "call_expression" and self.wraps(src, value):
                    node = value
                    continue
                break
            if node.type != "call_expression":
                break
            inner = self.wraps(src, node)
            if inner is None:
                break
            callee = _name(src, node)
            if callee not in _CONVERSIONS:
                names.append(callee)
            node = _unwrap(inner) or inner
        return node, names

    def trace(
        self, src: _Source, expr: Node | None, depth: int = 0
    ) -> list[tuple[int, tuple[str, ...]]]:
        """The routers a handler expression serves, each with the wrappers around it on the way:
        through wrapper calls, locals bound to them and what a checkout function returns
        (`return withCORS(validateAuth(mux))`)."""
        expr = _unwrap(expr)
        if expr is None or depth > _MAX_DEPTH:
            return []
        key = _id(src, expr)
        if key in self.traced:
            return self.traced[key]
        self.traced[key] = []  # a cycle serves no router
        out: list[tuple[int, tuple[str, ...]]] = []
        if expr.type in ("identifier", "selector_expression"):
            fn = _enclosing(expr)
            bounds = (
                self.co.values(src, expr, src.text(expr), fn)
                if expr.type == "identifier" and fn is not None
                else []
            )
            if len(bounds) > 1:  # assigned on some ways only: each value it may hold
                out = [x for b in bounds for x in self.trace(src, b.value, depth + 1)]
            else:
                out = [(i, ()) for i in self.identity(src, expr)]
                if not out and bounds:
                    out = self.trace(src, bounds[0].value, depth + 1)
        elif expr.type == "call_expression":
            if self.constructor(src, expr):
                out = [(_id(src, expr), ())]
            elif (inner := self.wraps(src, expr)) is not None:
                callee = _name(src, expr)
                name = () if callee in _CONVERSIONS else (callee,)
                index = next((i for i, a in enumerate(_args(expr)) if a == inner), -1)
                within = tuple(self.inner_names(src, expr, index)) if index >= 0 else ()
                out = [(i, (*name, *within, *ns)) for i, ns in self.trace(src, inner, depth + 1)]
            else:
                found = self.co.function(src, expr.child_by_field_name("function"))
                if found is not None and found[1].type != "func_literal":
                    fsrc, fn = found
                    out = [
                        x
                        for r in self.co.returned(fsrc, fn)
                        for x in self.trace(fsrc, r, depth + 1)
                    ]
                    if out:
                        out.append((_id(src, expr), ()))  # and this call's own router
        self.traced[key] = list(dict.fromkeys(out))
        return self.traced[key]

    def middleware_names(self, src: _Source, nodes: list[Node]) -> list[str]:
        return [n for n in (_name(src, x) for x in nodes) if n]

    def served(self, src: _Source) -> list[Node]:
        """Each handler a server is given: `http.ListenAndServe(addr, h)`, `http.Server{Handler:
        h}`, `srv.Handler = h`."""
        out = []
        for n in walk(src.root):
            if n.type == "call_expression":
                _, name = _field(src, n)
                name = name or _callee(src, n)
                args = _args(n)
                if name in _SERVES and len(args) == _SERVES[name][0]:
                    out.append(args[_SERVES[name][1]])
            elif n.type == "keyed_element" and len(n.named_children) == 2:
                if src.text(_unwrap(n.named_children[0]) or n.named_children[0]) == "Handler":
                    out.append(n.named_children[1])
            elif n.type == "assignment_statement":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                targets = left.named_children if left is not None else []
                values = right.named_children if right is not None else []
                for i, t in enumerate(targets):
                    if (
                        t.type == "selector_expression"
                        and src.text(t.child_by_field_name("field")) == "Handler"
                        and i < len(values)
                    ):
                        out.append(values[i])
        return out

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
            if self.helper(src, expr):
                return {_id(src, expr)}  # each call of a router-building helper: its own router
            return set()
        if expr.type == "identifier":
            name = src.text(expr)
            if src.kinds.get(name) == "http":
                return set()
            fn = _enclosing(expr)
            while fn is not None:
                bounds = self.co.values(src, expr, name, fn)
                if bounds:
                    return {i for b in bounds for i in self.identity(src, b.value, depth + 1)}
                names = [p for p, _ in _params(src, fn)]
                if name in names:  # a router passed in: whatever each caller passes
                    return {
                        i
                        for csrc, call in self.callers(src, fn)
                        if names.index(name) < len(_args(call))
                        for i in self.identity(csrc, _args(call)[names.index(name)], depth + 1)
                    }
                fn = _enclosing(fn)
            value = self.co.package_values.get((src.dir, name))
            return self.identity(value[0], value[1], depth + 1) if value else set()
        if expr.type == "selector_expression":
            operand = expr.child_by_field_name("operand")
            if operand is not None and src.text(operand) in src.imports:
                default = src.kinds.get(src.text(operand)) == "http"
                named = src.text(expr.child_by_field_name("field")) == "DefaultServeMux"
                return {_DEFAULT_MUX} if default and named else set()
            return {
                i
                for vsrc, v in self.field_sites(src, expr)
                for i in self.identity(vsrc, v, depth + 1)
            }
        return set()

    def helper(self, src: _Source, call: Node) -> tuple[_Source, Node] | None:
        """A checkout function a call runs that returns a router it builds (`newRouter()`)."""
        found = self.co.function(src, call.child_by_field_name("function"))
        if found is None or found[1].type == "func_literal":
            return None
        fsrc, fn = found
        built = any(self.identity(fsrc, r) - {_id(src, call)} for r in self.co.returned(fsrc, fn))
        return found if built else None

    def callers(self, src: _Source, fn: Node) -> list[tuple[_Source, Node]]:
        """The calls of a function, or of a method on a receiver of its type where told."""
        if fn.type == "func_literal":
            return []
        name = src.text(fn.child_by_field_name("name"))
        if fn.type != "method_declaration":
            return self.co.calls.get((src.dir, name), [])
        kind = _receiver_type(src, fn)
        out = []
        for csrc, call in self.co.calls.get(("method", name), []):
            operand, _ = _field(csrc, call)
            told = self.co.type_of(csrc, operand) if operand is not None else ""
            if not told or told == kind:
                out.append((csrc, call))
        return out

    def field_sites(self, src: _Source, expr: Node) -> list[tuple[_Source, Node]]:
        """What a struct field is assigned, for the owner's type where both sides tell it."""
        name = src.text(expr.child_by_field_name("field"))
        operand = expr.child_by_field_name("operand")
        kind = self.co.type_of(src, operand) if operand is not None else ""
        out = []
        for vsrc, value, owner in self.co.fields.get((src.dir, name), []):
            told = ""
            if owner is not None and owner.type == "composite_literal":
                told = _literal_type(vsrc, owner)
            elif owner is not None:
                told = self.co.type_of(vsrc, owner)
            if not kind or not told or kind == told:
                out.append((vsrc, value))
        return out if len(out) <= _MAX_FIELD_SITES else []

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

    # ---- router contexts
    def contexts(self, src: _Source, expr: Node | None, at: Node, depth: int = 0) -> list[_Ctx]:
        """Each place a router expression's routes end up: prefix, guards, framework."""
        expr = _unwrap(expr)
        if expr is None or depth > _MAX_DEPTH:
            return [_Ctx(dynamic=True)]
        key = (_id(src, expr), _id(src, at))
        if key not in self.resolved:
            self.resolved[key] = [_Ctx(dynamic=True)]  # a cycle reads as an unknown router
            out = list(dict.fromkeys(self._contexts(src, expr, at, depth)))
            if len(out) > _MAX_CONTEXTS:  # too many to follow: one more, unguarded
                out = [*out[:_MAX_CONTEXTS], _Ctx(dynamic=True)]
            self.resolved[key] = out or [_Ctx()]
        return self.resolved[key]

    def _contexts(self, src: _Source, expr: Node, at: Node, depth: int) -> list[_Ctx]:
        if expr.type == "call_expression":
            return self.call_contexts(src, expr, at, depth)
        if expr.type == "identifier":
            if src.kinds.get(src.text(expr)) == "http":  # `http.HandleFunc(..)`: the default mux
                return self.places(_DEFAULT_MUX, "http", depth) or [_Ctx(kind="http", known=True)]
            return self.name_contexts(src, expr, at, depth)
        if expr.type == "selector_expression":
            operand = expr.child_by_field_name("operand")
            name = src.text(expr.child_by_field_name("field"))
            alias = src.text(operand) if operand is not None else ""
            if alias in src.imports:
                kind = src.kinds.get(alias, "")
                if kind == "http" and name == "DefaultServeMux":
                    return self.places(_DEFAULT_MUX, kind, depth) or [_Ctx(kind=kind, known=True)]
                return [_Ctx(kind=kind)]
            out = [
                c
                for vsrc, v in self.field_sites(src, expr)
                for c in self.contexts(vsrc, v, v, depth + 1)
            ]
            out = out or [_Ctx(kind=self.kind_hint(src))]
            return self.field_middleware(src, expr, at, out)
        return [_Ctx(dynamic=True)]

    def call_contexts(self, src: _Source, call: Node, at: Node, depth: int) -> list[_Ctx]:
        if kind := self.constructor(src, call):
            return self.mounted(src, call, kind, depth)
        receiver, name = _field(src, call)
        args = _args(call)
        if receiver is not None and name in ("Group", "Route") and args:
            prefix = self.co.string(src, args[0])
            mws = args[1:] if prefix is not None else []
            names = self.middleware_names(src, [m for m in mws if m.type != "func_literal"])
            g, u = _named(names)
            dynamic = prefix is None and args[0].type != "func_literal"
            parents = self.contexts(src, receiver, call, depth + 1)
            if any(c.kind == "fiber" for c in parents) and _enclosing(at) == _enclosing(call):
                parents = self.contexts(src, receiver, at, depth + 1)  # fiber: at registration
            return [
                replace(c, dynamic=c.dynamic or dynamic).under(prefix or "", g, u) for c in parents
            ]
        if receiver is not None and name in ("With", *_USES, "Unbind"):
            g, u = _named(self.middleware_names(src, args))
            g, u = ([], [*u, *g]) if name == "Unbind" else (g, u)  # an unbound guard: judged
            return [c.under("", g, u) for c in self.contexts(src, receiver, call, depth + 1)]
        if receiver is not None and name == "Subrouter":
            prefix_node = self.chained(src, receiver, "PathPrefix")
            prefix = self.co.string(src, prefix_node) if prefix_node is not None else ""
            methods = tuple(
                m
                for n in walk(receiver)
                if n.type == "call_expression" and _field(src, n)[1] == "Methods"
                for a in _args(n)
                if (m := _method(src, a))
            )
            root = receiver
            while root.type == "call_expression" and _field(src, root)[0] is not None:
                root = _field(src, root)[0]  # type: ignore[assignment]
            return [
                replace(c, dynamic=c.dynamic or prefix is None, methods=methods or c.methods).under(
                    prefix or ""
                )
                for c in self.contexts(src, root, call, depth + 1)
            ]
        if helper := self.helper(src, call):
            bases = self.built(helper[0], helper[1])
            sites = self.places(_id(src, call), bases[0].kind if bases else "", depth)
            if not sites:
                return bases or [_Ctx(kind=self.kind_hint(src))]
            return [
                replace(s, kind=b.kind or s.kind).under(b.prefix, list(b.guards), list(b.unguards))
                for s in sites
                for b in bases
            ]
        found = self.co.function(src, call.child_by_field_name("function"))
        if found is not None and found[1].type != "func_literal":
            fsrc, fn = found
            out = [
                c for r in self.co.returned(fsrc, fn) for c in self.contexts(fsrc, r, r, depth + 1)
            ]
            if out:
                return out
        return [_Ctx(kind=self.kind_hint(src))]

    def built(self, fsrc: _Source, fn: Node) -> list[_Ctx]:
        """What a router-building helper returns, with the middleware it adds itself."""
        out = []
        for r in self.co.returned(fsrc, fn):
            r = _unwrap(r) or r
            if r.type == "call_expression" and (kind := self.constructor(fsrc, r)):
                out.append(_Ctx(kind=kind, known=True))
            elif r.type == "identifier":
                bound = self.co.binding(fsrc, r, fsrc.text(r), fn)
                value = _unwrap(bound.value) if bound is not None else None
                kind = (
                    self.constructor(fsrc, value)
                    if value is not None and value.type == "call_expression"
                    else ""
                )
                if kind:
                    base = [_Ctx(kind=kind, known=True)]
                    out += self.used_middleware(fsrc, fn, fsrc.text(r), bound, r, base)
        return out

    def places(self, ident: int, kind: str, depth: int) -> list[_Ctx]:
        """Where a router is mounted (`r.Mount("/api", api)`, `Handle("/api/", StripPrefix(..))`)
        and served (`ListenAndServe(addr, auth(mux))`): each its own place, so a router also
        served raw stays unguarded there."""
        out: list[_Ctx] = []
        for msrc, reg, names in self.mounts.get(ident, []):
            for c in self.contexts(msrc, reg.receiver, reg.call, depth + 1):
                prefix = self.mount_prefix(msrc, reg, kind)
                route = self.middleware_names(msrc, self.route_middleware(msrc, reg, c.kind))
                g, u = _named([*names, *route])
                out.append(replace(c, kind=kind, known=True).under(prefix, g, u))
        for names in self.serves.get(ident, []):
            out.append(_Ctx(kind=kind, known=True).under("", *_named(names)))
        return out

    def mounted(self, src: _Source, call: Node, kind: str, depth: int) -> list[_Ctx]:
        """A router built here: its own places, or, built in a helper that returns it, the
        places of each call of the helper."""
        out = self.places(_id(src, call), kind, depth)
        fn = _enclosing(call)
        if not out and fn is not None and fn.type != "func_literal":
            for csrc, c in self.callers(src, fn):
                if self.helper(csrc, c):
                    out += self.places(_id(csrc, c), kind, depth) or [_Ctx(kind=kind, known=True)]
        return out or [_Ctx(kind=kind, known=True)]

    def mount_prefix(self, src: _Source, reg: _Reg, kind: str) -> str:
        """The path a mounted router's own routes sit under: `http.StripPrefix` strips it, and
        chi and fiber `Mount` do for their own routers; net/http, gorilla and gin hand on the
        full path, as chi does to any other handler."""
        handler = reg.rest[0] if reg.rest else reg.call
        for n in walk(handler):
            if n.type == "call_expression" and _callee(src, n).endswith("StripPrefix") and _args(n):
                return self.co.string(src, _args(n)[0]) or ""
        if not reg.mount or kind not in ("chi", "fiber"):
            return ""
        path = self.co.string(src, reg.path) or ""
        return path.rstrip("/").removesuffix("/*")

    def name_contexts(self, src: _Source, name: Node, at: Node, depth: int) -> list[_Ctx]:
        ident = src.text(name)
        fn = _enclosing(at)
        while fn is not None:
            bound = self.co.binding(src, at, ident, fn)
            others = [b for b in self.co.values(src, at, ident, fn) if b is not bound]
            if bound is None and others:
                return [c for b in others for c in self.contexts(src, b.value, b.stmt, depth + 1)]
            if bound is not None:
                ctxs = self.contexts(src, bound.value, bound.stmt, depth + 1)
                ctxs += [c for b in others for c in self.contexts(src, b.value, b.stmt, depth + 1)]
                value = _unwrap(bound.value)
                if (
                    any(c.kind == "fiber" for c in ctxs)
                    and value is not None
                    and value.type == "call_expression"
                    and _field(src, value)[1] in ("Group", "Route")
                ):
                    ctxs = self.contexts(src, value, at, depth + 1)  # fiber: at registration
                return self.used_middleware(src, fn, ident, bound, at, ctxs)
            names = [p for p, _ in _params(src, fn)]
            if ident in names:
                ctxs = self.param_contexts(src, fn, names.index(ident), depth)
                return self.used_middleware(src, fn, ident, None, at, ctxs)
            fn = _enclosing(fn)
        value = self.co.package_values.get((src.dir, ident))
        if value is not None:
            vsrc, v = value
            return self.package_middleware(src, ident, at, self.contexts(vsrc, v, v, depth + 1), v)
        return [_Ctx(kind=self.kind_hint(src))]

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
        out = []
        for csrc, call in self.callers(src, fn):
            args = _args(call)
            if index < len(args):
                out += self.contexts(csrc, args[index], call, depth + 1)
        for csrc, holder in self.route_fns.get(_id(src, fn), []) if index == 0 else []:
            receiver, _ = _field(csrc, holder)
            args = _args(holder)
            prefix = self.co.string(csrc, args[0]) if len(args) > 1 else ""
            out += [
                replace(c, dynamic=c.dynamic or prefix is None).under(prefix or "")
                for c in self.contexts(csrc, receiver, holder, depth + 1)
            ]
        return out or [_Ctx(kind=self.param_kind(src, fn, index), known=True)]

    def param_kind(self, src: _Source, fn: Node, index: int) -> str:
        params = _params(src, fn)
        kind = params[index][1] if index < len(params) else ""
        m = _TYPED.search(kind)
        if m is None:
            return ""
        return src.kinds.get(m["pkg"]) or m["pkg"]

    def fn_uses(self, src: _Source, fn: Node) -> list[Node]:
        """The `Use`-like calls a function makes itself (not a nested closure's)."""
        key = _id(src, fn)
        if key not in self.uses:
            body = fn.child_by_field_name("body") or fn
            self.uses[key] = [
                n
                for n in walk(body)
                if n.type == "call_expression"
                and _field(src, n)[1] in _USES
                and _enclosing(n) == fn
            ]
        return self.uses[key]

    def apply(
        self, uses: list[tuple[_Source, Node, int]], ctxs: list[_Ctx], ordered_at: Node | None,
        root: bool,
    ) -> list[_Ctx]:  # fmt: skip
        """The contexts with these `Use` calls' middleware (each with the position it counts
        at); where order counts, only those before `ordered_at` (None: their order can't be
        told, so none count)."""
        out = []
        for c in ctxs:
            ordered = c.kind in _ORDERED and not (c.kind == "echo" and root)
            guards: list[str] = []
            unguards: list[str] = []
            scoped = list(c.scoped)
            for usrc, n, at in uses:
                if ordered and (ordered_at is None or at > ordered_at.start_byte):
                    continue
                args = _args(n)
                path = self.co.string(usrc, args[0]) if args else None
                if path is not None:  # fiber `app.Use("/api", mw)`
                    g, _ = _named(self.middleware_names(usrc, args[1:]))
                    scoped.append((_join(c.prefix, path), tuple(g)))
                    continue
                g, u = _named(self.middleware_names(usrc, args))
                guards, unguards = guards + g, unguards + u
            out.append(replace(c.under("", guards, unguards), scoped=tuple(scoped)))
        return out

    def used_middleware(
        self, src: _Source, fn: Node, ident: str, bound: _Binding | None, at: Node,
        ctxs: list[_Ctx],
    ) -> list[_Ctx]:  # fmt: skip
        """`r.Use(mw)` in this function on the same binding of `r` as `at` sees, and in a
        helper it hands `r` to (`setupMiddleware(r)`), counted where the helper is called."""
        uses: list[tuple[_Source, Node, int]] = []
        same = bound.stmt if bound else None
        for n in self.fn_uses(src, fn):
            receiver, _ = _field(src, n)
            if receiver is None or src.text(_unwrap(receiver)) != ident:
                continue
            seen = self.co.binding(src, n, ident, fn)
            if (seen.stmt if seen else None) != same:
                continue  # another `r`: shadowed, reassigned or out of scope
            uses.append((src, n, n.start_byte))
        for call in self.fn_calls(src, fn):
            for i, a in enumerate(_args(call)):
                if src.text(_unwrap(a) or a) != ident:
                    continue
                seen = self.co.binding(src, call, ident, fn)
                if (seen.stmt if seen else None) != same:
                    continue
                found = self.co.function(src, call.child_by_field_name("function"))
                if found is None or found[1].type == "func_literal":
                    continue
                hsrc, helper = found
                params = _params(hsrc, helper)
                if i >= len(params):
                    continue
                for n in self.fn_uses(hsrc, helper):
                    receiver, _ = _field(hsrc, n)
                    if receiver is not None and hsrc.text(_unwrap(receiver)) == params[i][0]:
                        uses.append((hsrc, n, call.start_byte))
        value = _unwrap(bound.value) if bound is not None else None
        root = (
            value is not None
            and value.type == "call_expression"
            and bool(self.constructor(src, value))
        )
        return self.apply(uses, ctxs, at, root)

    def fn_calls(self, src: _Source, fn: Node) -> list[Node]:
        """The calls a function makes itself that hand on a plain name (`setupRoutes(r)`)."""
        key = -_id(src, fn)
        if key not in self.uses:
            body = fn.child_by_field_name("body") or fn
            self.uses[key] = [
                n
                for n in walk(body)
                if n.type == "call_expression"
                and _enclosing(n) == fn
                and any((_unwrap(a) or a).type == "identifier" for a in _args(n))
            ]
        return self.uses[key]

    def package_middleware(
        self, src: _Source, ident: str, at: Node, ctxs: list[_Ctx], value: Node
    ) -> list[_Ctx]:
        """`router.Use(mw)` on a package-level router, wherever no local `router` shadows it;
        where order counts, only in the function that registers, before the route."""
        here = _enclosing(at)
        uses = [
            (s, n, n.start_byte)
            for s, n in self.dir_uses.get(src.dir, [])
            if (r := _field(s, n)[0]) is not None
            and s.text(_unwrap(r)) == ident
            and not self.shadowed(s, n, ident)
        ]
        value = _unwrap(value) or value
        root = value.type == "call_expression" and bool(self.constructor(src, value))
        ordered_ctxs = [c for c in ctxs if c.kind in _ORDERED and not (c.kind == "echo" and root)]
        local = [u for u in uses if u[0].file.rel == src.file.rel and _enclosing(u[1]) == here]
        return self.apply(local if ordered_ctxs else uses, ctxs, at, root)

    def shadowed(self, src: _Source, at: Node, ident: str) -> bool:
        fn = _enclosing(at)
        while fn is not None:
            if self.co.binding(src, at, ident, fn) is not None or ident in {
                p for p, _ in _params(src, fn)
            }:
                return True
            fn = _enclosing(fn)
        return False

    def field_middleware(self, src: _Source, expr: Node, at: Node, ctxs: list[_Ctx]) -> list[_Ctx]:
        """`s.router.Use(mw)` on the same router; where order counts, only earlier in the
        function that registers."""
        mine = self.identity(src, expr)
        owner = self.owner_type(src, expr)
        if not mine or not owner:
            return ctxs  # whose field this is can't be told: no other `Use` is its own
        name = src.text(expr.child_by_field_name("field"))
        uses = []
        for s, n in self.dir_uses.get(src.dir, []):
            receiver = _unwrap(_field(s, n)[0])
            if (
                receiver is not None
                and receiver.type == "selector_expression"
                and s.text(receiver.child_by_field_name("field")) == name
                and self.owner_type(s, receiver) == owner
                and self.identity(s, receiver) & mine
            ):
                uses.append((s, n, n.start_byte))
        unordered = [c for c in ctxs if c.kind not in _ORDERED]
        ordered = [c for c in ctxs if c.kind in _ORDERED]
        here = [u for u in uses if _enclosing(u[1]) == _enclosing(at)]
        return [*self.apply(uses, unordered, None, False), *self.apply(here, ordered, at, False)]

    def owner_type(self, src: _Source, expr: Node) -> str:
        """The struct type a field selector's owner has, where the code says it."""
        operand = expr.child_by_field_name("operand")
        return self.co.type_of(src, operand) if operand is not None else ""

    # ---- rows
    def rows(self) -> list[_Row]:
        rows = []
        for src, reg in self.regs:
            if self.trace(src, self.handler(src, reg, "")):
                continue  # a mount: its routes are the mounted router's
            raw = reg.path
            if (
                raw is None
                or raw.type == "unary_expression"
                or (_unwrap(raw) or raw).type not in _PATHS
            ):
                continue  # `db.Get(&out, query)`: no path, no route
            literal = self.co.string(src, raw)
            method_in, pattern = "", literal
            if literal is not None and (m := _METHOD_PATTERN.match(literal)):
                method_in, pattern = m[1], m[2]
            ctxs = self.contexts(src, reg.receiver, reg.call)
            if not _route_like(pattern, any(c.known for c in ctxs)):
                continue  # `cache.Get("key", v)`: not a route
            if reg.layout == "verbs" and any(_literal(a) for a in reg.rest):
                continue  # `client.Post("/v1/notes", "application/json", body)`: not a route
            for c in ctxs:
                handler = self.handler(src, reg, c.kind)
                if not self.handler_like(src, handler):
                    continue  # `conn.Delete("/locks/leader", -1)`: no handler, no route
                inner, wrappers = self.peel(src, handler)
                route = self.middleware_names(
                    src, [*self.route_middleware(src, reg, c.kind), *self.bound(src, reg.call)]
                )
                guards, unguards = _named([*route, *wrappers])
                full = _join(c.prefix, pattern if pattern is not None else src.text(raw)[:160])
                scoped = [g for p, gs in c.scoped if full.startswith(p) for g in gs]
                found = self.co.function(src, inner)
                if found is None and inner.type == "call_expression":
                    found = self.co.function(src, inner.child_by_field_name("function"))
                methods = list(c.methods) if reg.methods == ["ANY"] and c.methods else reg.methods
                for method in [method_in] if method_in else methods:
                    row = _row(
                        RouteFamily.GO_HTTP,
                        method,
                        full or "/",
                        src.text(handler)[:200],
                        src.file.rel,
                        src.line(reg.call),
                        guards,
                        _unique([*c.guards, *scoped]),
                        sorted({*unguards, *c.unguards}),
                    )
                    if found is not None:
                        row.handler_path, row.handler_line = (
                            found[0].file.rel,
                            found[0].line(found[1]),
                        )
                    receiver = src.text(reg.receiver)[:80]
                    rows.append(_mark(row, receiver, pattern is None or c.dynamic, src.file.rel))
        return rows


def _spread(args: list[Node]) -> list[Node]:
    """`append(adminChain, deleteUser)...` as a route's last argument: its elements."""
    last = args[-1] if args else None
    if last is not None and last.type == "variadic_argument" and last.named_children:
        inner = last.named_children[0]
        if inner.type == "call_expression" and inner.child_by_field_name("function") is not None:
            fn = inner.child_by_field_name("function")
            if fn.type == "identifier" and fn.text == b"append":
                return [*args[:-1], *_args(inner)]
    return args


def _literal(node: Node) -> bool:
    return (_unwrap(node) or node).type in (
        "interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal",
        "composite_literal", "true", "false",
    )  # fmt: skip


def _route_like(pattern: str | None, known: bool) -> bool:
    """A path a router takes: from `/` or a host, or for a known router `""`, `*` or `:id` too,
    or a computed one."""
    if pattern is None:
        return known
    if pattern.startswith("/") or _HOST_PATTERN.match(pattern):
        return True
    return known and (pattern == "" or pattern.startswith(("*", ":")))


@dataclass
class GoRoutes:
    rows: list[_Row]
    evidence: str | None  # a Go file that registers routes
    parsed: bool  # whether the Go parser was available


_REGISTERS = re.compile(
    r"\.(HandleFunc|Handle|HandlerFunc|Handler|Mount|Get|Post|Put|Delete|Patch|Head|Options|"
    r"GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|All|Method|MethodFunc|Match|Add)\("
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
