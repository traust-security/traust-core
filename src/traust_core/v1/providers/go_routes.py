"""Go HTTP routes and the guards on each, parsed with tree-sitter: net/http's `ServeMux`,
gorilla/mux, chi, gin, echo and fiber. A route's router is followed through groups, sub-routers,
mounts, the place it is served and the functions it is passed to; middleware a router `Use`s
guards the routes it covers (gin, fiber and echo groups: only those registered after it)."""

from __future__ import annotations

import ast
import posixpath
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
_HANDLER_TYPE = re.compile(
    r"\bHandler(Func)?\b|^func\s*\(\s*\w*\s*(http\.)?ResponseWriter\s*,\s*\w*\s*\*(http\.)?Request\s*\)"
)
_METHOD_CONST = re.compile(
    r"^(?:\w+\.)?Method(Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace)$"
)
# Go 1.22 `GET /notes/{id}`, `PROPFIND /dav/`, `M-SEARCH /discover`: a token, then the path
_METHOD_PATTERN = re.compile(r"^([A-Z][A-Z0-9!#$%&'*+.^_`|~-]*)\s+(\S.*)$")
_HOST_PATTERN = re.compile(r"^[\w-]+(\.[\w-]+)+(:\d+)?/")  # Go 1.22 `api.example.com/notes/{id}`
_ESCAPES = {"\\t": "\t", "\\n": "\n", "\\\\": "\\", '\\"': '"'}
_BUILD = re.compile(r"(?m)^//(go:build|\s*\+build)\s")
_GOOS = (r"aix|android|darwin|dragonfly|freebsd|hurd|illumos|ios|js|linux|nacl|netbsd|openbsd|"
         r"plan9|solaris|wasip1|windows|zos")  # fmt: skip
_GOARCH = (r"386|amd64|arm|arm64|loong64|mips|mipsle|mips64|mips64le|ppc64|ppc64le|riscv64|"
           r"s390x|wasm")  # fmt: skip
_FILE_CONSTRAINT = re.compile(rf"_({_GOOS}|{_GOARCH})(_({_GOARCH}))?\.go$")
# a router given to a function value, not middleware: `r.Route("/x", articleRoutes)`
_ROUTES_WITH_FN = {"Route"}
# library middleware that verifies but refuses nobody (jwtauth's Verifier sets the token only)
_LETS_THROUGH = re.compile(r"^Verif(ier|y)\w*$")  # of github.com/go-chi/jwtauth, by import path
# a middleware that is itself the handler step: it takes the request (`func(c *gin.Context)`)
_CONTEXT_PARAM = re.compile(
    r"\b(gin\.Context|echo\.Context|\w*\.?Ctx|ResponseWriter|RequestEvent)\b"
)
_GIN_CONTEXT = re.compile(r"\bgin\.Context\b")
_CONVERSIONS = {"http.HandlerFunc", "http.Handler", "echo.WrapHandler", "gin.WrapF", "gin.WrapH"}
# where a server's handler sits among its arguments: `ListenAndServeTLS(addr, cert, key, h)`
_SERVES = {
    "ListenAndServe": (2, 1),
    "ListenAndServeTLS": (4, 3),
    "Serve": (2, 1),
    "ServeTLS": (4, 1),
}
_DEFAULT_MUX = hash("net/http.DefaultServeMux")
# a framework router serving itself: gin `Run`/`RunTLS`, echo `Start*`, fiber `Listen*`
_RUNS = {"Run", "RunTLS", "RunUnix", "Start", "StartTLS", "StartAutoTLS", "StartServer",
         "StartH2CServer", "Listen", "ListenTLS"}  # fmt: skip
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
        self.dot_imports: list[str] = []
        for spec in walk(root):
            if spec.type != "import_spec":
                continue
            path = self.string(spec.child_by_field_name("path")) or ""
            name = spec.child_by_field_name("name")
            alias = self.text(name) if name is not None else _package_name(path)
            if alias == ".":
                self.dot_imports.append(path)  # `import . "github.com/go-chi/jwtauth/v5"`
            elif alias != "_":
                self.imports[alias] = path
        self.kinds = {
            alias: kind
            for alias, path in self.imports.items()
            for kind, rx in _FRAMEWORKS
            if rx.match(path)
        }
        # `import . "github.com/gin-gonic/gin"`: its names are bare (`Default()`, `Server{}`)
        self.dot_kinds = {kind for p in self.dot_imports for kind, rx in _FRAMEWORKS if rx.match(p)}
        head = re.split(r"(?m)^package\s", file.text, maxsplit=1)[0]
        # built only under some tags: its middleware may not be the one that runs (D42)
        self.constrained = bool(_BUILD.search(head) or _FILE_CONSTRAINT.search(file.name))

    def string(self, node: Node | None) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "interpreted_string_literal":
            data = b"".join(
                _escape_bytes(self.text(c))
                if c.type == "escape_sequence"
                else self.text(c).encode()
                for c in node.named_children
                if c.type in ("interpreted_string_literal_content", "escape_sequence")
            )
            return data.decode("utf-8", "replace")  # `"/caf\xc3\xa9"` is `/café`
        if node.type == "raw_string_literal":
            return self.text(node)[1:-1]
        return None


def _escape_bytes(text: str) -> bytes:
    """A Go escape sequence's bytes: `\\xNN` and octal are one byte each (a UTF-8 sequence
    spans several), `\\u`/`\\U` a character's UTF-8."""
    if re.fullmatch(r"\\x[0-9A-Fa-f]{2}", text):
        return bytes([int(text[2:], 16)])
    if re.fullmatch(r"\\[0-7]{3}", text):
        return bytes([int(text[1:], 8) & 0xFF])
    if text in _ESCAPES:
        return _ESCAPES[text].encode()
    try:
        return str(ast.literal_eval('"' + text + '"')).encode()
    except (ValueError, SyntaxError):
        return text.encode()


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
    if node.type in ("identifier", "field_identifier", "package_identifier", "type_identifier"):
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


def _receivers(src: _Source, fn: Node) -> set[str]:
    """The receiver's name of a method (`s` in `func (s *server) routes()`)."""
    recv = fn.child_by_field_name("receiver")
    if recv is None:
        return set()
    return {
        src.text(c) for p in recv.named_children for c in p.named_children if c.type == "identifier"
    }


def _receiver_type(src: _Source, fn: Node) -> str:
    """`Handler` of `(h *Handler)` and of `(h *Handler[T])`."""
    text = re.sub(r"\[[^\]]*\]", "", src.text(fn.child_by_field_name("receiver")))
    words = re.findall(r"\w+", text)
    return words[-1] if words else ""


def _top_level(node: Node, fn: Node, reach: Node | None = None) -> bool:
    """A statement that surely runs in `fn` before `reach` does: every branch, loop, case or
    `go`/`defer` around it also holds `reach` (with no `reach`, none may; a bare `{ .. }`
    block always runs)."""
    prev, cur = node, node.parent
    while cur is not None:
        if cur.type in _FUNCS:
            return cur == fn
        if cur.type in _BRANCHES and not (
            reach is not None and prev.start_byte <= reach.start_byte < prev.end_byte
        ):
            return False  # the arm it sits in (`if`'s then, its `else`) must hold the route
        prev, cur = cur, cur.parent
    return False


_BRANCHES = {
    "if_statement", "for_statement", "expression_switch_statement", "type_switch_statement",
    "select_statement", "expression_case", "default_case", "type_case", "communication_case",
    "go_statement", "defer_statement",
}  # fmt: skip


def _id(src: _Source, node: Node) -> int:
    return hash((src.file.rel, node.start_byte, node.end_byte))


def _scope(n: Node) -> tuple[int, int]:
    """The byte range a binding statement is visible in: its enclosing block, or the `if`,
    `for` or `switch` whose initializer it is (`if r := gin.New(); ok { .. }`)."""
    holder = n.parent.parent if n.parent is not None and n.parent.type == "for_clause" else n.parent
    if holder is not None and holder.type in (
        "if_statement", "for_statement", "expression_switch_statement", "type_switch_statement",
    ):  # fmt: skip
        return holder.start_byte, holder.end_byte
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
        if (
            _LOADS.match(last)
            or _HEADERS.match(last)
            or last.lower().startswith("secure")
            or any(s.lower() == "secure" for s in name.split(".")[:-1])
        ):
            continue  # loaders and response-header middleware (`secure.New`, `SecureWithConfig`)
        if GUARD_RX.search(NON_ENFORCING_RX.sub("", name)):
            guards.append(name)
    return _unique(guards), sorted(set(unguards))


@dataclass
class _Binding:
    stmt: Node
    value: Node
    scope: tuple[int, int]
    own: bool  # declared in the statement (`:=`/`var`), not assigned
    closure: bool = False  # assigned in a closure: may have run, any time


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
    ambiguous: set[tuple[str, str]] = field(default_factory=set)
    handler_types: set[str] = field(default_factory=set)  # types with a `ServeHTTP` method
    package_vars: set[tuple[str, str]] = field(default_factory=set)  # declared with no value
    ambiguous_values: set[tuple[str, str]] = field(default_factory=set)
    early: set[tuple[str, str]] | None = None  # names an `init` or package initializer reaches

    def index(self, files: list[TreeFile]) -> None:
        for src in self.sources:
            for n in walk(src.root):
                if (
                    n.type == "method_declaration"
                    and src.text(n.child_by_field_name("name")) == "ServeHTTP"
                ):
                    self.handler_types.add(_receiver_type(src, n))
        for f in files:
            if f.name == "go.mod" and (m := re.search(r"(?m)^module\s+(\S+)", f.text)):
                self.modules[m[1]] = str(PurePosixPath(f.rel).parent)
        for src in self.sources:
            for n in walk(src.root):
                if n.type == "function_declaration" and (name := n.child_by_field_name("name")):
                    key = (src.dir, src.text(name))
                    if key in self.functions:
                        self.ambiguous.add(key)  # build variants: which one runs isn't told
                    self.functions.setdefault(key, (src, n))
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
                            words = re.findall(r"\w+", ftype)
                            if (
                                _HANDLER_TYPE.search(ftype)
                                or ftype.startswith("func")
                                or (words and words[-1] in self.handler_types)
                            ):
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
                previous: list[Node] = []
                for spec in walk(decl):
                    if spec.type not in ("var_spec", "const_spec"):
                        continue
                    names = [c for c in spec.named_children if c.type == "identifier"]
                    value = spec.child_by_field_name("value")
                    values = value.named_children if value is not None else []
                    if spec.type == "const_spec":  # `const ( a = "/api"; b )`: b repeats a's value
                        values = values or previous
                        previous = values
                    for i, name in enumerate(names):
                        if i < len(values):
                            key = (src.dir, src.text(name))
                            if key in self.package_values:
                                self.ambiguous_values.add(key)  # build variants: which isn't told
                            self.package_values[key] = (src, values[i])
                        elif spec.type == "var_spec":  # `var requireAuth func(..)`: set later
                            self.package_vars.add((src.dir, src.text(name)))

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
                              "const_spec", "range_clause"):  # fmt: skip
                continue
            if _enclosing(n) != fn:
                if n.type == "assignment_statement":  # `f := func() { h = plain }`
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    values = right.named_children if right is not None else []
                    for i, name in enumerate(left.named_children if left is not None else []):
                        if name.type == "identifier" and i < len(values):
                            out.setdefault(src.text(name), []).append(
                                _Binding(n, values[i], (0, 0), False, True)
                            )
                continue
            if n.type == "range_clause":  # `for _, r := range rs`: shadows, holds no router
                loop = n.parent
                left = n.child_by_field_name("left")
                for name in left.named_children if left is not None else []:
                    if name.type == "identifier" and loop is not None:
                        span = (loop.start_byte, loop.end_byte)
                        out.setdefault(src.text(name), []).append(_Binding(n, n, span, True))
                continue
            if n.type in ("var_spec", "const_spec"):
                names = [c for c in n.named_children if c.type == "identifier"]
                value = n.child_by_field_name("value")
                values = value.named_children if value is not None else [n] * len(names)
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
            if b.closure:
                continue
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
            if b.closure:
                out.append(b)
                continue
            if b.stmt.start_byte >= at.start_byte or b.own:
                continue
            if b.scope[0] <= at.start_byte < b.scope[1]:
                continue
            if latest is None or b.stmt.start_byte > latest.stmt.start_byte:
                out.append(b)
        return out

    def function(
        self, src: _Source, expr: Node | None, typed: bool = False
    ) -> tuple[_Source, Node] | None:
        """The checkout function or method an expression names: `listNotes`, `api.ListNotes`,
        `h.GetNote` (a method by name, of the value's type when the code says it; `typed`: only
        then)."""
        expr = _unwrap(expr)
        if expr is None:
            return None
        if expr.type == "func_literal":
            return src, expr
        if expr.type == "index_expression":  # `RequireAuth[int]`: the generic function
            return self.function(
                src, expr.named_children[0] if expr.named_children else None, typed
            )
        if expr.type == "identifier":
            key = (src.dir, src.text(expr))
            if key in self.ambiguous or self.shadowed(src, expr):
                return None  # build variants, or a local or parameter of that name
            if key in self.functions:
                return self.functions[key]
            dotted = [  # `import . "example.com/app/handlers"`: its names are bare
                (where, key[1])
                for path in src.dot_imports
                if (where := self.directory(path)) is not None
            ]
            found = [self.functions[k] for k in dotted if k in self.functions]
            if any(k in self.ambiguous for k in dotted) or len(found) != 1:
                return None
            return found[0]
        if expr.type != "selector_expression":
            return None
        operand = expr.child_by_field_name("operand")
        name = src.text(expr.child_by_field_name("field"))
        alias = src.text(operand) if operand is not None else ""
        if operand is not None and operand.type == "identifier" and alias in src.imports:
            where = self.directory(src.imports[alias])
            if where is None or (where, name) in self.ambiguous:
                return None
            return self.functions.get((where, name))
        if operand is not None and self.external(src, operand):
            return None  # `svc := notesvc.New(db)`: a library's type, not a namesake's
        found = self.methods.get(name, [])
        kind = self.type_of(src, operand) if operand is not None else ""
        if typed and not kind:
            return None  # a namesake's method by name alone may be a library's (D42)
        if kind:
            found = [m for m in found if m[2] == kind]
        home = self.type_home(src, operand) if operand is not None else None
        if home == "":
            return None  # `svc extlib.Service`: a library's type has no checkout methods
        if home:
            found = [m for m in found if m[0].dir == home]
        return (found[0][0], found[0][1]) if len(found) == 1 else None

    def shadowed(self, src: _Source, node: Node) -> bool:
        """A name a local binding, parameter or receiver holds where `node` reads it."""
        name = src.text(node)
        fn = _enclosing(node)
        while fn is not None:
            if self.declares(src, node, name, fn) or name in {
                p for p, _ in _params(src, fn)
            } | _receivers(src, fn):
                return True
            fn = _enclosing(fn)
        return False

    def runs_after_init(self, src: _Source, fn: Node | None) -> bool:
        """Whether code in `fn` surely runs after every `init`: no `init` or package
        initializer names its function, directly or through what they name (D42)."""
        while fn is not None and fn.type == "func_literal":
            fn = _enclosing(fn)
        if fn is None or _is_init(src, fn):
            return False
        name = src.text(fn.child_by_field_name("name"))
        key = ("method", name) if fn.type == "method_declaration" else (src.dir, name)
        return key not in self.reached_early()

    def reached_early(self) -> set[tuple[str, str]]:
        if self.early is not None:
            return self.early
        todo = [
            (src, decl)
            for src in self.sources
            for decl in src.root.named_children
            if decl.type == "var_declaration" or _is_init(src, decl)
        ]
        self.early, seen = set(), set()
        while todo:
            src, node = todo.pop()
            for n in walk(node):
                keys = []
                if n.type == "identifier":
                    keys = [(src.dir, src.text(n))] + [
                        (where, src.text(n))
                        for path in src.dot_imports
                        if (where := self.directory(path)) is not None
                    ]
                elif n.type == "selector_expression":
                    operand = n.child_by_field_name("operand")
                    name = src.text(n.child_by_field_name("field"))
                    alias = src.text(operand) if operand is not None else ""
                    if alias not in src.imports:
                        keys = [("method", name)]
                    elif (where := self.directory(src.imports[alias])) is not None:
                        keys = [(where, name)]  # a library's (`gin.New`) runs no checkout code
                for key in keys:
                    if key in self.early:
                        continue
                    self.early.add(key)
                    found = (
                        [(m[0], m[1]) for m in self.methods.get(key[1], [])]
                        if key[0] == "method"
                        else [self.functions[key]]
                        if key in self.functions
                        else []
                    )
                    for fsrc, fn in found:
                        if _id(fsrc, fn) not in seen:
                            seen.add(_id(fsrc, fn))
                            todo.append((fsrc, fn))
        return self.early

    def local_const(self, src: _Source, node: Node) -> Node | None:
        """The value of the local `const` a name reads, where a local holds it; else None."""
        name, fn = src.text(node), _enclosing(node)
        while fn is not None:
            if self.declares(src, node, name, fn):
                b = self.binding(src, node, name, fn)
                return b.value if b is not None and b.stmt.type == "const_spec" else None
            if name in {p for p, _ in _params(src, fn)} | _receivers(src, fn):
                return None
            fn = _enclosing(fn)
        return None

    def declares(self, src: _Source, at: Node, name: str, fn: Node) -> bool:
        """`name := ..` or `var name` in `fn` before `at`, in a scope `at` sees (an assignment
        `name = ..` to a package variable declares nothing)."""
        return any(
            b.own and not b.closure and b.stmt.start_byte < at.start_byte
            and b.scope[0] <= at.start_byte < b.scope[1]
            for b in self.bindings(src, fn).get(name, [])
        )  # fmt: skip

    def external(self, src: _Source, value: Node) -> bool:
        """A value a library builds: bound to `pkg.New(..)` of a package outside the checkout."""
        value = _unwrap(value) or value
        if value.type != "identifier":
            return False
        call = _unwrap(self.bound_value(src, value))
        if call is None or call.type != "call_expression":
            return False
        operand, _ = _field(src, call)
        alias = src.text(operand) if operand is not None else ""
        return alias in src.imports and self.directory(src.imports[alias]) is None

    def bound_value(self, src: _Source, value: Node) -> Node | None:
        """What a name is bound to where it is read: its local binding, else its package value."""
        fn = _enclosing(value)
        bound = self.binding(src, value, src.text(value), fn) if fn is not None else None
        if bound is not None:
            return bound.value
        key = (src.dir, src.text(value))
        if self.shadowed(src, value) or key not in self.package_values:
            return None
        return None if key in self.ambiguous_values else self.package_values[key][1]

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
        key = (src.dir, name)  # `var auth = &Auth{}`: a package value's
        if key in self.package_values and key not in self.ambiguous_values:
            vsrc, bound_value = self.package_values[key]
            return self.value_type(vsrc, bound_value)
        return ""

    def type_home(self, src: _Source, value: Node) -> str | None:
        """The checkout package a value's named type is declared in, where the code says it:
        "" for a library's type, None where it isn't told."""
        value = _unwrap(value) or value
        if value.type != "identifier":
            return None
        name = src.text(value)
        fn = _enclosing(value)
        while fn is not None:
            for p, kind in _params(src, fn):
                if p == name:
                    return self.kind_home(src, kind)
            recv = fn.child_by_field_name("receiver")
            if recv is not None and re.search(rf"\b{re.escape(name)}\b", src.text(recv)):
                return src.dir
            bound = self.binding(src, value, name, fn)
            if bound is not None:
                return self.value_home(src, bound.value)
            fn = _enclosing(fn)
        key = (src.dir, name)
        if key in self.package_values and key not in self.ambiguous_values:
            vsrc, bound_value = self.package_values[key]
            return self.value_home(vsrc, bound_value)
        return None

    def kind_home(self, src: _Source, kind: str) -> str | None:
        first = kind.strip().strip("()").split(",")[0]
        m = re.fullmatch(r"[\s*&\[\]]*(?:(\w+)\.)?(\w+)\s*(?:\[[^\]]*\])?\s*", first)
        if m is None:
            return None
        if m[1] is None:
            return None if src.dot_imports else src.dir
        if m[1] not in src.imports:
            return None
        where = self.directory(src.imports[m[1]])
        return where if where is not None else ""

    def value_home(self, src: _Source, value: Node) -> str | None:
        """`&T{..}` / `pkg.T{..}`, `pkg.New(..)` of a library, or a checkout function's result."""
        inner = _unwrap(value) or value
        if inner.type == "composite_literal":
            return self.kind_home(src, src.text(inner.child_by_field_name("type")))
        if inner.type != "call_expression":
            return None
        callee = _unwrap(inner.child_by_field_name("function"))
        if callee is None:
            return None
        if callee.type == "selector_expression":
            operand = callee.child_by_field_name("operand")
            alias = src.text(operand) if operand is not None else ""
            if alias not in src.imports:
                return None
            if self.directory(src.imports[alias]) is None:
                return ""  # `extlib.New(..)`: a library's value
        elif callee.type != "identifier":
            return None
        found = self.function(src, callee)
        if found is None or found[1].type == "func_literal":
            return None
        return self.kind_home(found[0], found[0].text(found[1].child_by_field_name("result")))

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
        alias, _, fn_name = (
            _callee(src, node).partition(".") if node.type == "call_expression" else ("", "", "")
        )
        if fn_name == "Join" and src.imports.get(alias) == "path":  # `path.Join`, `p.Join`
            parts = [self.string(src, a, depth + 1) for a in _args(node)]
            if not parts or any(p is None for p in parts):
                return None
            joined = "/".join(p for p in parts if p)  # type: ignore[misc]
            if not joined:
                return ""
            cleaned = posixpath.normpath(
                joined
            )  # as Go's path.Clean: `/api/../health` is `/health`
            return "/" + cleaned.lstrip("/") if joined.startswith("/") else cleaned
        key: tuple[str, str] | None = None
        if node.type == "identifier" and self.shadowed(src, node):
            local = self.local_const(src, node)
            return self.string(src, local, depth + 1) if local is not None else None
        if node.type == "identifier":
            key = (src.dir, src.text(node))
        elif node.type == "selector_expression":
            operand = node.child_by_field_name("operand")
            alias = src.text(operand) if operand is not None else ""
            where = self.directory(src.imports[alias]) if alias in src.imports else None
            key = (where, src.text(node.child_by_field_name("field"))) if where else None
        if key is not None and key in self.package_values and key not in self.ambiguous_values:
            vsrc, value = self.package_values[key]
            return None if vsrc.constrained else self.string(vsrc, value, depth + 1)
        return None


def _literal_type(src: _Source, value: Node) -> str:
    text = src.text(value)
    if m := re.match(r"&?\s*(?:\w+\.)?(\w+)\s*(?:\[[^\]]*\])?\s*\{", text):
        return m[1]
    if m := re.match(r"(?:\w+\.)?New(\w+)\s*\(", text):
        return m[1]
    return ""


def _method(src: _Source, node: Node | None, co: _Checkout | None = None) -> str | None:
    """A method argument: `"GET"`, net/http's `http.MethodGet` (or a framework's that is
    net/http's), or a checkout constant's value."""
    if (text := src.string(node)) is not None:
        return text.upper()
    node = _unwrap(node)
    if node is None:
        return None
    if co is not None and (value := co.string(src, node)) is not None:
        return value.upper()  # `const MethodGet = "POST"` is POST
    m = _METHOD_CONST.match(src.text(node))
    if m is None:
        return None
    if node.type == "selector_expression":
        alias = src.text(node.child_by_field_name("operand"))
        return m[1].upper() if src.kinds.get(alias) in ("http", "fiber", "echo") else None
    return m[1].upper() if "http" in src.dot_kinds else None


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
    router_only: bool = False  # a route only on a known gin/echo/fiber router


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
        self.passing: dict[tuple[int, int], bool] = {}
        self.surely_mw: dict[int, bool] = {}
        self.valued: dict[str, set[str]] = {}
        self.package_sets: dict[tuple[str, str], list[tuple[_Source, Node]]] = {}
        self.early: dict[int, list[int]] = {}
        self.gotos: dict[int, list[int]] = {}
        self.helper_uses: dict[tuple[int, str, int], list[tuple[_Source, Node, int]]] = {}
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
                inner = _unwrap(served) or served
                if (
                    inner.type == "call_expression"
                    and _name(src, inner) in _CONVERSIONS
                    and _args(inner)
                ):
                    inner = _unwrap(_args(inner)[0]) or inner  # `http.Handler(nil)`
                if inner.type == "nil" or served.type in (
                    "qualified_type",
                    "type_identifier",
                    "field_identifier",
                ):
                    self.serves.setdefault(_DEFAULT_MUX, []).append([])
                    continue
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
            verb = _method(src, args[0], self.co) or "ANY"
            return _Reg(call, receiver, [verb], args[1], [args[2]], "fixed")
        if (
            name in ("Handle", "Add")
            and len(args) >= 3
            and (verb := _method(src, args[0], self.co))
        ):
            return _Reg(call, receiver, [verb], args[1], _spread(args[2:]), "verbs")
        if (
            name in ("Handle", "Add")
            and len(args) >= 3
            and (_unwrap(args[0]) or args[0]).type == "identifier"
            and src.string(args[1]) is not None
        ):  # `for _, m := range methods { r.Handle(m, "/users/:id", h) }`
            return _Reg(call, receiver, ["ANY"], args[1], _spread(args[2:]), "verbs")
        if (
            name == "Use"
            and len(args) == 2
            and src.string(args[0]) is not None
            and self.identity(src, args[1])
        ):
            return _Reg(call, receiver, ["ANY"], args[0], [args[1]], "fixed", True)  # fiber mount
        if name in ("Match", "Add") and len(args) >= 3 and args[0].type == "composite_literal":
            verbs = [m for a in walk(args[0]) if (m := _method(src, a, self.co))] or ["ANY"]
            reg = _Reg(call, receiver, verbs, args[1], _spread(args[2:]), "verbs")
            reg.router_only = True  # `store.Match([]string{..}, key, fn)` is no route
            return reg
        if name == "Match" and len(args) >= 3:
            verbs = [m for a in walk(args[0]) if (m := _method(src, a, self.co))] or ["ANY"]
            return _Reg(call, receiver, verbs, args[1], args[2:], "verbs")
        if lower in _VERBS | _ANY and len(args) >= 2:
            verb = "ANY" if lower in _ANY else name.upper()
            return _Reg(call, receiver, [verb], args[0], _spread(args[1:]), "verbs")
        return None

    def own_function(self, src: _Source, call: Node) -> bool:
        found = self.co.function(src, call.child_by_field_name("function"), typed=True)
        return found is not None and found[1].type != "func_literal"

    def own_method(self, src: _Source, call: Node) -> bool:
        """A call to a method of the checkout's own type that registers no route itself."""
        found = self.co.function(src, call.child_by_field_name("function"), typed=True)
        if found is None or found[1].type != "method_declaration":
            return False
        fsrc, fn = found
        body = fn.child_by_field_name("body") or fn
        return not any(
            n.type == "call_expression" and self.registration(fsrc, n) is not None
            for n in walk(body)
        )

    def handler(self, src: _Source, reg: _Reg, kind: str) -> Node:
        """The handler among a route's arguments: last for gin and fiber (in order), first for
        echo (its middleware follow it)."""
        if reg.layout == "fixed" or len(reg.rest) == 1:
            return reg.rest[0]
        return reg.rest[0] if (kind or self.kind_hint(src)) == "echo" else reg.rest[-1]

    def route_middleware(self, src: _Source, reg: _Reg, kind: str) -> list[Node]:
        if reg.layout == "fixed" or len(reg.rest) == 1:
            return []
        kind = kind or self.kind_hint(src)
        if not kind:  # echo puts middleware after the handler, the rest before: only the middle
            return reg.rest[1:-1]
        return reg.rest[1:] if kind == "echo" else reg.rest[:-1]

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

    def unbound(self, src: _Source, call: Node) -> bool:
        """`rg.DELETE(..).Unbind(id)`: a route that drops middleware by id; which isn't told."""
        node = call
        while (
            node.parent is not None
            and node.parent.type == "selector_expression"
            and node.parent.parent is not None
            and node.parent.parent.type == "call_expression"
        ):
            node = node.parent.parent
            if _field(src, node)[1] == "Unbind":
                return True
        return False

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
                methods += [m for a in _args(n) if (m := _method(src, a, self.co))]
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
        a handler-typed value, a struct that serves HTTP (`&usersHandler{}`), or a call that
        builds or wraps one. Data (`db`, `&out`, `-1`, another struct literal) is none."""
        if depth > _MAX_DEPTH:
            return False
        inner = _unwrap(node) or node
        if inner.type == "composite_literal":
            return _literal_type(src, inner) in self.co.handler_types
        if node.type == "unary_expression":
            return False
        node = _unwrap(node) or node
        if node.type in ("func_literal", "index_expression", "type_conversion_expression"):
            return True  # a closure, a generic handler (`getOne[Note]`) or wrapper (`Wrap[int](h)`)
        if node.type == "call_expression":
            return True  # `api.ListSessions(db)`, `auth(h)`: a handler built or wrapped
        if node.type == "identifier":
            name = src.text(node)
            fn = _enclosing(node)
            while fn is not None:
                bound = self.co.binding(src, node, name, fn)
                if bound is not None:
                    value = _unwrap(bound.value) or bound.value
                    if value.type == "range_clause":
                        return True  # `for p, h := range routes`: whatever the table holds
                    if (
                        value.type == "composite_literal"
                        and node.parent is not None
                        and node.parent.type == "variadic_argument"
                    ):
                        return True  # `r.DELETE(path, handlers...)`
                    if value.type == "composite_literal":
                        return _literal_type(src, value) in self.co.handler_types
                    if value.type == "call_expression":
                        found = self.co.function(src, value.child_by_field_name("function"))
                        if found is not None and found[1].type != "func_literal":
                            result = found[0].text(found[1].child_by_field_name("result"))
                            words = re.findall(r"\w+", result)
                            # `cfg := loadConfig()`: a checkout function that returns no handler
                            return bool(
                                _HANDLER_TYPE.search(result)
                                or _TYPED.search(result)
                                or (words and words[-1] in self.co.handler_types)
                            ) or bool(self.identity(src, value))
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
            if inner.type in ("func_literal", "call_expression", "index_expression"):
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
        key = (_id(*found), index)
        if key not in self.passing:
            self.passing[key] = False  # a recursion passes nothing on
            self.passing[key] = self._passes_on(found[0], found[1], index, depth)
        return self.passing[key]

    def _passes_on(self, fsrc: _Source, fn: Node, index: int, depth: int) -> bool:
        params = _params(fsrc, fn)
        if fn.type == "func_literal" or index >= len(params) or not params[index][0]:
            return False
        if params[index][1] and not (
            _HANDLER_TYPE.search(params[index][1]) or _TYPED.search(params[index][1])
        ):
            return False  # `write func(http.ResponseWriter, any)`: a callback, not a handler
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
        paths = []
        for r in self.co.returned(fsrc, fn):
            inner, names = self.peel(fsrc, r)
            if inner.type == "identifier" and fsrc.text(inner) == params[index][0]:
                paths.append(names)
        if not paths:
            return []
        return [n for n in paths[0] if all(n in p for p in paths[1:])]  # on every path (D42)

    def certain(self, src: _Source, call: Node, index: int) -> bool:
        """A wrapper that always wraps: a library's (taken at its word), an unseen function's,
        or a checkout function every return path of which builds a new handler (D42)."""
        if src.constrained:
            return False
        fn_node = call.child_by_field_name("function")
        inner = _unwrap(fn_node)
        if inner is not None and inner.type == "call_expression":  # `RequireRole("admin")(h)`
            factory = self.co.function(src, inner.child_by_field_name("function"))
            if factory is not None:
                return factory[1].type != "func_literal" and self.middleware_value(*factory)
        found = self.co.function(src, fn_node)
        if found is None and inner is not None and inner.type == "identifier":
            fn = _enclosing(inner)
            values = self.co.values(src, inner, src.text(inner), fn) if fn is not None else []
            literal = _unwrap(values[0].value) if len(values) == 1 else None
            if literal is not None and literal.type == "func_literal":  # `wrap := func(h) ..`
                found = (src, literal)
        if found is None:
            return self.unseen(src, fn_node)
        fsrc, fn = found
        params = _params(fsrc, fn)
        if index >= len(params):
            return False
        return self.always_wraps(fsrc, fn, params[index][0])

    def unseen(self, src: _Source, node: Node | None) -> bool:
        """A callee the checkout defines nothing for: a library's (`jwtauth.Verifier`,
        `cors.New(..).Handler`) or a function this checkout can't see. A package variable, a
        field, a parameter or an interface method may hold anything, so it is no callee."""
        node = _unwrap(node)
        if node is None:
            return False
        if node.type == "call_expression":
            return self.unseen(src, node.child_by_field_name("function"))
        if node.type == "identifier":
            key = (src.dir, src.text(node))
            return key not in self.co.functions and self.bare_function(src, node)
        if node.type == "selector_expression":
            operand = _unwrap(node.child_by_field_name("operand"))
            if operand is None:
                return False
            if operand.type == "identifier" and src.text(operand) in src.imports:
                # a library's; a checkout package's name is a function only if it resolves to one
                return self.co.directory(src.imports[src.text(operand)]) is None
            return operand.type in ("call_expression", "identifier") and self.unseen(src, operand)
        return node.type in ("index_expression", "type_conversion_expression")

    def always_wraps(self, fsrc: _Source, fn: Node, param: str, depth: int = 0) -> bool:
        """Every return path of a wrapper builds a new handler around `param`: a closure, a
        conversion of one, or another such wrapper's or a library's call. Handing it back bare,
        aliased or converted (`return next`, `http.HandlerFunc(next.ServeHTTP)`) builds none."""
        if fsrc.constrained or depth > _MAX_DEPTH:
            return False
        returns = self.co.returned(fsrc, fn)
        return bool(returns) and all(self.builds(fsrc, r, depth, param) for r in returns)

    def builds(self, src: _Source, r: Node, depth: int, param: str = "") -> bool:
        r = _unwrap(r) or r
        if r.type == "func_literal":
            if any(_HANDLER_TYPE.search(k) for _, k in _params(src, r)):
                return self.middleware_value(src, r, depth + 1)  # `return func(next) {..}`
            return _forwards_once(src, r, param)
        if r.type == "composite_literal":  # PocketBase `&hook.Handler{Func: requireAuth(..)}`
            values = [
                _unwrap(k.named_children[-1]) or k.named_children[-1]
                for k in walk(r.child_by_field_name("body") or r)
                if k.type == "keyed_element" and k.named_children
            ]
            funcs = [v for v in values if v.type == "func_literal" or self.returns_func(src, v)]
            return bool(funcs) and all(
                self.middleware_value(src, v, depth + 1)
                if v.type == "func_literal"
                else self.builds(src, v, depth + 1)
                for v in funcs
            )
        if r.type == "type_conversion_expression" or (
            r.type == "call_expression" and _name(src, r) in _CONVERSIONS
        ):
            inner = (
                r.child_by_field_name("operand")
                if r.type == "type_conversion_expression"
                else (_args(r)[0] if _args(r) else None)
            )
            inner = _unwrap(inner) or inner if inner is not None else None
            return (
                inner is not None
                and inner.type == "func_literal"
                and _forwards_once(src, inner, param)
            )
        if r.type != "call_expression":
            return False
        found = self.co.function(src, r.child_by_field_name("function"))
        if found is None:
            return self.unseen(src, r.child_by_field_name("function"))
        fsrc, fn = found
        if fn.type == "func_literal":
            return False
        return self.middleware_value(fsrc, fn, depth + 1)

    def returns_func(self, src: _Source, value: Node) -> bool:
        """A call to a checkout function that returns a function (`requireAuth(..)`)."""
        if value.type != "call_expression":
            return False
        found = self.co.function(src, value.child_by_field_name("function"))
        if found is None or found[1].type == "func_literal":
            return False
        result = found[0].text(found[1].child_by_field_name("result"))
        return result.lstrip("*").startswith("func") or bool(_HANDLER_TYPE.search(result))

    def middleware_value(self, fsrc: _Source, fn: Node, depth: int = 0) -> bool:
        """A checkout middleware that surely does its work: a handler step itself (it takes the
        request: `func(c *gin.Context)`), a wrapper that always wraps its handler, or a factory
        every return of which is such a middleware (D42)."""
        if fsrc.constrained or depth > _MAX_DEPTH:
            return False
        key = _id(fsrc, fn)
        if key in self.surely_mw:
            return self.surely_mw[key]
        self.surely_mw[key] = False
        params = _params(fsrc, fn)
        handlers = [n for n, k in params if _HANDLER_TYPE.search(k) or _TYPED.search(k)]
        if handlers:
            ok = self.always_wraps(fsrc, fn, handlers[0], depth)
        elif contexts := [n for n, k in params if _CONTEXT_PARAM.search(k)]:
            ok = _forwards_once(fsrc, fn, contexts[0], "Next")
        else:
            returns = self.co.returned(fsrc, fn)
            ok = bool(returns) and all(
                self.middleware_value(fsrc, _unwrap(r) or r, depth + 1)
                if (_unwrap(r) or r).type == "func_literal"
                else self.builds(fsrc, r, depth)
                for r in returns
            )
        self.surely_mw[key] = ok
        return ok

    def stringish(self, src: _Source, node: Node, depth: int = 0) -> bool:
        """A value that is text: a string, a `+` of strings, `fmt.Sprintf`, `os.Getenv`,
        `path.Join`, a `[]string`, or a local bound once to one."""
        node = _unwrap(node) or node
        if depth > _MAX_DEPTH:
            return False
        if node.type in ("interpreted_string_literal", "raw_string_literal", "binary_expression"):
            return True
        if node.type == "composite_literal":
            return "string" in src.text(node.child_by_field_name("type"))
        if node.type == "call_expression":
            return bool(
                re.match(
                    r"(fmt\.Sprint|os\.Getenv|path\.|filepath\.|strings\.|url\.)", _name(src, node)
                )
            )
        if node.type == "identifier":
            fn = _enclosing(node)
            values = self.co.values(src, node, src.text(node), fn) if fn is not None else []
            if len(values) == 1 and values[0].value.type != "var_spec":
                return self.stringish(src, values[0].value, depth + 1)
            return (src.dir, src.text(node)) in self.co.package_values and self.co.string(
                src, node
            ) is not None
        return False

    def credited(self, src: _Source, node: Node, depth: int = 0) -> list[str]:
        """The names a middleware value may be credited by (D42): a library's, an unseen
        function's, or a checkout middleware that surely does its work; a local bound once to
        one of those. Variables, fields, parameters and interfaces may hold anything: none."""
        node = _unwrap(node) or node
        if src.constrained or depth > _MAX_DEPTH:
            return []
        if self.lets_through(src, node):
            return []
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            found = self.co.function(src, fn_node, typed=True)
            if found is None:
                return [_name(src, node)] if self.unseen(src, fn_node) else []
            ok = found[1].type != "func_literal" and self.middleware_value(found[0], found[1])
            return [_name(src, node)] if ok else []
        if node.type in ("identifier", "selector_expression"):
            found = self.co.function(src, node, typed=True)
            if found is not None:
                ok = found[1].type != "func_literal" and self.middleware_value(found[0], found[1])
                return [_name(src, node)] if ok else []
            if node.type == "identifier":
                fn = _enclosing(node)
                values = self.co.values(src, node, src.text(node), fn) if fn is not None else []
                if (
                    len(values) == 1
                    and (_unwrap(values[0].value) or values[0].value).type == "call_expression"
                ):
                    return self.credited(src, values[0].value, depth + 1)
            return [_name(src, node)] if self.unseen(src, node) else []
        return []

    def lets_through(self, src: _Source, node: Node) -> bool:
        """Library middleware that may let a request through unrefused: jwtauth's Verifier
        (under any import name), anything configured with a `Skipper`, or with a config value
        it doesn't read inline (`JWTWithConfig(cfg)`: `cfg` may carry one)."""
        node = _unwrap(node) or node
        dotted = _name(src, node)
        alias, _, rest = dotted.partition(".")
        dot = "." not in dotted and any("go-chi/jwtauth" in p for p in src.dot_imports)
        if (dot and _LETS_THROUGH.match(dotted)) or (
            "go-chi/jwtauth" in src.imports.get(alias, "")
            and _LETS_THROUGH.match(rest.rsplit(".", 1)[-1])
        ):
            return True
        if any(
            k.type == "keyed_element"
            and k.named_children
            and src.text(_unwrap(k.named_children[0]) or k.named_children[0]) == "Skipper"
            for k in walk(node)
        ):
            return True
        return (
            node.type == "call_expression"
            and "Config" in dotted
            and any((_unwrap(a) or a).type != "composite_literal" for a in _args(node))
        )

    def mw(self, src: _Source, nodes: list[Node]) -> tuple[list[str], list[str]]:
        """Guards from the middleware that surely runs, unguards from any named (D42)."""
        guards, _ = _named([n for x in nodes for n in self.credited(src, x)])
        _, unguards = _named(self.middleware_names(src, nodes))
        return guards, unguards

    def surely(self, src: _Source, node: Node, fn: Node, reach: Node | None) -> bool:
        """`_top_level`, and no `return` before it that could end the run first, unless the
        route itself comes later in the same function (that return skips it too)."""
        if not _top_level(node, fn, reach):
            return False
        key = _id(src, fn)
        if key not in self.early:
            body = fn.child_by_field_name("body") or fn
            self.early[key] = [
                r.start_byte
                for r in walk(body)
                if r.type == "return_statement" and _enclosing(r) == fn
            ]
        later = reach is not None and _enclosing(reach) == fn and reach.start_byte > node.start_byte
        if any(r < node.start_byte for r in self.early[key]) and not later:
            return False
        if key not in self.gotos:
            body = fn.child_by_field_name("body") or fn
            self.gotos[key] = [
                g.start_byte
                for g in walk(body)
                if g.type == "goto_statement" and _enclosing(g) == fn
            ]
        gotos = self.gotos[key]
        if any(g < node.start_byte for g in gotos):
            return False  # `if skip { goto route }; r.Use(auth); route: ..`
        loop = node.parent
        while loop is not None and loop != fn and loop.type != "for_statement":
            loop = loop.parent
        if loop is not None and loop.type == "for_statement":  # `if m.Public { continue }`
            skips = [
                s for s in walk(loop)
                if s.type in ("continue_statement", "break_statement", "goto_statement")
                and s.start_byte < node.start_byte and _enclosing(s) == fn
            ]  # fmt: skip
            inside = later and loop.start_byte <= reach.start_byte < loop.end_byte  # type: ignore[union-attr]
            if skips and not inside:
                return False
        return True

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
            } | _receivers(src, fn):
                return False
            fn = _enclosing(fn)
        key = (src.dir, name)
        return key not in self.co.package_values and key not in self.co.package_vars

    def peel(self, src: _Source, handler: Node) -> tuple[Node, list[str]]:
        """The handler inside its wrappers, and the wrappers' names: `auth(http.HandlerFunc(h))`
        is `h` under `auth`; a local bound to a wrapper (`p := auth(api)`) is followed too."""
        node = _unwrap(handler) or handler
        names: list[str] = []
        for _ in range(_MAX_DEPTH):
            if node.type == "identifier":
                fn = _enclosing(node)
                values = self.co.values(src, node, src.text(node), fn) if fn is not None else []
                if len(values) != 1:
                    break  # several values (`if dev { h = plain }`): which wraps it isn't told
                value = _unwrap(values[0].value)
                if value is not None and value.type == "call_expression" and self.wraps(src, value):
                    node = value
                    continue
                break
            if node.type == "type_conversion_expression":  # a generic wrapper `Wrap[int](h)`
                names += self.generic_names(src, node)
                node = _unwrap(node.child_by_field_name("operand")) or node
                continue
            if node.type != "call_expression":
                break
            inner = self.wraps(src, node)
            if inner is None:
                break
            names += self.wrapper_names(src, node, inner)
            node = _unwrap(inner) or inner
        return node, names

    def generic_names(self, src: _Source, node: Node) -> list[str]:
        """A generic wrapper's name, where it always wraps (no bare return of its handler)."""
        name = _name(src, node.child_by_field_name("type"))
        found = self.co.functions.get((src.dir, name))
        if found is not None:
            fsrc, fn = found
            params = _params(fsrc, fn)
            first = params[0][0] if params else ""
            if fsrc.constrained or any(
                fsrc.text(_unwrap(r) or r) == first for r in self.co.returned(fsrc, fn)
            ):
                return []
        return [name] if name and not src.constrained else []

    def wrapper_names(self, src: _Source, call: Node, inner: Node) -> list[str]:
        """What a wrapping call is named for, where it always wraps (D42): its callee, the
        middleware of a chain it ends (`alice.New(requireAuth).Then(mux)`), and the wrappers a
        checkout wrapper always puts on."""
        index = next((i for i, a in enumerate(_args(call)) if a == inner), -1)
        if index < 0 or not self.certain(src, call, index):
            return []
        fn_node = _unwrap(call.child_by_field_name("function"))
        if self.lets_through(src, call) or (
            fn_node is not None and self.lets_through(src, fn_node)
        ):
            return []  # `jwtauth.Verifier(ta)(api)`: refuses nobody
        callee = _name(src, call)
        out = [] if callee in _CONVERSIONS else [callee]
        fn = call.child_by_field_name("function")
        operand = (
            fn.child_by_field_name("operand")
            if fn is not None and fn.type == "selector_expression"
            else None
        )
        while operand is not None and operand.type == "call_expression":
            out += [n for a in _args(operand) for n in self.credited(src, a)]
            inner_fn = operand.child_by_field_name("function")
            operand = (
                inner_fn.child_by_field_name("operand")
                if inner_fn is not None and inner_fn.type == "selector_expression"
                else None
            )
        return [*out, *self.inner_names(src, call, index)]

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
        if expr.type == "type_conversion_expression":
            names = tuple(self.generic_names(src, expr))
            out = [
                (i, (*names, *ns))
                for i, ns in self.trace(src, expr.child_by_field_name("operand"), depth + 1)
            ]
        elif (
            expr.type == "selector_expression"
            and src.text(expr.child_by_field_name("field")) == "ServeHTTP"
        ):
            operand = expr.child_by_field_name("operand")
            out = self.trace(src, operand, depth + 1)  # `public.HandleFunc("/", api.ServeHTTP)`
        elif expr.type in ("identifier", "selector_expression"):
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
                names = tuple(self.wrapper_names(src, expr, inner))
                out = [(i, (*names, *ns)) for i, ns in self.trace(src, inner, depth + 1)]
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
                if name in _SERVES and self.own_function(src, n):
                    pass  # `worker.Serve(addr, r)`: the checkout's own; its body is read instead
                elif name in _SERVES and len(args) == _SERVES[name][0]:
                    out.append(args[_SERVES[name][1]])
                elif (
                    name in _SERVES
                    and (server := _field(src, n)[0]) is not None
                    and (self.handler_unset(src, server, n))
                ):
                    # `srv.ListenAndServe()` with no `Handler`: the default mux, raw
                    out.append(n.child_by_field_name("function").child_by_field_name("field"))
                elif name in _RUNS and (receiver := _field(src, n)[0]) is not None:
                    out.append(receiver)  # `r.Run(":9090")`, `e.Start(..)`, `app.Listen(..)`: raw
            elif n.type == "keyed_element" and len(n.named_children) == 2:
                literal = n.parent.parent if n.parent is not None else None
                if (
                    src.text(_unwrap(n.named_children[0]) or n.named_children[0]) == "Handler"
                    and literal is not None
                    and literal.type == "composite_literal"
                    and self.http_server(src, literal.child_by_field_name("type"))
                ):
                    out.append(n.named_children[1])  # `http.Server{Handler: h}`, not any `Handler:`
            elif n.type == "composite_literal" and self.http_server(
                src, n.child_by_field_name("type")
            ):
                body = n.child_by_field_name("body")
                keys = {
                    src.text(_unwrap(k.named_children[0]) or k.named_children[0])
                    for k in walk(body)
                    if k.type == "keyed_element" and k.named_children
                } if body is not None else set()  # fmt: skip
                holder = n.parent  # `(&http.Server{Addr: a}).ListenAndServe()`: started here
                while holder is not None and holder.type in (
                    "parenthesized_expression",
                    "unary_expression",
                ):
                    holder = holder.parent
                started = (
                    holder is not None
                    and holder.type == "selector_expression"
                    and holder.parent is not None
                    and holder.parent.type == "call_expression"
                    and _field(src, holder.parent)[1] in _SERVES
                )
                if "Handler" not in keys and started:
                    out.append(n.child_by_field_name("type"))  # no Handler: the default mux
            elif n.type == "assignment_statement":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                targets = left.named_children if left is not None else []
                values = right.named_children if right is not None else []
                for i, t in enumerate(targets):
                    if (
                        t.type == "selector_expression"
                        and src.text(t.child_by_field_name("field")) == "Handler"
                        and i < len(values)
                        and self.server_value(src, t.child_by_field_name("operand"))
                    ):
                        out.append(values[i])  # `srv.Handler = h` on an `http.Server`
        return out

    def http_server(self, src: _Source, kind: Node | None) -> bool:
        """`http.Server` (under its import name, or `Server` with net/http dot-imported)."""
        return self.http_server_text(src, src.text(kind))

    def server_value(self, src: _Source, value: Node | None, depth: int = 0) -> bool:
        """A value that is an `http.Server`: a parameter of that type or a local bound to one."""
        value = _unwrap(value)
        if value is None or value.type != "identifier" or depth > _MAX_DEPTH:
            return False
        fn = _enclosing(value)
        while fn is not None:
            for p, kind in _params(src, fn):
                if p == src.text(value):
                    return self.http_server_text(src, kind)
            bound = self.co.binding(src, value, src.text(value), fn)
            if bound is not None:
                return self.server_expr(src, bound.value, depth + 1)
            fn = _enclosing(fn)
        package = self.co.package_values.get((src.dir, src.text(value)))
        return package is not None and self.server_expr(*package, depth + 1)

    def server_expr(self, src: _Source, value: Node, depth: int = 0) -> bool:
        """`http.Server{..}`, `&http.Server{..}`, `new(http.Server)`, `var srv http.Server`, or
        another name for one (`other := srv`)."""
        inner = _unwrap(value) or value
        if inner.type == "identifier":
            return self.server_value(src, inner, depth)
        if inner.type == "composite_literal":
            return self.http_server(src, inner.child_by_field_name("type"))
        if inner.type == "var_spec":
            return self.http_server(src, inner.child_by_field_name("type"))
        if inner.type == "call_expression" and _callee(src, inner) == "new":
            args = inner.child_by_field_name("arguments")
            return args is not None and self.http_server_text(src, src.text(args).strip("()"))
        return False

    def handler_unset(self, src: _Source, server: Node, at: Node) -> bool:
        """A server value whose `Handler` nothing surely sets before it is started: it may serve
        the default mux (`if prod { srv.Handler = auth(mux) }`, D42)."""
        server = _unwrap(server) or server
        if server.type != "identifier" or not self.server_value(src, server):
            return False
        name = src.text(server)
        fn = _enclosing(server)
        bound = self.co.bound_value(src, server)  # a local's, or a package server's
        value = _unwrap(bound) if bound is not None else None
        if value is not None and value.type == "composite_literal":
            body = value.child_by_field_name("body")
            if body is not None and any(
                k.type == "keyed_element" and k.named_children
                and src.text(_unwrap(k.named_children[0]) or k.named_children[0]) == "Handler"
                for k in walk(body)
            ):  # fmt: skip
                return False
        if fn is None:
            return True
        names = {name}
        pointer = bound is not None and re.match(r"\s*(&|new\s*\()", src.text(bound))
        for alias, binds in self.co.bindings(src, fn).items() if pointer else []:
            if any(
                (v := _unwrap(b.value) or b.value).type == "identifier" and src.text(v) == name
                for b in binds
            ):
                names.add(alias)  # `other := srv`: the same server, through its pointer
        sets = []
        for n in walk(fn.child_by_field_name("body") or fn):
            if n.type != "assignment_statement" or _enclosing(n) != fn:
                continue
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            values = right.named_children if right is not None else []
            for i, t in enumerate(left.named_children if left is not None else []):
                if (
                    t.type == "selector_expression"
                    and src.text(t.child_by_field_name("operand")) in names
                    and src.text(t.child_by_field_name("field")) == "Handler"
                    and i < len(values)
                    and not self.maybe_nil(src, values[i])
                ):
                    sets.append(n)
        return not any(a.start_byte < at.start_byte and self.surely(src, a, fn, at) for a in sets)

    def maybe_nil(self, src: _Source, value: Node, depth: int = 0) -> bool:
        """A handler value that may be nil: `nil`, `http.Handler(nil)`, or a variable declared
        with no value (`var h http.Handler`); a nil `Handler` serves the default mux."""
        value = _unwrap(value) or value
        if depth > _MAX_DEPTH or src.text(value) == "nil":
            return True
        if value.type in ("call_expression", "type_conversion_expression"):
            inner = (
                _args(value)
                if value.type == "call_expression"
                else [value.child_by_field_name("operand")]
            )
            return len(inner) == 1 and inner[0] is not None and src.text(inner[0]) == "nil"
        if value.type != "identifier":
            return False
        fn = _enclosing(value)
        binds = self.co.values(src, value, src.text(value), fn) if fn is not None else []
        if not binds:
            return (src.dir, src.text(value)) in self.co.package_vars
        return any(
            b.value.type == "var_spec" or self.maybe_nil(src, b.value, depth + 1) for b in binds
        )

    def http_server_text(self, src: _Source, kind: str) -> bool:
        alias, dot, name = kind.lstrip("*& ").partition(".")
        if not dot:
            return alias == "Server" and "http" in src.dot_kinds
        return name == "Server" and src.kinds.get(alias) == "http"

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
            if _field(src, expr)[1] == "Subrouter":
                return {_id(src, expr)}  # a gorilla sub-router can be served on its own
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
        params = {p for p, _ in _params(fsrc, fn)} | _receivers(fsrc, fn)
        built = any(
            self.identity(fsrc, r) - {_id(src, call)}
            for r in self.co.returned(fsrc, fn)
            if not ((_unwrap(r) or r).type == "identifier" and fsrc.text(_unwrap(r) or r) in params)
        )  # `func passthrough(r chi.Router) chi.Router { return r }` hands one on, builds none
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
            where = self.owner_dir(csrc, operand) if operand is not None else None
            if (not told or told == kind) and (where is None or where == src.dir):
                out.append((csrc, call))
        return out

    def owner_dir(self, src: _Source, value: Node, depth: int = 0) -> str | None:
        """The checkout package a value's type comes from, where the code says it:
        `users.New(db)`, `&billing.Handler{}`, a local bound to one, or the same package."""
        value = _unwrap(value) or value
        if depth > _MAX_DEPTH:
            return None
        if value.type in ("call_expression", "composite_literal"):
            head = value.child_by_field_name(
                "function" if value.type == "call_expression" else "type"
            )
            head = _unwrap(head) or head
            if head is not None and head.type in ("selector_expression", "qualified_type"):
                alias = src.text(head.named_children[0]) if head.named_children else ""
                if alias in src.imports:
                    return self.co.directory(src.imports[alias])
                if head.type == "selector_expression":
                    return self.owner_dir(src, head.child_by_field_name("operand"), depth + 1)
            return (
                src.dir
                if head is not None and head.type in ("identifier", "type_identifier")
                else None
            )
        if value.type == "identifier":
            fn = _enclosing(value)
            bound = self.co.binding(src, value, src.text(value), fn) if fn is not None else None
            if bound is not None:
                return self.owner_dir(src, bound.value, depth + 1)
        return None

    def field_sites(self, src: _Source, expr: Node) -> list[tuple[_Source, Node]]:
        """What a struct field is assigned, for the owner's type where both sides tell it."""
        name = src.text(expr.child_by_field_name("field"))
        operand = expr.child_by_field_name("operand")
        kind = self.co.type_of(src, operand) if operand is not None else ""
        out = []
        sites = self.co.fields.get((src.dir, name), [])
        if not sites and kind:  # `s.E` of a struct another package declares: the one that does
            homes = {d for d, ty in self.co.data_fields if ty == kind}
            if len(homes) == 1:
                sites = self.co.fields.get((next(iter(homes)), name), [])
        for vsrc, value, owner in sites:
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
        if fn is not None and fn.type == "identifier" and not self.co.shadowed(src, fn):
            for kind in src.dot_kinds:  # dot-imported: `Default()`
                if (
                    src.text(fn) in _CONSTRUCTORS[kind]
                    and (src.dir, src.text(fn)) not in self.co.functions
                ):
                    return kind
            return ""
        if fn is None or fn.type != "selector_expression":
            return ""
        operand = fn.child_by_field_name("operand")
        alias = src.text(operand) if operand is not None else ""
        kind = src.kinds.get(alias) or (
            alias
            if alias in _CONSTRUCTORS
            and alias not in src.imports
            and operand is not None
            and not self.co.shadowed(src, operand)
            and (src.dir, alias) not in self.co.package_values
            and (src.dir, alias) not in self.co.package_vars
            and (src.dir, alias) not in self.co.functions
            else ""
        )
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
            mws = args[1:] if prefix is not None and name not in _ROUTES_WITH_FN else []
            g, u = self.mw(src, [m for m in mws if m.type != "func_literal"])
            dynamic = prefix is None and args[0].type != "func_literal"
            parents = self.contexts(src, receiver, call, depth + 1)
            if any(c.kind == "fiber" for c in parents) and _enclosing(at) == _enclosing(call):
                parents = self.contexts(src, receiver, at, depth + 1)  # fiber: at registration
            return [
                replace(c, dynamic=c.dynamic or dynamic).under(prefix or "", g, u) for c in parents
            ]
        if receiver is not None and name == "Unbind":  # drops middleware by id: none is sure
            return [
                replace(c, guards=(), unguards=(*c.unguards, "Unbind"))
                for c in self.contexts(src, receiver, call, depth + 1)
            ]
        if receiver is not None and name in ("With", *_USES):
            g, u = self.mw(src, args)
            return [c.under("", g, u) for c in self.contexts(src, receiver, call, depth + 1)]
        if receiver is not None and name == "Subrouter":
            prefix_node = self.chained(src, receiver, "PathPrefix")
            prefix = self.co.string(src, prefix_node) if prefix_node is not None else ""
            methods = tuple(
                m
                for n in walk(receiver)
                if n.type == "call_expression" and _field(src, n)[1] == "Methods"
                for a in _args(n)
                if (m := _method(src, a, self.co))
            )
            root = receiver
            while root.type == "call_expression" and _field(src, root)[0] is not None:
                root = _field(src, root)[0]  # type: ignore[assignment]
            own = self.places(_id(src, call), "mux", depth)  # `ListenAndServe(":9090", api)`
            return [
                replace(c, dynamic=c.dynamic or prefix is None, methods=methods or c.methods).under(
                    prefix or ""
                )
                for c in self.contexts(src, root, call, depth + 1)
            ] + [replace(c, methods=methods or c.methods).under(prefix or "") for c in own]
        if helper := self.helper(src, call):
            bases = self.built(helper[0], helper[1])
            kind = bases[0].kind if bases else ""
            sites = self.places(_id(src, call), kind, depth)
            for r in self.co.returned(*helper):  # mounted inside the helper (`parent.Handle(..)`)
                for i in self.identity(helper[0], r) - {_id(src, call)}:
                    sites += self.places(i, kind, depth)
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
                    out += self.used_middleware(fsrc, fn, fsrc.text(r), bound, r, base, cutoff=r)
        return out

    def places(self, ident: int, kind: str, depth: int) -> list[_Ctx]:
        """Where a router is mounted (`r.Mount("/api", api)`, `Handle("/api/", StripPrefix(..))`)
        and served (`ListenAndServe(addr, auth(mux))`): each its own place, so a router also
        served raw stays unguarded there."""
        out: list[_Ctx] = []
        for msrc, reg, names in self.mounts.get(ident, []):
            literal = self.co.string(msrc, reg.path) or ""
            method = m[1] if (m := _METHOD_PATTERN.match(literal)) else ""
            for c in self.contexts(msrc, reg.receiver, reg.call, depth + 1):
                prefix = self.mount_prefix(msrc, reg, kind)
                rg, ru = self.mw(msrc, self.route_middleware(msrc, reg, c.kind))
                g, u = _named(names)
                g, u = ([] if msrc.constrained else [*g, *rg]), [*u, *ru]
                placed = replace(c, kind=kind, known=True, dynamic=c.dynamic or prefix is None)
                if method or reg.methods != ["ANY"]:  # `Handle("GET /api/", ..)`: GET only
                    placed = replace(placed, methods=(method,) if method else tuple(reg.methods))
                out.append(placed.under(prefix or "", g, u))
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

    def mount_prefix(self, src: _Source, reg: _Reg, kind: str) -> str | None:
        """The path a mounted router's own routes sit under: `http.StripPrefix` strips it, and
        chi and fiber `Mount` do for their own routers; net/http, gorilla and gin hand on the
        full path, as chi does to any other handler."""
        handler = reg.rest[0] if reg.rest else reg.call
        if (stripped := self.stripped(src, handler)) is not None:
            return stripped
        if not reg.mount or kind not in ("chi", "fiber"):
            return ""
        path = self.co.string(src, reg.path)
        return path.rstrip("/").removesuffix("/*") if path is not None else None  # computed

    def stripped(self, src: _Source, expr: Node, depth: int = 0) -> str | None:
        """The prefix an `http.StripPrefix` on the way strips: inline, in a local
        (`h := http.StripPrefix(..)`) or in what a checkout function returns."""
        node = _unwrap(expr) or expr
        if depth > _MAX_DEPTH:
            return None
        for n in walk(node):
            if n.type == "call_expression" and _callee(src, n).endswith("StripPrefix") and _args(n):
                return self.co.string(src, _args(n)[0])  # None: a computed prefix
        if node.type == "identifier":
            fn = _enclosing(node)
            bound = self.co.binding(src, node, src.text(node), fn) if fn is not None else None
            return self.stripped(src, bound.value, depth + 1) if bound is not None else None
        if node.type == "call_expression":
            found = self.co.function(src, node.child_by_field_name("function"))
            if found is not None and found[1].type != "func_literal":
                for r in self.co.returned(*found):
                    if (s := self.stripped(found[0], r, depth + 1)) is not None:
                        return s
        return None

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
                value = _unwrap(bound.value)
                if (
                    any(c.kind == "fiber" for c in ctxs)
                    and value is not None
                    and value.type == "call_expression"
                    and _field(src, value)[1] in ("Group", "Route")
                ):
                    ctxs = self.contexts(src, value, at, depth + 1)  # fiber: at registration
                out = self.used_middleware(src, fn, ident, bound, at, ctxs)
                for b in others:  # `if disabled { r = chi.NewRouter() }`: that one's own `Use`
                    mine = self.contexts(src, b.value, b.stmt, depth + 1)
                    out += self.used_middleware(src, fn, ident, b, at, mine)
                return out
            names = [p for p, _ in _params(src, fn)]
            if ident in names:
                ctxs = self.param_contexts(src, fn, names.index(ident), depth)
                return self.used_middleware(src, fn, ident, None, at, ctxs)
            fn = _enclosing(fn)
        value = self.co.package_values.get((src.dir, ident))
        assigned = self.package_assignments(src, ident)
        if value is None and len(assigned) == 1 and (src.dir, ident) in self.co.package_vars:
            value = assigned[0]  # `var router chi.Router`, then `router = chi.NewRouter()` once
            assigned = []
        if value is not None:
            vsrc, v = value
            ctxs = self.contexts(vsrc, v, v, depth + 1)
            if assigned:  # replaced somewhere: which router a `Use` was on isn't told (D42)
                return [
                    *(replace(c, guards=(), scoped=()) for c in ctxs),
                    *(c for a in assigned for c in self.contexts(a[0], a[1], a[1], depth + 1)),
                ]
            return self.package_middleware(src, ident, at, ctxs, v)
        return [_Ctx(kind=self.kind_hint(src))]

    def package_assignments(self, src: _Source, ident: str) -> list[tuple[_Source, Node]]:
        """The values a package-level name is assigned in functions (not a shadowing local)."""
        key = (src.dir, ident)
        if key not in self.package_sets:
            out = []
            for s in self.co.sources:
                if s.dir != src.dir or ident.encode() not in s.data:
                    continue
                for n in walk(s.root):
                    if n.type != "assignment_statement":
                        continue
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    values = right.named_children if right is not None else []
                    for i, target in enumerate(left.named_children if left is not None else []):
                        if (
                            target.type == "identifier"
                            and s.text(target) == ident
                            and i < len(values)
                            and not self.co.shadowed(s, target)
                        ):
                            out.append((s, values[i]))
            self.package_sets[key] = out
        return self.package_sets[key]

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
        if self.as_value(src, fn):  # `for _, reg := range []func(chi.Router){userRoutes}`
            out.append(_Ctx(kind=self.param_kind(src, fn, index), dynamic=True))
        for csrc, holder in self.route_fns.get(_id(src, fn), []) if index == 0 else []:
            receiver, _ = _field(csrc, holder)
            args = _args(holder)
            prefix = self.co.string(csrc, args[0]) if len(args) > 1 else ""
            out += [
                replace(c, dynamic=c.dynamic or prefix is None).under(prefix or "")
                for c in self.contexts(csrc, receiver, holder, depth + 1)
            ]
        return out or [_Ctx(kind=self.param_kind(src, fn, index), known=True)]

    def as_value(self, src: _Source, fn: Node) -> bool:
        """A named function referred to other than by a call or a `Route`/`Group` argument:
        whoever calls it through that value isn't followed."""
        name = src.text(fn.child_by_field_name("name")) if fn.type == "function_declaration" else ""
        if not name:
            return False
        if src.dir not in self.valued:
            self.valued[src.dir] = self.values_in(src.dir)
        return name in self.valued[src.dir]

    def values_in(self, where: str) -> set[str]:
        """The names a package's files refer to other than by a call, a `Route`/`Group`
        argument or a declaration: one walk per package, whatever the number of helpers."""
        out: set[str] = set()
        for s in self.co.sources:
            if s.dir != where:
                continue
            for n in walk(s.root):
                if n.type != "identifier":
                    continue
                parent = n.parent
                if (
                    parent is not None
                    and parent.type == "call_expression"
                    and parent.child_by_field_name("function") == n
                ):
                    continue
                holder = (
                    parent.parent if parent is not None and parent.type == "argument_list" else None
                )
                if holder is not None and _field(s, holder)[1] in ("Route", "Group"):
                    continue
                if parent is not None and parent.type == "function_declaration":
                    continue
                out.add(s.text(n))
        return out

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
        root: bool, cutoff: Node | None = None,
    ) -> list[_Ctx]:  # fmt: skip
        """The contexts with these `Use` calls' middleware (each with the position it counts
        at); where order counts, only those before `ordered_at` (None: their order can't be
        told, so none count)."""
        out = []
        for c in ctxs:
            ordered = _ordered(c, root)
            guards: list[str] = []
            unguards: list[str] = []
            scoped = list(c.scoped)
            for usrc, n, at in uses:
                if ordered and (ordered_at is None or at >= ordered_at.start_byte):
                    continue
                if cutoff is not None and at >= cutoff.start_byte:
                    continue  # after the `return` this way out takes
                fn = _enclosing(n)
                reach = (
                    ordered_at if ordered_at is not None and _enclosing(ordered_at) == fn else None
                )
                if usrc.constrained or fn is None or not self.surely(usrc, n, fn, reach):
                    continue  # in a branch, after a `return`, in a build-tagged file (D42)
                args = _args(n)
                path = self.co.string(usrc, args[0]) if args else None
                if path is not None:  # fiber `app.Use("/api", mw)`
                    g, _ = self.mw(usrc, args[1:])
                    scoped.append((_join(c.prefix, path), tuple(g)))
                    continue
                if args and (
                    not self.handler_like(usrc, args[0])
                    or (len(args) > 1 and self.stringish(usrc, args[0]))
                ):
                    continue  # `app.Use(adminPath, mw)`: a path not told, so no scope (D42)
                g, u = self.mw(usrc, args)
                guards, unguards = guards + g, unguards + u
            out.append(replace(c.under("", guards, unguards), scoped=tuple(scoped)))
        return out

    def used_middleware(
        self, src: _Source, fn: Node, ident: str, bound: _Binding | None, at: Node,
        ctxs: list[_Ctx], cutoff: Node | None = None,
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
        uses += self.helper_middleware(src, fn, ident, same)
        value = _unwrap(bound.value) if bound is not None else None
        root = (
            value is not None
            and value.type == "call_expression"
            and bool(self.constructor(src, value))
        )
        out = self.apply(uses, ctxs, at, root, cutoff)
        for n in self.fn_unbinds(src, fn):  # `pub.Unbind(apis.DefaultRequireAuthMiddlewareId)`
            receiver = _field(src, n)[0]
            seen = self.co.binding(src, n, ident, fn)
            if (
                receiver is not None
                and src.text(_unwrap(receiver)) == ident
                and ((seen.stmt if seen else None) == same)
            ):
                return [replace(c, guards=(), unguards=(*c.unguards, "Unbind")) for c in out]
        return out

    def helper_middleware(
        self, src: _Source, fn: Node, ident: str, same: Node | None, depth: int = 0
    ) -> list[tuple[_Source, Node, int]]:
        """`setupMiddleware(r)`: the helper's own `Use` on its parameter, and its helpers' in
        turn, counted where it is called; only a call every run makes, to a helper that never
        rebinds the parameter."""
        key = (_id(src, fn), ident, _id(src, same) if same is not None else 0)
        if key in self.helper_uses:
            return self.helper_uses[key]
        self.helper_uses[key] = []  # a helper that calls itself adds nothing more
        if depth > _MAX_DEPTH:
            return []
        out = []
        for call in self.fn_calls(src, fn):
            if not self.surely(src, call, fn, None):
                continue
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
                if i >= len(params) or self.co.bindings(hsrc, helper).get(params[i][0]):
                    continue  # `r = r.Group("/admin")` in the helper: its `Use` isn't on ours
                for n in self.fn_uses(hsrc, helper):
                    receiver, _ = _field(hsrc, n)
                    if receiver is not None and hsrc.text(_unwrap(receiver)) == params[i][0]:
                        out.append((hsrc, n, call.start_byte))
                for usrc, n, _ in self.helper_middleware(
                    hsrc, helper, params[i][0], None, depth + 1
                ):
                    out.append((usrc, n, call.start_byte))
        earliest: dict[int, tuple[_Source, Node, int]] = {}
        for u in out:  # one per middleware, at its earliest certain call
            k = _id(u[0], u[1])
            if k not in earliest or u[2] < earliest[k][2]:
                earliest[k] = u
        self.helper_uses[key] = list(earliest.values())
        return self.helper_uses[key]

    def fn_unbinds(self, src: _Source, fn: Node) -> list[Node]:
        """The `Unbind` calls a function makes itself."""
        key = _id(src, fn) ^ 0x5A5A
        if key not in self.uses:
            body = fn.child_by_field_name("body") or fn
            self.uses[key] = [
                n
                for n in walk(body)
                if n.type == "call_expression"
                and _field(src, n)[1] == "Unbind"
                and _enclosing(n) == fn
            ]
        return self.uses[key]

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
            and (fn := _enclosing(n)) is not None
            # where it surely runs before the route: `init`, or the function that registers (D42)
            and (
                fn == here
                or (
                    fn.type == "function_declaration"
                    and s.text(fn.child_by_field_name("name")) == "init"
                )
            )
        ]
        value = _unwrap(value) or value
        root = value.type == "call_expression" and bool(self.constructor(src, value))
        ordered_ctxs = [c for c in ctxs if _ordered(c, root)]
        local = [u for u in uses if u[0].file.rel == src.file.rel and _enclosing(u[1]) == here]
        # an `init` runs before the route where nothing run at init registers it, or where it
        # is an earlier `init`: by file name, then by place in the file
        after = self.co.runs_after_init(src, here)
        early = [
            (s, n, -1)
            for s, n, _ in uses
            if _is_init(s, init := _enclosing(n))
            and init != here
            and (
                after
                or (
                    _is_init(src, here)
                    and (s.file.rel, init.start_byte) < (src.file.rel, here.start_byte)
                )
            )
        ]
        return self.apply([*local, *early] if ordered_ctxs else uses, ctxs, at, root)

    def shadowed(self, src: _Source, at: Node, ident: str) -> bool:
        fn = _enclosing(at)
        while fn is not None:
            if self.co.declares(src, at, ident, fn) or ident in {
                p for p, _ in _params(src, fn)
            } | _receivers(src, fn):
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
        here = _enclosing(at)
        if here is None or len(self.field_sites(src, expr)) != 1:
            return ctxs  # assigned more than once (`s.router = chi.NewRouter()` again): unsure
        operand = expr.child_by_field_name("operand")
        holder = self.co.binding(src, at, src.text(operand), here) if operand is not None else None
        # only in the function that registers, on the same variable (`admin.router.Use` is
        # not `public.router`'s): one instance's field may not be another's
        uses = []
        for n in self.fn_uses(src, here):
            receiver = _unwrap(_field(src, n)[0])
            if (
                receiver is not None
                and receiver.type == "selector_expression"
                and src.text(receiver.child_by_field_name("field")) == name
                and operand is not None
                and src.text(receiver.child_by_field_name("operand")) == src.text(operand)
                and self.co.binding(src, n, src.text(operand), here) == holder
                and self.identity(src, receiver) & mine
            ):
                uses.append((src, n, n.start_byte))
        unordered = [c for c in ctxs if not _ordered(c, False)]
        ordered = [c for c in ctxs if _ordered(c, False)]
        local = [u for u in uses if _enclosing(u[1]) == here]
        return [*self.apply(uses, unordered, None, False), *self.apply(local, ordered, at, False)]

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
            if method_in and not any(c.kind in ("http", "chi", "") for c in ctxs):
                method_in, pattern = "", literal  # gorilla `"GET /reports"`: no such path
            if reg.router_only and not any(
                c.known and c.kind in ("gin", "echo", "fiber") for c in ctxs
            ):
                continue
            if not any(c.known for c in ctxs) and self.own_method(src, reg.call):
                continue  # `db.Get("/internal", h)` on the checkout's own store: no router's
            served_mux = any(c.kind == "http" for c in ctxs)
            if served_mux and pattern is not None and re.match(r"[\w.-]+(:\d+)?/\S*$", pattern):
                pass  # a ServeMux host pattern: `localhost/admin`
            elif not _route_like(pattern, any(c.known for c in ctxs)):
                continue  # `cache.Get("key", v)`: not a route
            if reg.layout == "verbs" and any(
                _literal(a) or self.co.string(src, a) is not None for a in reg.rest
            ):
                continue  # `client.Post("/v1/notes", "application/json", body)`: not a route
            if src.kinds.get(src.text(reg.receiver)) == "http" and reg.layout == "verbs":
                continue  # `http.Post(url, contentType, body)`: net/http's client
            # no router told, in a file with no router package but net/http's: maybe a client
            unknown = not any(c.known or c.kind for c in ctxs) and not set(src.kinds.values()) - {
                "http"
            }
            unbound = self.unbound(src, reg.call)
            for c in ctxs:
                handler = self.handler(src, reg, c.kind)
                if not self.handler_like(src, handler):
                    continue  # `conn.Delete("/locks/leader", -1)`: no handler, no route
                if unknown and self.co.function(src, self.peel(src, handler)[0]) is None:
                    continue  # no router told, in a file with no router package: `conn.Delete(..)`
                inner, wrappers = self.peel(src, handler)
                rg, ru = self.mw(
                    src, [*self.route_middleware(src, reg, c.kind), *self.bound(src, reg.call)]
                )
                wg, wu = _named(wrappers)
                guards, unguards = _unique([*rg, *wg]), sorted({*ru, *wu})
                guards = [] if src.constrained or unbound else guards  # D42: may not run
                full = _join(c.prefix, pattern if pattern is not None else src.text(raw)[:160])
                scoped = [
                    g
                    for p, gs in c.scoped
                    if full == p or full.startswith(p.rstrip("/") + "/")
                    for g in gs
                ]
                found = self.co.function(src, inner)
                if found is None and inner.type == "call_expression":
                    found = self.co.function(src, inner.child_by_field_name("function"))
                methods = list(c.methods) if reg.methods == ["ANY"] and c.methods else reg.methods
                if c.methods and reg.methods != ["ANY"]:
                    methods = [m for m in reg.methods if m in c.methods]
                wanted = [method_in] if method_in else methods
                if c.methods and method_in and method_in not in c.methods:
                    wanted = []  # behind a `GET` mount, a `DELETE` route is unreachable
                for method in wanted:
                    row = _row(
                        RouteFamily.GO_HTTP,
                        method,
                        full or "/",
                        src.text(handler)[:200],
                        src.file.rel,
                        src.line(reg.call),
                        guards,
                        [] if unbound else _unique([*c.guards, *scoped]),
                        sorted({*unguards, *c.unguards, *(["Unbind"] if unbound else [])}),
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


def _forwards_once(src: _Source, fn: Node, name: str, method: str = "ServeHTTP") -> bool:
    """A middleware body hands the request on at one place at most, and only itself: a second
    `next(..)` / `next.ServeHTTP(..)` / `c.Next()` is a path around the check, and so is a
    forward through an alias, a nested closure or (gin) a `return` that doesn't abort (D42)."""
    body = fn.child_by_field_name("body")
    if body is None or not name:
        return True
    forwards, aliased = [], False
    for n in walk(body):
        if n.type == "identifier" and src.text(n) == name:
            parent = n.parent
            if method == "ServeHTTP" and not (
                parent is not None
                and (
                    (
                        parent.type == "call_expression"
                        and parent.child_by_field_name("function") == n
                    )
                    or (
                        parent.type == "selector_expression"
                        and src.text(parent.child_by_field_name("field")) == method
                    )
                )
            ):
                aliased = True  # `h := next`, `chain(next)`: handed on where it isn't read
            elif parent is not None and parent.type == "expression_list":
                aliased = True  # `ctx := c`
        if n.type == "call_expression" and _forward(src, n, name, method):
            forwards.append(n)
    if aliased or any(_enclosing(f) != fn or _deferred(f, fn) for f in forwards):
        return False
    proceeds = len(forwards)
    if _GIN_CONTEXT.search(next((k for p, k in _params(src, fn) if p == name), "")):
        stops = (method, "Abort", "AbortWithStatus", "AbortWithStatusJSON", "AbortWithError")
        for r in walk(body):  # gin goes on unless aborted: a bare `return` lets it through
            if r.type == "return_statement" and _enclosing(r) == fn:
                before = []
                sibling = r.prev_named_sibling
                while sibling is not None:
                    before.append(sibling)
                    sibling = sibling.prev_named_sibling
                proceeds += not any(_stops(src, b, name, stops) for b in before)
        block = body.named_children[0] if body.named_child_count == 1 else body
        listed = block if block.type == "statement_list" else body
        statements = [c for c in listed.named_children if c.type != "comment"]
        last = statements[-1] if statements else None
        if last is None or (last.type != "return_statement" and not _stops(src, last, name, stops)):
            proceeds += 1  # the end of the body: on to the handler
    return proceeds <= 1


def _deferred(call: Node, fn: Node) -> bool:
    """`defer next.ServeHTTP(w, r)` / `go c.Next()`: runs on the refusing path too."""
    node = call.parent
    while node is not None and node != fn:
        if node.type in ("defer_statement", "go_statement"):
            return True
        node = node.parent
    return False


def _forward(src: _Source, call: Node, name: str, method: str) -> bool:
    callee = _unwrap(call.child_by_field_name("function"))
    if callee is None:
        return False
    if callee.type == "identifier":
        return method == "ServeHTTP" and src.text(callee) == name
    operand = (
        callee.child_by_field_name("operand") if callee.type == "selector_expression" else None
    )
    return (
        operand is not None
        and src.text(operand) == name
        and src.text(callee.child_by_field_name("field")) == method
    )


def _stops(src: _Source, statement: Node, name: str, methods: tuple[str, ...]) -> bool:
    """`c.Abort()` / `c.Next()` as a statement of its own."""
    call = statement.named_children[0] if statement.type == "expression_statement" else None
    if call is None or call.type != "call_expression":
        return False
    return any(_forward(src, call, name, m) for m in methods)


def _is_init(src: _Source, fn: Node | None) -> bool:
    return (
        fn is not None
        and fn.type == "function_declaration"
        and src.text(fn.child_by_field_name("name")) == "init"
    )


def _ordered(c: _Ctx, root: bool) -> bool:
    """Whether a `Use` covers only the routes after it: gin, fiber, an echo group, and any
    router whose framework isn't told (D42)."""
    return (c.kind in _ORDERED or not c.kind) and not (c.kind == "echo" and root)


def _route_like(pattern: str | None, known: bool) -> bool:
    """A path a router takes: from `/` or a host, or for a known router `""`, `*` or `:id` too,
    or a computed one."""
    if pattern is None:
        return known
    if pattern.startswith("/") or _HOST_PATTERN.match(pattern):
        return True
    # a known router also takes `""`, `*`, `:id` and gin's relative `users/:id`
    return known and (pattern == "" or bool(re.match(r"[\w*:{]\S*$", pattern)))  # no spaces


@dataclass
class GoRoutes:
    rows: list[_Row]
    evidence: str | None  # a Go file that registers routes
    parsed: bool  # whether the Go parser was available


_REGISTER_CALL = (
    r"\.(HandleFunc|Handle|HandlerFunc|Handler|Mount|Get|Post|Put|Delete|Patch|Head|Options|"
    r"Connect|Trace|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE|Any|All|Method|"
    r"MethodFunc|Match|Add)[ \t]*(?:/\*.*?\*/[ \t]*)*\("
)
_REGISTERS = re.compile(_REGISTER_CALL, re.S)
# a registration with a path as its first argument: `router.GET("/x", h)`, `"GET /x"`
_PATH_REGISTERS = re.compile(_REGISTER_CALL + r'\s*"(?:[A-Z]+ )?/', re.S)


_ROUTER_IMPORT = re.compile(
    r'"(net/http|github\.com/(gin-gonic/gin|labstack/echo|go-chi/chi|gorilla/mux|gofiber/fiber|'
    r'pocketbase/pocketbase)[^"]*)"'
)


def go_rows(files: list[TreeFile]) -> GoRoutes:
    """The HTTP routes of a checkout's Go sources."""
    go = [
        f
        for f in files
        if f.path.suffix == ".go"
        and not f.name.endswith("_test.go")
        and not f.name.startswith(("_", "."))
        and not any(p.startswith(("_", ".")) or p == "testdata" for p in f.rel.split("/")[:-1])
    ]  # `go build` skips `_examples/`, `.hidden/` and `testdata/`
    # evidence of routes: a registration-shaped call in a file that imports an HTTP router (a
    # `db.Get(..)` alone is none, so no gap is claimed for it when the grammar is missing)
    shaped = [f for f in go if _REGISTERS.search(f.text)]
    if not shaped:
        return GoRoutes([], None, True)
    available = parser()
    if available is None:
        routed = {f.path.parent for f in go if _ROUTER_IMPORT.search(f.text)}
        gap = next(
            (f.rel for f in shaped if f.path.parent in routed or _PATH_REGISTERS.search(f.text)),
            None,
        )
        return GoRoutes([], gap, gap is None)  # no gap for a lone `db.Get(&out, q)`
    evidence = shaped[0].rel
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
