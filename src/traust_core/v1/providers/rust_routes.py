"""axum and actix-web routes in Rust and the guards on each, parsed with tree-sitter from the
`rust` extra. An axum `layer`/`route_layer` wraps the routes added before it; an actix `wrap`
wraps its whole app or scope. Auth-shaped handler extractors (`AuthUser`, `BearerAuth`) guard."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.route_guards import (
    GUARD_RX,
    NON_ENFORCING_RX,
    UNGUARD_RX,
    _mark,
    _Row,
    _row,
    _unguards_in,
    _unique,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import rust_parser as parser
from traust_core.v1.providers.tree import TreeFile

AXUM_USE = re.compile(r"\baxum::")
ACTIX_USE = re.compile(r"\bactix_web::")
VERBS = ("get", "post", "put", "delete", "patch", "head", "options", "trace")
# Rust extractor and layer names that guard on top of the shared guard words.
_RUST_GUARD_EXTRA = re.compile(r"(?i)(claims|bearer|principal|identity)")
# Extractors that carry the request's payload: the types inside them are data, not callers.
_PAYLOADS = {"Json", "Form", "Query", "Path", "Multipart", "Bytes", "RawQuery", "State", "Data"}
_ROUTER_NEW = re.compile(r"(?:^|::)Router(?:::<.*>)?::new$")
_GRANTS = ("protect", "has_permissions", "has_roles", "has_any_permission", "has_any_role")
ACTIX_UNREGISTERED = "actix:registration-not-found"
_MAX_DEPTH = 8


def _unwrap(node: Node | None) -> Node | None:
    """The expression inside `x?`, `x.await`, `(x)` and `&x`."""
    while node is not None and node.type in (
        "try_expression",
        "await_expression",
        "parenthesized_expression",
        "reference_expression",
    ):
        node = next((c for c in node.named_children if c.type not in ("mutable_specifier",)), None)
    return node


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "line_comment"] if args else []


def _last(path: str) -> str:
    return path.rsplit("::", 1)[-1].split("<", 1)[0].strip()


def _is_guard(name: str) -> bool:
    if UNGUARD_RX.search(name):
        return False
    rest = NON_ENFORCING_RX.sub("", name)
    return bool(GUARD_RX.search(rest) or _RUST_GUARD_EXTRA.search(rest))


class _Source(Parsed):
    def string(self, node: Node | None) -> str | None:
        node = _unwrap(node)
        if node is None or node.type not in ("string_literal", "raw_string_literal"):
            return None
        return "".join(self.text(c) for c in node.named_children if c.type == "string_content")


def _chain(src: _Source, node: Node | None) -> tuple[Node | None, list[tuple[str, list[Node]]]]:
    """A method chain from its root: `Router::new().route(a).layer(b)` is (`Router::new()`,
    [(route, [a]), (layer, [b])])."""
    steps: list[tuple[str, list[Node]]] = []
    node = _unwrap(node)
    while node is not None and node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "field_expression":
            break
        steps.append((src.text(fn.child_by_field_name("field")), _args(node)))
        node = _unwrap(fn.child_by_field_name("value"))
    return node, steps[::-1]


def _callee(src: _Source, node: Node | None) -> str:
    """`Router::new` for `Router::new()`, `get` for `get(h)`, else ""."""
    node = _unwrap(node)
    if node is None or node.type != "call_expression":
        return ""
    return src.text(node.child_by_field_name("function")).replace(" ", "")


def _outermost(node: Node) -> Node:
    """The whole chain a call is the root of: climbs `.method(...)` links."""
    while (
        node.parent is not None
        and node.parent.type == "field_expression"
        and node.parent.parent is not None
        and node.parent.parent.type == "call_expression"
    ):
        node = node.parent.parent
    return node


def _names(src: _Source, node: Node) -> tuple[list[str], list[str]]:
    """Guard and unguard names a layer or middleware expression is built from."""
    idents = " ".join(
        src.text(n)
        for n in walk(node)
        if n.type in ("identifier", "scoped_identifier", "type_identifier")
        and (n.parent is None or n.parent.type != "scoped_identifier")
    )
    guards = [t for t in re.findall(r"[A-Za-z_][\w:]*", idents) if _is_guard(t)]
    return _unique(guards), _unguards_in(idents)


@dataclass
class _Route:
    method: str
    pattern: str
    handler: str
    src: _Source
    node: Node
    guards: list[str] = field(default_factory=list)
    scope_guards: list[str] = field(default_factory=list)
    unguards: list[str] = field(default_factory=list)
    dynamic: bool = False

    def under(self, prefix: str, guards: list[str], unguards: list[str]) -> _Route:
        return _Route(
            self.method,
            _join(prefix, self.pattern),
            self.handler,
            self.src,
            self.node,
            self.guards,
            _unique([*self.scope_guards, *guards]),
            sorted({*self.unguards, *unguards}),
            self.dynamic,
        )


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    return prefix.rstrip("/") + ("/" + path.lstrip("/") if path.strip("/") else "")


@dataclass
class _Crate:
    sources: list[_Source]
    functions: dict[str, list[tuple[_Source, Node]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for src in self.sources:
            for n in walk(src.root):
                if n.type == "function_item" and (name := n.child_by_field_name("name")):
                    self.functions.setdefault(src.text(name), []).append((src, n))

    def function(self, name: str) -> tuple[_Source, Node] | None:
        found = self.functions.get(_last(name), [])
        return found[0] if found else None

    def binding(self, src: _Source, at: Node, name: str) -> Node | None:
        """The value `let name = ...` binds in the function enclosing `at`."""
        fn = at
        while fn is not None and fn.type not in ("function_item", "closure_expression"):
            fn = fn.parent
        for n in walk(fn) if fn is not None else []:
            if n.type != "let_declaration":
                continue
            if src.text(n.child_by_field_name("pattern")).removeprefix("mut ").strip() == name:
                return n.child_by_field_name("value")
        return None

    def returned(self, src: _Source, fn: Node) -> Node | None:
        body = fn.child_by_field_name("body")
        tail = body.named_children[-1] if body is not None and body.named_children else None
        if tail is not None and tail.type == "expression_statement":
            tail = tail.named_children[0] if tail.named_children else None
        if tail is not None and tail.type == "return_expression":
            tail = tail.named_children[0] if tail.named_children else None
        return tail

    def handler_guards(self, name: str) -> list[str]:
        """Auth-shaped extractors in a handler's parameters, and its bare guard calls."""
        found = self.function(name)
        if found is None:
            return []
        src, fn = found
        guards = []
        params = fn.child_by_field_name("parameters")
        for p in params.named_children if params is not None else []:
            kind = p.child_by_field_name("type")
            if kind is None or _last(src.text(kind)) in _PAYLOADS:
                continue
            for t in walk(kind):
                if t.type == "type_identifier" and _is_guard(src.text(t)):
                    guards.append(f"extractor:{src.text(t)}")
        body = fn.child_by_field_name("body")
        calls = []
        for stmt in body.named_children if body is not None else []:
            expr = _unwrap(stmt.named_children[0]) if stmt.named_children else None
            if stmt.type == "expression_statement" and expr and expr.type == "call_expression":
                fn_ = expr.child_by_field_name("function")
                chained = fn_.type == "field_expression"
                calls.append(src.text(fn_.child_by_field_name("field") if chained else fn_))
        guards += [f"call:{n}" for n in calls if _is_guard(n)]
        return _unique(guards)


class _Axum:
    def __init__(self, crate: _Crate) -> None:
        self.crate = crate
        self.nested: set[int] = set()

    def rows(self) -> list[_Row]:
        roots = []
        for src in self.crate.sources:
            if not AXUM_USE.search(src.file.text) and "Router" not in src.file.text:
                continue
            for n in walk(src.root):
                if n.type == "call_expression" and _ROUTER_NEW.search(_callee(src, n)):
                    roots.append((src, _outermost(n)))
        resolved = [(src, node, self.router(src, node, 0)) for src, node in roots]
        rows = []
        for src, node, routes in resolved:
            if id_(src, node) in self.nested:
                continue
            for r in routes:
                rows.append(_finish(RouteFamily.AXUM, r, self.crate))
        return rows

    def router(self, src: _Source, expr: Node | None, depth: int) -> list[_Route]:
        if depth > _MAX_DEPTH:
            return []
        root, steps = _chain(src, expr)
        routes: list[_Route] = []
        callee = _callee(src, root)
        if _ROUTER_NEW.search(callee):
            pass
        elif root is not None and root.type == "call_expression" and callee:
            found = self.crate.function(callee)
            if found is None:
                return []
            fsrc, fn = found
            routes = self._nested(fsrc, self.crate.returned(fsrc, fn), depth)
        elif root is not None and root.type == "identifier":
            routes = self._nested(src, self.crate.binding(src, root, src.text(root)), depth)
        else:
            return []
        for name, args in steps:
            if name == "route" and len(args) == 2:
                routes += self._methods(src, args[1], *_path(src, args[0]))
            elif name in ("route_service", "nest_service") and len(args) == 2:
                path, dynamic = _path(src, args[0])
                handler = src.text(args[1])[:200]
                routes.append(_Route("ALL", path, handler, src, args[1], dynamic=dynamic))
            elif name == "nest" and len(args) == 2:
                prefix, dynamic = _path(src, args[0])
                for r in self._nested(src, args[1], depth):
                    nested = r.under(prefix, [], [])
                    nested.dynamic = nested.dynamic or dynamic
                    routes.append(nested)
            elif name == "merge" and args:
                routes += self._nested(src, args[0], depth)
            elif name in ("layer", "route_layer") and args:
                g, u = _names(src, args[0])
                routes = [r.under("", g, u) for r in routes]
        return routes

    def _nested(self, src: _Source, expr: Node | None, depth: int) -> list[_Route]:
        expr = _unwrap(expr)
        if expr is None:
            return []
        root, _ = _chain(src, expr)
        if (
            root is not None
            and root.type == "call_expression"
            and _ROUTER_NEW.search(_callee(src, root))
        ):
            self.nested.add(id_(src, _outermost(root)))
        return self.router(src, expr, depth + 1)

    def _methods(self, src: _Source, expr: Node, path: str, dynamic: bool) -> list[_Route]:
        """`get(h).post(h2).layer(l)`: one route per verb, the method router's layers guarding."""
        root, steps = _chain(src, expr)
        calls = [(_last(_callee(src, root)), _args(root) if root is not None else [])]
        calls += [(n, a) for n, a in steps]
        routes: list[_Route] = []
        guards: list[str] = []
        unguards: list[str] = []
        for name, args in calls:
            if name in (*VERBS, "any") and args:
                verb = "ALL" if name == "any" else name.upper()
                handler = src.text(args[0])[:200]
                routes.append(_Route(verb, path, handler, src, args[0], dynamic=dynamic))
            elif name == "on" and len(args) == 2:
                for verb in re.findall(r"MethodFilter::(\w+)", src.text(args[0])) or ["ALL"]:
                    handler = src.text(args[1])[:200]
                    routes.append(_Route(verb, path, handler, src, args[1], dynamic=dynamic))
            elif name in ("layer", "route_layer") and args:
                g, u = _names(src, args[0])
                guards, unguards = guards + g, unguards + u
        for r in routes:
            r.guards, r.unguards = _unique(guards), sorted(set(unguards))
        return routes


class _Actix:
    def __init__(self, crate: _Crate) -> None:
        self.crate = crate
        self.macros: dict[str, tuple[_Source, Node, list[tuple[str, str, list[str]]]]] = {}
        self.registered: set[str] = set()
        for src in crate.sources:
            for n in walk(src.root):
                if n.type == "function_item" and (found := self._macro(src, n)):
                    self.macros[src.text(n.child_by_field_name("name"))] = (src, n, found)

    def _macro(self, src: _Source, fn: Node) -> list[tuple[str, str, list[str]]]:
        """(verb, path, guards) per route attribute on a handler, its grants attributes added."""
        attrs = []
        prev = fn.prev_named_sibling
        while prev is not None and prev.type == "attribute_item":
            attrs.append(prev)
            prev = prev.prev_named_sibling
        routes: list[tuple[str, str]] = []
        guards: list[str] = []
        for a in attrs:
            attr = next((c for c in a.named_children if c.type == "attribute"), None)
            if attr is None:
                continue
            name = _last(src.text(attr.named_children[0]))
            tokens = attr.child_by_field_name("arguments")
            text = src.text(tokens)
            path = (
                next((src.string(s) for s in walk(tokens) if s.type == "string_literal"), None)
                if tokens is not None
                else None
            )
            if name in VERBS and path is not None:
                routes.append((name.upper(), path))
            elif name == "route" and path is not None:
                routes += [(m, path) for m in re.findall(r'method\s*=\s*"(\w+)"', text)] or [
                    ("ALL", path)
                ]
            elif name in _GRANTS:
                guards.append(f"#[{name}{text[:60]}]")
            for wrap in re.findall(r'wrap\s*=\s*"([^"]+)"', text):
                g, _ = _guard_split(wrap)
                guards += g
        return [(verb, path, guards) for verb, path in routes]

    def rows(self) -> list[_Row]:
        rows = []
        for src in self.crate.sources:
            if not ACTIX_USE.search(src.file.text) and "App::new" not in src.file.text:
                continue
            for n in walk(src.root):
                if n.type == "call_expression" and _callee(src, n).endswith("App::new"):
                    rows += [
                        _finish(RouteFamily.ACTIX, r, self.crate)
                        for r in self.scope(src, _outermost(n), 0)
                    ]
        for name, (src, fn, found) in self.macros.items():
            if name in self.registered:
                continue
            for verb, path, guards in found:
                r = _Route(verb, path, name, src, fn, guards, [], [ACTIX_UNREGISTERED])
                rows.append(_finish(RouteFamily.ACTIX, r, self.crate))
        return rows

    def scope(self, src: _Source, expr: Node | None, depth: int) -> list[_Route]:
        if depth > _MAX_DEPTH:
            return []
        root, steps = _chain(src, expr)
        full = _callee(src, root)
        callee = _last(full)
        prefix = ""
        resource = None
        if callee in ("scope", "resource") or full.endswith(("Scope::new", "Resource::new")):
            path = src.string(_args(root)[0]) if root is not None and _args(root) else None
            if callee == "resource" or full.endswith("Resource::new"):
                resource = path or ""
            else:
                prefix = path or ""
        elif callee != "new" and not (root is not None and root.type == "identifier"):
            return []
        routes: list[_Route] = []
        guards: list[str] = []
        unguards: list[str] = []
        for name, args in steps:
            if name == "service" and args:
                routes += self._service(src, args[0], depth)
            elif name == "route" and len(args) == 2:
                routes += self._route(src, args[1], *_path(src, args[0]))
            elif name == "route" and len(args) == 1 and resource is not None:
                routes += self._route(src, args[0], "", False)
            elif name == "to" and args and resource is not None:
                routes.append(_Route("ALL", "", src.text(args[0])[:200], src, args[0]))
            elif name == "configure" and args:
                routes += self._configure(src, args[0], depth)
            elif name in ("wrap", "wrap_fn") and args:
                g, u = _names(src, args[0])
                guards, unguards = guards + g, unguards + u
        base = resource if resource is not None else prefix
        return [r.under(base, guards, unguards) for r in routes]

    def _service(self, src: _Source, expr: Node, depth: int) -> list[_Route]:
        expr = _unwrap(expr) or expr
        if expr.type in ("identifier", "scoped_identifier"):
            name = _last(src.text(expr))
            if name in self.macros:
                self.registered.add(name)
                msrc, fn, found = self.macros[name]
                return [_Route(v, p, name, msrc, fn, list(g)) for v, p, g in found]
            return []
        if expr.type == "tuple_expression":
            return [r for c in expr.named_children for r in self._service(src, c, depth)]
        return self.scope(src, expr, depth + 1)

    def _route(self, src: _Source, expr: Node, path: str, dynamic: bool) -> list[_Route]:
        """`web::get().to(h)`, `web::method(Method::GET).guard(..).to(h)`."""
        root, steps = _chain(src, expr)
        verb = _last(_callee(src, root)).upper()
        if verb == "METHOD" and root is not None:
            verb = _last(src.text(_args(root)[0])).upper() if _args(root) else "ALL"
        handler = next((a for n, a in steps if n == "to" and a), None)
        if handler is None:
            return []
        verb = verb if verb.lower() in VERBS else "ALL"
        guards = [g for n, a in steps if n in ("wrap", "guard") and a for g in _names(src, a[0])[0]]
        handler_text = src.text(handler[0])[:200]
        return [_Route(verb, path, handler_text, src, handler[0], guards, dynamic=dynamic)]

    def _configure(self, src: _Source, expr: Node, depth: int) -> list[_Route]:
        """`.configure(routes::config)`: the chains on the function's `ServiceConfig` parameter."""
        found = self.crate.function(src.text(expr))
        if found is None:
            return []
        fsrc, fn = found
        params = fn.child_by_field_name("parameters")
        names = [
            fsrc.text(p.child_by_field_name("pattern"))
            for p in (params.named_children if params is not None else [])
            if p.type == "parameter" and "ServiceConfig" in fsrc.text(p.child_by_field_name("type"))
        ]
        routes = []
        for n in walk(fn):
            if n.type != "call_expression" or _outermost(n) is not n:
                continue
            root, _ = _chain(fsrc, n)
            if root is not None and root.type == "identifier" and fsrc.text(root) in names:
                routes += self.scope(fsrc, n, depth + 1)
        return routes


def _guard_split(expr: str) -> tuple[list[str], list[str]]:
    names = re.findall(r"[A-Za-z_][\w:]*", expr)
    return [n for n in names if _is_guard(n)], [n for n in names if UNGUARD_RX.search(n)]


def id_(src: _Source, node: Node) -> int:
    return hash((src.file.rel, node.start_byte, node.end_byte))


def _path(src: _Source, node: Node) -> tuple[str, bool]:
    literal = src.string(node)
    return (literal, False) if literal is not None else (src.text(node)[:160], True)


def _finish(family: RouteFamily, r: _Route, crate: _Crate) -> _Row:
    named = re.fullmatch(r"[\w:]+", r.handler) is not None
    row = _row(
        family,
        r.method,
        r.pattern,
        r.handler,
        r.src.file.rel,
        r.src.line(r.node),
        _unique([*r.guards, *(crate.handler_guards(r.handler) if named else [])]),
        r.scope_guards,
        r.unguards,
    )
    if named and (found := crate.function(r.handler)) is not None:
        row.handler_path, row.handler_line = found[0].file.rel, found[0].line(found[1])
    return _mark(row, None, r.dynamic, r.src.file.rel)


@dataclass
class RustRoutes:
    rows: list[_Row]
    evidence: dict[RouteFamily, str]  # a file per family that uses it
    parsed: bool  # whether the Rust parser was available


def rust_rows(files: list[TreeFile]) -> RustRoutes:
    """The axum and actix-web rows of a checkout's Rust sources."""
    rust = [f for f in files if f.path.suffix == ".rs"]
    evidence: dict[RouteFamily, str] = {}
    for f in rust:
        for family, rx in ((RouteFamily.AXUM, AXUM_USE), (RouteFamily.ACTIX, ACTIX_USE)):
            if family not in evidence and rx.search(f.text):
                evidence[family] = f.rel
    if not evidence:
        return RustRoutes([], {}, True)
    available = parser()
    if available is None:
        return RustRoutes([], evidence, False)
    sources = []
    for f in rust:
        data = f.text.encode("utf-8")
        sources.append(_Source(f, available.parse(data).root_node, data))
    crate = _Crate(sources)
    return RustRoutes(_Axum(crate).rows() + _Actix(crate).rows(), evidence, True)
