"""Express routes (express, express-promise-router) in JS/TS and the guards applied to each,
parsed with tree-sitter from the `js` extra. A Backstage plugin's router mounted through its
`httpRouter` service is authenticated by default; a path its auth policy opens is judged."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.route_guards import (
    UNGUARD_RX,
    _guards_in,
    _mark,
    _Row,
    _row,
    _unguards_in,
    _unique,
)
from traust_core.v1.providers.syntax import Node, Parsed
from traust_core.v1.providers.syntax import js_parsers as parsers
from traust_core.v1.providers.syntax import walk as _walk
from traust_core.v1.providers.tree import TreeFile

EXPRESS_IMPORT = re.compile(
    r"""(?:require\(\s*|\bfrom\s+|\bimport\s+)["'](?:express|express-promise-router)["']"""
)
GRAMMARS = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}
EXPRESS_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "all")
_ROUTER_TYPES = re.compile(r"^(?:express\.)?(Router|Application|Express)\b")
# Middleware that loads state or sets headers (a session, passport's user, helmet): it never
# refuses a request, whatever its name says.
_NON_ENFORCING = re.compile(
    r"^(session|expressSession|cookieSession|passport\.(initialize|session)|helmet(\.\w+)?|"
    r"cookieParser|cors)$"
)
_BACKSTAGE_ROOT = "<backstage:httpRouter>"
BACKSTAGE_GUARD = "backstage:httpRouter"
_OPEN_POLICIES = ("unauthenticated", "user-cookie")
_MAX_MOUNTS = 8

_Key = tuple[str, str]


def _unwrap(node: Node | None) -> Node | None:
    """The expression inside `await x`, `(x)`, `x as T` and `x!`."""
    while node is not None and node.type in (
        "await_expression",
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
        "satisfies_expression",
    ):
        node = next((c for c in node.named_children if c.type != "type_annotation"), None)
    return node


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args else []


class _Source(Parsed):
    def string(self, node: Node | None) -> str | None:
        """A string or substitution-free template literal's value."""
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "string":
            return "".join(self.text(c) for c in node.named_children if c.type == "string_fragment")
        if node.type == "template_string" and not any(
            c.type == "template_substitution" for c in node.named_children
        ):
            return self.text(node)[1:-1]
        return None


@dataclass
class _Mount:
    parent: _Key
    prefix: str
    guards: list[str]
    unguards: list[str]


@dataclass
class _Scope:
    prefix: str
    guards: list[str]
    unguards: list[str]
    policies: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class _Express:
    sources: list[_Source]
    receivers: set[_Key] = field(default_factory=set)
    uses: dict[_Key, list[tuple[int, list[str], list[str]]]] = field(default_factory=dict)
    mounts: dict[_Key, list[_Mount]] = field(default_factory=dict)
    policies: dict[_Key, list[tuple[str, str]]] = field(default_factory=dict)
    exports: dict[str, dict[str, str]] = field(default_factory=dict)
    imports: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)
    functions: dict[str, dict[str, Node]] = field(default_factory=dict)
    methods: dict[str, dict[str, Node]] = field(default_factory=dict)
    aliases: dict[_Key, _Key] = field(default_factory=dict)
    by_path: dict[str, _Source] = field(default_factory=dict)
    backstage: dict[str, set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.by_path = {s.file.rel: s for s in self.sources}
        for src in self.sources:
            self._index(src)
        for src in self.sources:
            self._alias(src)
        for src in self.sources:
            self._wire(src)

    def _resolve_module(self, rel: str, spec: str) -> str | None:
        if not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        stem = base.removesuffix(posixpath.splitext(base)[1]) if base.endswith(".js") else base
        for candidate in (
            base,
            *(stem + s for s in GRAMMARS),
            *(f"{base}/index{s}" for s in GRAMMARS),
        ):
            if candidate in self.by_path:
                return candidate
        return None

    def _index(self, src: _Source) -> None:
        rel = src.file.rel
        exports = self.exports.setdefault(rel, {})
        imports = self.imports.setdefault(rel, {})
        functions = self.functions.setdefault(rel, {})
        methods = self.methods.setdefault(rel, {})
        backstage = self.backstage.setdefault(rel, set())
        for n in _walk(src.root):
            if n.type == "import_statement":
                spec = src.string(n.child_by_field_name("source"))
                where = self._resolve_module(rel, spec or "")
                for c in _walk(n):
                    if where is None:
                        break
                    if c.type == "import_clause":
                        default = next(
                            (x for x in c.named_children if x.type == "identifier"), None
                        )
                        if default is not None:
                            imports[src.text(default)] = (where, "default")
                    elif c.type == "import_specifier":
                        name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
                        imports[src.text(alias or name)] = (where, src.text(name))
            elif n.type == "variable_declarator":
                name, value = n.child_by_field_name("name"), _unwrap(n.child_by_field_name("value"))
                if name is None or value is None:
                    continue
                if value.type == "call_expression":
                    callee = src.text(value.child_by_field_name("function"))
                    if callee == "require" and name.type == "identifier":
                        spec = src.string(_args(value)[0]) if _args(value) else None
                        if where := self._resolve_module(rel, spec or ""):
                            imports[src.text(name)] = (where, "default")
                    elif self._is_ctor(callee) and name.type == "identifier":
                        self.receivers.add((rel, src.text(name)))
                elif value.type in ("arrow_function", "function_expression", "function"):
                    functions[src.text(name)] = value
                if (
                    n.parent is not None
                    and n.parent.parent is not None
                    and (n.parent.parent.type == "export_statement")
                ):
                    exports[src.text(name)] = src.text(name)
            elif n.type == "method_definition" and (name := n.child_by_field_name("name")):
                methods.setdefault(src.text(name), n)
            elif n.type in ("function_declaration", "generator_function_declaration"):
                name = n.child_by_field_name("name")
                if name is not None:
                    functions[src.text(name)] = n
                    if n.parent is not None and n.parent.type == "export_statement":
                        is_default = any(c.type == "default" for c in n.parent.children)
                        exports["default" if is_default else src.text(name)] = src.text(name)
            elif n.type == "export_statement" and any(c.type == "default" for c in n.children):
                value = n.child_by_field_name("value") or next(
                    (c for c in n.named_children if c.type == "identifier"), None
                )
                if value is not None and value.type == "identifier":
                    exports["default"] = src.text(value)
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), _unwrap(n.child_by_field_name("right"))
                if (
                    src.text(left) == "module.exports"
                    and right is not None
                    and (right.type == "identifier")
                ):
                    exports["default"] = src.text(right)
            elif n.type in ("required_parameter", "optional_parameter"):
                pattern, annotation = (
                    n.child_by_field_name("pattern"),
                    n.child_by_field_name("type"),
                )
                if (
                    pattern is not None
                    and annotation is not None
                    and _ROUTER_TYPES.match(src.text(annotation).lstrip(": ").strip())
                ):
                    self.receivers.add((rel, src.text(pattern)))
            elif n.type == "pair" and src.text(n.child_by_field_name("value")) == (
                "coreServices.httpRouter"
            ):
                backstage.add(src.text(n.child_by_field_name("key")))

    def _alias(self, src: _Source) -> None:
        """`const sse = createSseRouter(opts)`: the name is the router the factory returns."""
        rel = src.file.rel
        for n in _walk(src.root):
            if n.type != "variable_declarator":
                continue
            name, value = n.child_by_field_name("name"), _unwrap(n.child_by_field_name("value"))
            if name is None or name.type != "identifier" or (rel, src.text(name)) in self.receivers:
                continue
            if (
                value is not None
                and value.type == "call_expression"
                and (found := self._key(rel, value)) is not None
            ):
                self.aliases[(rel, src.text(name))] = found

    @staticmethod
    def _is_ctor(callee: str) -> bool:
        return callee in ("express", "Router", "express.Router", "PromiseRouter") or bool(
            re.fullmatch(r"\w+\.Router", callee)
        )

    def _key(self, rel: str, node: Node | None, seen: frozenset[str] = frozenset()) -> _Key | None:
        """The router an expression is: a bound name, an imported export, or what a router
        factory (`await createRouter(opts)`) returns."""
        node = _unwrap(node)
        if node is None:
            return None
        src = self.by_path[rel]
        if node.type == "identifier":
            name = src.text(node)
            if (rel, name) in self.receivers:
                return rel, name
            if (rel, name) in self.aliases:
                return self.aliases[(rel, name)]
            if name in self.imports.get(rel, {}):
                where, exported = self.imports[rel][name]
                local = self.exports.get(where, {}).get(exported)
                if local and (where, local) in self.receivers:
                    return where, local
            return None
        if node.type == "call_expression":
            callee = _unwrap(node.child_by_field_name("function"))
            fn, where = (
                self._method(rel, callee)
                if callee is not None and callee.type == "member_expression"
                else self._function(rel, callee)
            )
            if fn is None or where is None or f"{where}:{fn.start_byte}" in seen:
                return None
            for n in _walk(fn):
                if n.type == "return_statement" and n.named_children:
                    found = self._key(
                        where, n.named_children[0], seen | {f"{where}:{fn.start_byte}"}
                    )
                    if found:
                        return found
        return None

    def _method(self, rel: str, node: Node) -> tuple[Node | None, str | None]:
        """A method a call names (`oidc.getRouter()`): this file's, then an imported file's."""
        name = self.by_path[rel].text(node.child_by_field_name("property"))
        files = [rel, *dict.fromkeys(w for w, _ in self.imports.get(rel, {}).values())]
        for where in files:
            if name in self.methods.get(where, {}):
                return self.methods[where][name], where
        return None, None

    def _function(self, rel: str, node: Node | None) -> tuple[Node | None, str | None]:
        if node is None or node.type != "identifier":
            return None, None
        name = self.by_path[rel].text(node)
        if name in self.functions.get(rel, {}):
            return self.functions[rel][name], rel
        if name in self.imports.get(rel, {}):
            where, exported = self.imports[rel][name]
            local = self.exports.get(where, {}).get(exported, exported)
            return self.functions.get(where, {}).get(local), where
        return None, None

    def _receiver(self, src: _Source, node: Node | None) -> _Key | None:
        node = _unwrap(node)
        if node is None or node.type != "identifier":
            return None
        key = (src.file.rel, src.text(node))
        return key if key in self.receivers else self.aliases.get(key)

    def _names(self, src: _Source, node: Node) -> tuple[list[str], list[str]]:
        """Guard and unguard names a middleware or handler expression carries: the names it is
        built from, never a string's contents or an inline function's body (only that body's bare
        guard calls)."""
        node = _unwrap(node) or node
        if node.type in ("arrow_function", "function_expression", "function"):
            return _bare_guard_calls(src, node)
        names = " ".join(n for n in _identifiers(src, node) if not _NON_ENFORCING.match(n))
        return _guards_in(names), _unguards_in(names)

    def _wire(self, src: _Source) -> None:
        rel = src.file.rel
        for call in _walk(src.root):
            if call.type != "call_expression":
                continue
            fn = call.child_by_field_name("function")
            if fn is None or fn.type != "member_expression":
                continue
            obj, prop = (
                fn.child_by_field_name("object"),
                src.text(fn.child_by_field_name("property")),
            )
            target = src.text(obj)
            if target in self.backstage.get(rel, set()):
                self._backstage(src, call, prop)
                continue
            parent = self._receiver(src, obj)
            if parent is None or prop != "use":
                continue
            args = _args(call)
            prefix = src.string(args[0]) if args else None
            if prefix is not None:
                args = args[1:]
            guards: list[str] = []
            unguards: list[str] = []
            for arg in args:
                child = self._key(rel, arg)
                if child is not None:
                    before = [u for u in self.uses.get(parent, []) if u[0] < call.start_byte]
                    self.mounts.setdefault(child, []).append(
                        _Mount(
                            parent,
                            prefix or "",
                            _unique([*(g for u in before for g in u[1]), *guards]),
                            sorted({*(x for u in before for x in u[2]), *unguards}),
                        )
                    )
                    continue
                g, u = self._names(src, arg)
                guards += g
                unguards += u
            if prefix is None and (guards or unguards):
                self.uses.setdefault(parent, []).append((call.start_byte, guards, unguards))

    def _backstage(self, src: _Source, call: Node, prop: str) -> None:
        root = (src.file.rel, _BACKSTAGE_ROOT)
        args = _args(call)
        if prop == "use":
            for arg in args:
                if (child := self._key(src.file.rel, arg)) is not None:
                    self.mounts.setdefault(child, []).append(
                        _Mount(root, "", [BACKSTAGE_GUARD], [])
                    )
        elif prop == "addAuthPolicy" and args and args[0].type == "object":
            fields = {
                src.text(p.child_by_field_name("key")): src.string(p.child_by_field_name("value"))
                for p in args[0].named_children
                if p.type == "pair"
            }
            if fields.get("path") is not None and fields.get("allow") in _OPEN_POLICIES:
                self.policies.setdefault(root, []).append((fields["path"], fields["allow"]))

    def chains(self, key: _Key, seen: frozenset[_Key] = frozenset()) -> list[_Scope]:
        if key[1] == _BACKSTAGE_ROOT:
            return [_Scope("", [], [], list(self.policies.get(key, [])))]
        parents = [m for m in self.mounts.get(key, []) if m.parent not in seen]
        if not parents:
            return [_Scope("", [], [])]
        out = []
        for m in parents[:_MAX_MOUNTS]:
            for up in self.chains(m.parent, seen | {key}):
                out.append(
                    _Scope(
                        up.prefix + m.prefix,
                        _unique([*up.guards, *m.guards]),
                        sorted({*up.unguards, *m.unguards}),
                        up.policies,
                    )
                )
        return out[:_MAX_MOUNTS]

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for src in self.sources:
            for call in _walk(src.root):
                if call.type == "call_expression":
                    rows += self._registration(src, call)
        return rows

    def _registration(self, src: _Source, call: Node) -> list[_Row]:
        fn = call.child_by_field_name("function")
        args = _args(call)
        if fn is not None and fn.type == "member_expression":
            verb = src.text(fn.child_by_field_name("property"))
            obj = fn.child_by_field_name("object")
            if verb in EXPRESS_VERBS:
                if (key := self._receiver(src, obj)) is not None and len(args) >= 2:
                    return self._rows(src, call, key, verb, args[0], args[1:])
                route = _unwrap(obj)
                while route is not None and route.type == "call_expression":
                    inner = route.child_by_field_name("function")
                    if inner is None or inner.type != "member_expression":
                        break
                    if src.text(inner.child_by_field_name("property")) == "route":
                        key = self._receiver(src, inner.child_by_field_name("object"))
                        route_args = _args(route)
                        if key is not None and route_args and args:
                            return self._rows(src, call, key, verb, route_args[0], args)
                        break
                    route = _unwrap(inner.child_by_field_name("object"))
        # registerHandler(app.get, '/path', handler): the verb is passed as a value
        if len(args) >= 3 and args[0].type == "member_expression":
            verb = src.text(args[0].child_by_field_name("property"))
            key = self._receiver(src, args[0].child_by_field_name("object"))
            if key is not None and verb in EXPRESS_VERBS:
                return self._rows(src, call, key, verb, args[1], args[2:])
        return []

    def _rows(
        self, src: _Source, call: Node, key: _Key, verb: str, path: Node, handlers: list[Node]
    ) -> list[_Row]:
        literal = src.string(path)
        pattern, dynamic = (literal, False) if literal is not None else (src.text(path)[:160], True)
        guards: list[str] = []
        unguards: list[str] = []
        for h in handlers[:-1]:
            g, u = self._names(src, h)
            guards += g
            unguards += u
        last = _unwrap(handlers[-1]) or handlers[-1]
        if last.type == "call_expression":
            g, u = self._names(src, last.child_by_field_name("arguments") or last)
            guards, unguards = guards + g, unguards + u
        elif last.type in ("arrow_function", "function_expression", "function"):
            g, u = _bare_guard_calls(src, last)
            guards, unguards = guards + g, unguards + u
        before = [u for u in self.uses.get(key, []) if u[0] < call.start_byte]
        rows = []
        for scope in self.chains(key):
            full = scope.prefix + pattern
            opened = [
                f"backstage:allow-{allow}"
                for p, allow in scope.policies
                if full == p or full.startswith(p.rstrip("/") + "/")
            ]
            row = _row(
                RouteFamily.EXPRESS,
                verb.upper(),
                full,
                src.text(last)[:200]
                if last.type not in ("arrow_function", "function_expression")
                else "<inline>",
                src.file.rel,
                src.line(call),
                _unique(guards),
                _unique([*scope.guards, *(g for u in before for g in u[1])]),
                sorted({*unguards, *scope.unguards, *(x for u in before for x in u[2]), *opened}),
            )
            row.handler_line = src.line(last)
            rows.append(_mark(row, key[1], dynamic, src.file.rel))
        return rows


def _identifiers(src: _Source, node: Node) -> list[str]:
    """The dotted names an expression is made of (a callee and its name arguments)."""
    node = _unwrap(node) or node
    if node.type in ("identifier", "member_expression", "property_identifier"):
        return [src.text(node)]
    if node.type == "call_expression":
        return [
            *_identifiers(src, node.child_by_field_name("function")),
            *(n for a in _args(node) for n in _identifiers(src, a)),
        ]
    if node.type in ("arguments", "array", "spread_element"):
        return [n for c in node.named_children for n in _identifiers(src, c)]
    return []


def _bare_guard_calls(src: _Source, fn: Node) -> tuple[list[str], list[str]]:
    """Guard-shaped calls an inline handler makes as bare statements of its own body (`await
    requireAdmin(req)`); a kept result only reads who is calling."""
    body = fn.child_by_field_name("body")
    names = []
    for stmt in body.named_children if body is not None and body.type == "statement_block" else []:
        if stmt.type != "expression_statement" or not stmt.named_children:
            continue
        value = _unwrap(stmt.named_children[0])
        if value is not None and value.type == "call_expression":
            names.append(src.text(value.child_by_field_name("function")))
    guards = [f"call:{n}" for n in _guards_in(" ".join(names))]
    unguards = [f"call:{n}" for n in names if UNGUARD_RX.search(n)]
    return guards, unguards


def express_rows(files: list[TreeFile]) -> tuple[list[_Row], str | None, bool]:
    """(rows, a file importing express or None, whether the JS/TS parser was available)."""
    candidates = [f for f in files if f.path.suffix in GRAMMARS and not f.name.endswith(".d.ts")]
    evidence = next((f.rel for f in candidates if EXPRESS_IMPORT.search(f.text)), None)
    if evidence is None:
        return [], None, True
    available = parsers()
    if available is None:
        return [], evidence, False
    sources = []
    for f in candidates:
        data = f.text.encode("utf-8")
        sources.append(_Source(f, available[GRAMMARS[f.path.suffix]].parse(data).root_node, data))
    return _Express(sources).rows(), evidence, True
