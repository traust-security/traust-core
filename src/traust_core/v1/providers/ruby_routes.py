"""Rails and Sinatra routes in Ruby and the guards on each, parsed with tree-sitter from the
`ruby` extra. Rails routes come from `config/routes.rb` and their guards from each controller's
`before_action` chain (inherited, `only`/`except`, and `skip_before_action`, which is judged);
Sinatra guards are `before` filters, `use Rack::Auth::*` and guard calls in the route body."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from traust_core.v1.models.code_facts import RouteAsymmetry, RouteFamily
from traust_core.v1.models.common import RepoPath
from traust_core.v1.providers.route_guards import (
    GUARD_RX,
    NON_ENFORCING_RX,
    UNGUARD_RX,
    _mark,
    _Row,
    _row,
    _unique,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import ruby_parser as parser
from traust_core.v1.providers.tree import TreeFile

SINATRA_USE = re.compile(r"""require\s+['"]sinatra|Sinatra::(?:Base|Application)""")
VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
_ACTIONS = {
    "index": ("GET", ""),
    "create": ("POST", ""),
    "new": ("GET", "/new"),
    "edit": ("GET", "/:id/edit"),
    "show": ("GET", "/:id"),
    "update": ("PATCH", "/:id"),
    "destroy": ("DELETE", "/:id"),
}
_SINGULAR_ACTIONS = ("create", "new", "edit", "show", "update", "destroy")
_BEFORE = ("before_action", "prepend_before_action", "append_before_action", "before_filter")
_SKIP = ("skip_before_action", "skip_before_filter")
# callbacks that guard whatever their name says
_GUARD_CALLBACKS = (
    "http_basic_authenticate_with",
    "load_and_authorize_resource",
    "authorize_resource",
)
SKIPPED = "skip_before_action"


def _is_guard(name: str) -> bool:
    if UNGUARD_RX.search(name):
        return False
    return bool(GUARD_RX.search(NON_ENFORCING_RX.sub("", name)))


class _Source(Parsed):
    def string(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type in ("simple_symbol", "hash_key_symbol"):
            return self.text(node).lstrip(":")
        interpolated = any(c.type == "interpolation" for c in node.named_children)
        if node.type == "string" and not interpolated:
            return "".join(self.text(c) for c in node.named_children if c.type == "string_content")
        return None


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args else []


def _method(src: _Source, call: Node) -> str:
    return src.text(call.child_by_field_name("method"))


def _body(call: Node) -> list[Node]:
    block = call.child_by_field_name("block")
    if block is None:
        return []
    body = block.child_by_field_name("body") or next(
        (c for c in block.named_children if c.type in ("body_statement", "block_body")), None
    )
    return list(body.named_children) if body is not None else []


def _options(src: _Source, call: Node) -> dict[str, Node]:
    """A call's `key: value` and `"path" => "c#a"` pairs, by key (`=>` under its own key)."""
    found = {}
    for a in _args(call):
        for p in [a] if a.type == "pair" else (a.named_children if a.type == "hash" else []):
            if p.type == "pair":
                key = p.child_by_field_name("key")
                symbol = key.type in ("hash_key_symbol", "simple_symbol")
                found[src.string(key) if symbol else "=>"] = p.child_by_field_name("value")
    return found


def _names(src: _Source, node: Node | None) -> list[str]:
    """Symbol or string values, one or an array of them."""
    if node is None:
        return []
    items = node.named_children if node.type == "array" else [node]
    return [v for i in items if (v := src.string(i)) is not None]


def _plural(name: str) -> str:
    if name.endswith("s"):
        return name
    if name.endswith("y") and name[-2:-1] not in "aeiou":
        return name[:-1] + "ies"
    return name + "s"


def _singular(name: str) -> str:
    if name.endswith("ies"):
        return name[:-3] + "y"
    return name[:-1] if name.endswith("s") else name


@dataclass(frozen=True)
class _Scope:
    path: str = ""
    module: str = ""
    controller: str | None = None
    member: str | None = None  # the resource's member path, `/posts/:id`
    guards: tuple[str, ...] = ()


@dataclass
class _Route:
    method: str
    pattern: str
    controller: str
    action: str
    src: _Source
    node: Node
    scope_guards: tuple[str, ...] = ()


def _join(*parts: str) -> str:
    segments = [p.strip("/") for p in parts if p.strip("/")]
    return "/" + "/".join(segments)


class _RailsRoutes:
    """`config/routes.rb` (and the files it `draw`s) as (verb, path, controller#action) rows."""

    def __init__(self, sources: dict[str, _Source]) -> None:
        self.sources = sources
        self.routes: list[_Route] = []
        for rel, src in sources.items():
            if rel.endswith("config/routes.rb"):
                for n in walk(src.root):
                    if (
                        n.type == "call"
                        and _method(src, n) == "draw"
                        and "routes" in src.text(n.child_by_field_name("receiver"))
                    ):
                        self._block(src, _body(n), _Scope(), rel.removesuffix("routes.rb"))

    def _block(self, src: _Source, calls: list[Node], scope: _Scope, config: str) -> None:
        for c in calls:
            if c.type == "call":
                self._call(src, c, scope, config)

    def _controller(self, scope: _Scope, name: str) -> str:
        return f"{scope.module}{name}" if "/" not in name else name

    def _call(self, src: _Source, call: Node, scope: _Scope, config: str) -> None:
        name = _method(src, call)
        args = _args(call)
        opts = _options(src, call)
        first = src.string(args[0]) if args else None
        if name in ("resources", "resource"):
            for res in [v for a in args if (v := src.string(a)) is not None and a.type != "pair"]:
                self._resource(src, call, scope, config, res, name == "resource", opts)
        elif name == "namespace" and first:
            module = f"{scope.module}{first}/"
            inner = replace(scope, path=_join(scope.path, first), module=module)
            self._block(src, _body(call), inner, config)
        elif name == "scope":
            positional = first is not None and args[0].type != "pair"
            path = first if positional else src.string(opts.get("path"))
            module = src.string(opts.get("module"))
            inner = replace(
                scope,
                path=_join(scope.path, path or ""),
                module=f"{scope.module}{module}/" if module else scope.module,
            )
            self._block(src, _body(call), inner, config)
        elif name in ("member", "collection") and scope.member is not None:
            path = scope.member if name == "member" else scope.member.rsplit("/:", 1)[0]
            self._block(src, _body(call), replace(scope, path=path, member=None), config)
        elif name in ("authenticate", "authenticated"):
            who = first or "user"
            guarded = replace(scope, guards=(*scope.guards, f"devise:{name}({who})"))
            self._block(src, _body(call), guarded, config)
        elif name in ("constraints", "defaults", "controller", "concern"):
            inner = scope if name != "controller" or not first else replace(scope, controller=first)
            if name != "concern":
                self._block(src, _body(call), inner, config)
        elif name in (*VERBS, "match"):
            self._verb(src, call, scope, name, first, opts)
        elif name == "root":
            positional = first is not None and args[0].type != "pair"
            target = first if positional else src.string(opts.get("to"))
            self._add(src, call, scope, "GET", scope.path or "/", target)
        elif name == "mount" and args:
            at = src.string(opts.get("at")) or src.string(opts.get("=>"))
            mounted = args[0].child_by_field_name("key") if args[0].type == "pair" else args[0]
            path = _join(scope.path, at or "")
            self.routes.append(_Route("ALL", path, src.text(mounted), "", src, call, scope.guards))
        elif name == "draw" and first:
            included = self.sources.get(f"{config}routes/{first}.rb")
            if included is not None:
                self._block(included, list(included.root.named_children), scope, config)

    def _resource(
        self,
        src: _Source,
        call: Node,
        scope: _Scope,
        config: str,
        name: str,
        singular: bool,
        opts: dict[str, Node],
    ) -> None:
        path = _join(scope.path, src.string(opts.get("path")) or name)
        named = src.string(opts.get("controller")) or (_plural(name) if singular else name)
        controller = self._controller(scope, named)
        actions = list(_SINGULAR_ACTIONS if singular else _ACTIONS)
        if "only" in opts:
            actions = [a for a in actions if a in _names(src, opts["only"])]
        if "except" in opts:
            actions = [a for a in actions if a not in _names(src, opts["except"])]
        for action in actions:
            verb, suffix = _ACTIONS[action]
            suffix = suffix.replace("/:id", "") if singular else suffix
            for v in (verb, "PUT") if action == "update" else (verb,):
                route = _Route(v, path + suffix, controller, action, src, call, scope.guards)
                self.routes.append(route)
        member = path if singular else f"{path}/:id"
        nested = f"{path}/:{_singular(name)}_id" if not singular else path
        self._block(
            src,
            _body(call),
            replace(scope, path=nested, controller=controller, member=member),
            config,
        )

    def _verb(
        self,
        src: _Source,
        call: Node,
        scope: _Scope,
        name: str,
        first: str | None,
        opts: dict[str, Node],
    ) -> None:
        target = src.string(opts.get("to")) or src.string(opts.get("=>"))
        if target is None and "controller" in opts:
            target = f"{src.string(opts['controller'])}#{src.string(opts.get('action')) or first}"
        if target is None and first and scope.controller:
            target = f"{scope.controller}#{first}"  # `get :preview` inside a resource
        path = _join(scope.path, first or "")
        verbs = (
            [name.upper()]
            if name != "match"
            else [v.upper() for v in _names(src, opts.get("via"))] or ["ALL"]
        )
        for v in verbs:
            self._add(src, call, scope, "ALL" if v == "ALL" else v, path, target)

    def _add(
        self, src: _Source, call: Node, scope: _Scope, verb: str, path: str, target: str | None
    ) -> None:
        controller, _, action = (target or "").partition("#")
        self.routes.append(
            _Route(verb, path, self._controller(scope, controller), action, src, call, scope.guards)
        )


@dataclass
class _Callback:
    name: str
    only: list[str] | None
    skip: bool
    except_: list[str] = field(default_factory=list)

    def applies(self, action: str) -> bool:
        return (self.only is None or action in self.only) and action not in self.except_


@dataclass
class _Controller:
    name: str
    parent: str | None
    callbacks: list[_Callback]
    actions: dict[str, Node]
    src: _Source


def _controllers(sources: dict[str, _Source]) -> dict[str, _Controller]:
    """Controllers by route name (`admin/users`) and by class name (`ApplicationController`)."""
    found: dict[str, _Controller] = {}
    for rel, src in sources.items():
        for n in walk(src.root):
            if n.type != "class":
                continue
            name = src.text(n.child_by_field_name("name"))
            if not name.endswith("Controller"):
                continue
            sup = n.child_by_field_name("superclass")
            base = sup.named_children[0] if sup is not None and sup.named_children else None
            parent = src.text(base).rsplit("::", 1)[-1] if base is not None else None
            callbacks: list[_Callback] = []
            actions: dict[str, Node] = {}
            body = n.child_by_field_name("body")
            for stmt in body.named_children if body is not None else []:
                if stmt.type == "method":
                    actions[src.text(stmt.child_by_field_name("name"))] = stmt
                elif stmt.type in ("call", "identifier"):
                    method = _method(src, stmt) if stmt.type == "call" else src.text(stmt)
                    callbacks += _callbacks(src, stmt, method)
            controller = _Controller(name, parent, callbacks, actions, src)
            found[name.rsplit("::", 1)[-1]] = controller
            if m := re.search(r"app/controllers/(.+)_controller\.rb$", rel):
                found[m.group(1)] = controller
    return found


def _callbacks(src: _Source, stmt: Node, method: str) -> list[_Callback]:
    if method not in (*_BEFORE, *_SKIP, *_GUARD_CALLBACKS):
        return []
    opts = _options(src, stmt) if stmt.type == "call" else {}
    only = _names(src, opts.get("only")) if "only" in opts else None
    except_ = _names(src, opts.get("except"))
    if method in _GUARD_CALLBACKS:
        return [_Callback(method, only, False, except_)]
    args = _args(stmt) if stmt.type == "call" else []
    names = [v for a in args if a.type != "pair" and (v := src.string(a))]
    return [_Callback(n, only, method in _SKIP, except_) for n in names]


def _chain(controllers: dict[str, _Controller], c: _Controller) -> list[_Controller]:
    chain, seen = [c], {c.name}
    while chain[-1].parent and chain[-1].parent in controllers:
        parent = controllers[chain[-1].parent]
        if parent.name in seen:
            break
        chain.append(parent)
        seen.add(parent.name)
    return chain[::-1]


def _rails_guards(
    controllers: dict[str, _Controller], c: _Controller, action: str
) -> tuple[list[str], list[str]]:
    """(guards, unguards): the before_action guards that run for the action, base class first;
    a skip that removes one is an unguard, judged."""
    active: list[str] = []
    skipped: list[str] = []
    for ctrl in _chain(controllers, c):
        for cb in ctrl.callbacks:
            if not cb.applies(action):
                continue
            if cb.skip:
                if cb.name in active:
                    active.remove(cb.name)
                    skipped.append(f"{SKIPPED}:{cb.name}")
            elif (_is_guard(cb.name) or cb.name in _GUARD_CALLBACKS) and cb.name not in active:
                active.append(cb.name)
    return active, skipped


def _body_guard_calls(src: _Source, stmts: list[Node]) -> list[str]:
    names = [
        src.text(s.child_by_field_name("method")) if s.type == "call" else src.text(s)
        for s in stmts
        if s.type in ("call", "identifier")
    ]
    return [f"call:{n}" for n in names if _is_guard(n)]


def _rails_rows(sources: dict[str, _Source]) -> list[_Row]:
    controllers = _controllers(sources)
    rows = []
    for r in _RailsRoutes(sources).routes:
        c = controllers.get(r.controller)
        guards: list[str] = []
        unguards: list[str] = []
        handler_path, handler_line = r.src.file.rel, r.src.line(r.node)
        if c is not None:
            guards, unguards = _rails_guards(controllers, c, r.action)
            if (action := c.actions.get(r.action)) is not None:
                body = action.child_by_field_name("body")
                guards += _body_guard_calls(c.src, list(body.named_children) if body else [])
                handler_path, handler_line = c.src.file.rel, c.src.line(action)
        row = _row(
            RouteFamily.RAILS,
            r.method,
            r.pattern,
            f"{r.controller}#{r.action}" if r.action else r.controller,
            r.src.file.rel,
            r.src.line(r.node),
            _unique(guards),
            list(r.scope_guards),
            unguards,
        )
        row.handler_path, row.handler_line = handler_path, handler_line
        _mark(row, None, False, r.src.file.rel)
        row.view_class = c.name if c is not None else r.controller
        rows.append(row)
    return rows


def callback_asymmetries(rows: list[_Row]) -> list[RouteAsymmetry]:
    """Within one controller, actions missing a guard callback its other actions run (the
    `before_action :x, except: [...]` shape): each is judged."""
    groups: dict[tuple[str, str], list[_Row]] = {}
    for r in rows:
        if r.family is RouteFamily.RAILS and r.view_class:
            groups.setdefault((r.handler_path, r.view_class), []).append(r)
    found = []
    for (path, controller), members in sorted(groups.items()):
        for guard in _unique(g for r in members for g in r.guards if not g.startswith("call:")):
            lack = [r for r in members if guard not in r.guards]
            if not lack or len(lack) == len(members):
                continue
            found.append(
                RouteAsymmetry(
                    family=RouteFamily.RAILS,
                    path=RepoPath(path),
                    group=controller,
                    guarded=tuple(r.label for r in members if guard in r.guards),
                    unguarded=tuple(r.label for r in lack),
                )
            )
            for r in lack:
                r.mark()
    return found


def _sinatra_pattern(path: str) -> re.Pattern[str]:
    out = re.escape(path).replace(r"\*", ".*")
    return re.compile(re.sub(r":\w+", "[^/]+", out))


def _sinatra_rows(src: _Source) -> list[_Row]:
    rows: list[_Row] = []
    scope: list[str] = []
    filters: list[tuple[re.Pattern[str] | None, list[str]]] = []
    calls = [
        n for n in walk(src.root) if n.type == "call" and n.child_by_field_name("receiver") is None
    ]
    for call in calls:
        name = _method(src, call)
        args = _args(call)
        if name == "use" and args:
            scope += [t for t in re.findall(r"[A-Za-z_][\w:]*", src.text(args[0])) if _is_guard(t)]
        elif name == "before":
            path = src.string(args[0]) if args else None
            names = [
                src.text(n.child_by_field_name("method")) if n.type == "call" else src.text(n)
                for n in walk(call.child_by_field_name("block") or call)
                if n.type in ("call", "identifier")
            ]
            guards = [f"before:{n}" for n in _unique(names) if _is_guard(n)]
            if guards:
                filters.append((_sinatra_pattern(path) if path else None, guards))
    namespaces = [
        (ns.start_byte, ns.end_byte, src.string(_args(ns)[0]) or "")
        for ns in calls
        if _method(src, ns) == "namespace" and _args(ns)
    ]
    for call in calls:
        name = _method(src, call)
        args = _args(call)
        if name not in VERBS or not args or call.child_by_field_name("block") is None:
            continue
        literal = src.string(args[0])
        prefix = [p for start, end, p in namespaces if start < call.start_byte < end]
        pattern = _join(*prefix, literal) if literal is not None else src.text(args[0])[:160]
        scoped = [
            g for rx, gs in filters if rx is None or (literal and rx.fullmatch(pattern)) for g in gs
        ]
        row = _row(
            RouteFamily.SINATRA,
            name.upper(),
            pattern,
            "<block>",
            src.file.rel,
            src.line(call),
            _body_guard_calls(src, _body(call)),
            _unique([*scope, *scoped]),
            [],
        )
        rows.append(_mark(row, None, literal is None, src.file.rel))
    return rows


@dataclass
class RubyRoutes:
    rows: list[_Row]
    evidence: dict[RouteFamily, str]  # a file per family that uses it
    parsed: bool  # whether the Ruby parser was available


def ruby_rows(files: list[TreeFile]) -> RubyRoutes:
    """The Rails and Sinatra rows of a checkout's Ruby sources."""
    ruby = [f for f in files if f.path.suffix == ".rb"]
    evidence: dict[RouteFamily, str] = {}
    for f in ruby:
        if RouteFamily.RAILS not in evidence and f.rel.endswith("config/routes.rb"):
            evidence[RouteFamily.RAILS] = f.rel
        if RouteFamily.SINATRA not in evidence and SINATRA_USE.search(f.text):
            evidence[RouteFamily.SINATRA] = f.rel
    if not evidence:
        return RubyRoutes([], {}, True)
    available = parser()
    if available is None:
        return RubyRoutes([], evidence, False)
    sources = {}
    for f in ruby:
        data = f.text.encode("utf-8")
        sources[f.rel] = _Source(f, available.parse(data).root_node, data)
    rows = _rails_rows(sources) if RouteFamily.RAILS in evidence else []
    for src in sources.values():
        if SINATRA_USE.search(src.file.text):
            rows += _sinatra_rows(src)
    return RubyRoutes(rows, evidence, True)
