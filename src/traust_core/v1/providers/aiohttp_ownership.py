"""aiohttp ownership facts. The reader judges only (D35): a read of a record by the path id alone
is judged, and anything else reads unknown. It is the Flask reader's (same resolution, same
SQLAlchemy reads) with aiohttp's ids, caller and middleware, SQLAlchemy Core tables, literal SQL,
Motor (MongoDB) filters and Tortoise/Gino model reads."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterator

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.flask_ownership import (
    _CLIENT,
    _TEST_FILE,
    FlaskOwnership,
    _bound_value,
    _const,
    _Def,
    _dotted,
    _key_of,
    _last,
    _Model,
    _params,
    _Walk,
    own_routes,
)
from traust_core.v1.providers.route_ownership import HandlerFacts, Lookup
from traust_core.v1.providers.route_plumbing import _Modules, _Row, _Source

_Key = tuple[str, str]

# the request's data a client chose (`request.match_info` holds the path ids, read as ids)
_AIO_CLIENT = _CLIENT | {"query", "post", "text", "read", "content", "rel_url", "multipart"}
# who the caller is: aiohttp-security, and a mapping key holding it (`request["user"]`,
# a session's `user_id`, aiohttp-jwt's payload)
_SECURITY = re.compile(
    r"^aiohttp_security(\.\w+)*\."
    r"(authorized_userid|check_authorized|check_permission|permits|is_anonymous)$"
)
_CALLER_KEY = re.compile(
    r"(?i)^_?(current_?)?(user|me|account|identity|member|principal|owner|tenant|caller|uid|"
    r"sub|auth(_?user)?|login|payload|jwt|claims)(_?(id|obj|info|data))?$"
)
_SESSIONS = re.compile(r"^aiohttp_session(\.\w+)*\.get_session$")
# what a middleware may read of the route without reading its ids
_ROUTE_NAMES = {"route", "apps", "current_app", "http_exception", "expect_handler", "handler"}
_PATH_READS = {"path", "raw_path", "rel_url", "url", "path_qs"}
# decorators of aiohttp's ecosystem that act on nothing the handler reads
_AIO_DECORATORS = re.compile(
    r"^(template|docs|request_schema|response_schema|querystring_schema|match_info_schema|"
    r"headers_schema|json_schema|form_schema|cookies_schema|marshal_with|use_kwargs)$"
)
# literal SQL: one statement whose WHERE is only AND-ed `column = placeholder` terms
_SQL = re.compile(
    r"(?is)^\s*(?P<verb>select\s.+?\sfrom|update|delete\s+from)\s+"
    r"(?:\"?\w+\"?\.)?\"?(?P<table>\w+)\"?(?P<rest>.*)$"
)
_SQL_WHERE = re.compile(r"(?is)\swhere\s(?P<where>.+?)(\s(order|group|limit|returning|for)\s.*)?$")
_PLACEHOLDER = r"(\$(?P<num>\d+)|%s|\?|:(?P<name>\w+)|%\((?P<pyname>\w+)\)s)(::\w+)?"
_SQL_TERM = re.compile(rf"(?is)^\s*(\"?\w+\"?\.)?\"?(\w+)\"?\s*=\s*{_PLACEHOLDER}\s*$")
_POSITIONAL = re.compile(r"%s|\?")
# a statement setting the connection's session state (Postgres row-level security keys off it)
_SQL_SETS = re.compile(r"(?is)^\s*(set\s|reset\s|select\s+(pg_catalog\.)?set_config\s*\()")
_SQL_NARROWS = re.compile(r"(?i)\b(join|union|or|in|exists|with|intersect|except)\b|\(\s*select\b")
_SQL_CALLS = {
    "fetchrow", "fetch", "fetchval", "fetchone", "fetchall", "execute", "fetch_one", "fetch_all",
    "fetch_val",
}  # fmt: skip
# Motor / PyMongo reads and writes taking a filter document
_MONGO_CALLS = {
    "find_one", "find", "find_one_and_update", "find_one_and_delete", "find_one_and_replace",
    "update_one", "update_many", "delete_one", "delete_many", "replace_one", "count_documents",
}  # fmt: skip
_TABLE_CALLS = {"select", "update", "delete"}  # `notes.select()`, Core's
# what runs a Core select, whatever the connection (aiopg, databases, an async engine)
_RUNNERS = {
    "execute", "fetchrow", "fetch", "fetchval", "scalar", "scalars", "fetchone", "fetch_one",
    "fetch_all", "fetch_val", "iterate",
}  # fmt: skip
_CORE_LINKS = {
    "where", "filter", "filter_by", "values", "returning", "order_by", "limit", "offset",
    "with_for_update", "select_from",
}  # fmt: skip
# Tortoise and Gino model reads: `await Note.get(id=..)`, `Note.filter(id=..).first()`
_MODEL_READS = {"get", "get_or_none", "filter", "first", "all", "delete", "get_or_404"}
_ID_WRAPPERS = {"int", "str", "UUID", "uuid.UUID", "ObjectId", "bson.ObjectId"}


def own_aiohttp(rows: list[_Row], sources: list[_Source], modules: _Modules) -> None:
    """Fill `ownership` on the aiohttp rows' authenticated id routes, judging only (D35)."""
    if any(r.family is RouteFamily.AIOHTTP for r in rows):
        own_routes(rows, RouteFamily.AIOHTTP, AiohttpOwnership(sources, modules))


class AiohttpOwnership(FlaskOwnership):
    """What an aiohttp handler does with the path ids and the caller."""

    def __init__(self, sources: list[_Source], modules: _Modules) -> None:
        super().__init__(sources, modules)
        self.hooks = []  # Flask's hooks run before Flask views, never an aiohttp handler
        self.tables: dict[_Model, tuple[str, ...]] = {}
        self.strings: dict[_Key, str] = {}  # module-level SQL constants
        for rel, tree in self.trees.items():
            for n in tree.body:
                value = _bound_value(n)
                targets = n.targets if isinstance(n, ast.Assign) else [getattr(n, "target", None)]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if (text := _const(value)) is not None:
                    self.strings.update({(rel, name): text for name in names})
                if isinstance(value, ast.Call) and _last(_dotted(value.func)) == "Table":
                    self.add_table(rel, names, value)
        # an ORM model's table name: literal SQL on it reads the model's fields
        for (_, name), node in self.defs.items():
            if isinstance(node, ast.ClassDef) and name in self.fields:
                table = next(
                    (
                        _const(_bound_value(s))
                        for s in node.body
                        if "__tablename__" in {_dotted(t) for t in getattr(s, "targets", [])}
                    ),
                    None,
                )
                if table and table not in self.fields:
                    self.fields[table] = self.fields[name]
        for (rel, name), node in self.defs.items():
            meta = next(
                (
                    s
                    for s in getattr(node, "body", [])
                    if isinstance(s, ast.ClassDef) and s.name == "Meta"
                ),
                None,
            )
            if meta and any(
                "manager" in {_dotted(x) for x in getattr(s, "targets", [])} for s in meta.body
            ):
                self.plain[(rel, name)] = False  # a Tortoise manager of its own may narrow reads
        self.parents |= self.app_parents()
        installed = self.installed()
        self.apps = (
            {k for keys in installed.values() for k in keys}
            | set(self.parents)
            | {p for ps in self.parents.values() for p in ps}
        )
        for rel, tree in self.trees.items():  # `app = web.Application()`, with no middleware
            for n in ast.walk(tree):
                value = _bound_value(n)
                if isinstance(value, ast.Call) and _last(_dotted(value.func)) == "Application":
                    targets = getattr(n, "targets", [])
                    self.apps |= {self.receiver_key(_dotted(x), rel) for x in targets}
        self.hooks += list(self.middleware_hooks(installed))

    def add_table(self, rel: str, names: list[str], call: ast.Call) -> None:
        """`notes = sa.Table("notes", meta, sa.Column("owner_id", ..))`, a Core table."""
        columns = tuple(
            c
            for a in call.args
            if isinstance(a, ast.Call)
            and _last(_dotted(a.func)) == "Column"
            and a.args
            and (c := _const(a.args[0]))
        )
        table = (_const(call.args[0]) if call.args else None) or (names[0] if names else "")
        for name in names:
            self.tables[(rel, name)] = columns
            self.records[(rel, name)] = table
            self.fields[table] = columns
            self.plain[(rel, name)] = True

    def walk(self, rel: str, fn: _Def | None, path_ids: set[str], **kwargs: object) -> _Walk:
        return _AioWalk(self, rel, fn, path_ids, **kwargs)  # type: ignore[arg-type]

    def library_decorator(self, d: ast.AST, rel: str) -> bool:
        dotted = _dotted(d)
        if dotted in ("staticmethod", "classmethod"):
            return True
        if _AIO_DECORATORS.match(_last(dotted)) and (
            self.library(dotted, rel) or self.library_instance(dotted.partition(".")[0], rel)
        ):
            return True
        return super().library_decorator(d, rel)

    # ---- apps and middleware
    def app_parents(self) -> dict[_Key, set[_Key]]:
        """Each route table's and sub-app's parent app: `app.add_routes(routes)`,
        `app.add_subapp("/api", api)` (a parent's middlewares run on its sub-apps' routes)."""
        parents: dict[_Key, set[_Key]] = defaultdict(set)
        for rel, tree in self.trees.items():
            for n in ast.walk(tree):
                if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
                    continue
                child = None
                if n.func.attr == "add_routes" and n.args:
                    child = n.args[0]
                elif n.func.attr == "add_subapp" and len(n.args) > 1:
                    child = n.args[1]
                if isinstance(child, ast.Name | ast.Attribute):
                    app = _dotted(n.func.value).removesuffix(".router")
                    parents[self.receiver_key(_dotted(child), rel)].add(self.receiver_key(app, rel))
        return parents

    def covers(self, scope: _Key, row: _Row) -> bool:
        """A route we can't place under a known app (added in a `setup_routes(app)` helper) may
        run under any middleware: fail closed."""
        if super().covers(scope, row):
            return True
        return row.receiver is None or self.receiver_key(row.receiver, row.path) not in self.apps

    def plain_chain(self, chain: list[tuple[str, ast.ClassDef]], fn: _Def) -> bool:
        """aiohttp's `View` dispatches in `_iter`: a checkout override runs before the verb."""
        if any(isinstance(n, _Def) and n.name == "_iter" for _, c in chain for n in c.body):
            return False
        return super().plain_chain(chain, fn)

    def sees_caller(self, fn: ast.AST, rel: str) -> bool:
        """Checkout code reading the caller, its first parameter taken as the request."""
        walk = _AioWalk(self, rel, None, set())
        if isinstance(fn, _Def):
            params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args]]
            walk.requests |= {p for p in params if p not in ("self", "cls")}
        walk.parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
        return any(
            walk.is_caller(n)
            for n in ast.walk(fn)
            if not isinstance(getattr(n, "ctx", None), ast.Store)  # `request["user"] = ..` sets it
        )

    def middleware_hooks(
        self, installed: dict[_Key, list[_Key]]
    ) -> Iterator[tuple[_Key | None, set[str] | None]]:
        """(the app whose routes it runs before, None for any; the path ids it reads, None for
        any) of each checkout middleware reading the route: its `match_info`, or the path
        beside the caller, directly or in checkout code it calls."""
        for rel, tree in self.trees.items():
            if _TEST_FILE.search(rel):
                continue
            nested = [
                n
                for n in ast.walk(tree)
                if isinstance(n, _Def | ast.ClassDef) and n not in tree.body
            ]
            for n in [*tree.body, *nested]:
                apps = installed.get((rel, getattr(n, "name", "")), [])
                if n not in tree.body and not apps:
                    continue  # a factory's own middleware counts where the factory installs it
                if not self.is_middleware(n, apps):
                    continue
                reads = self.route_reads(n, rel, hop=True)
                if reads is None or reads:
                    for scope in apps or [None]:
                        yield scope, reads

    def installed(self) -> dict[_Key, list[_Key]]:
        """The apps each middleware is installed on: `web.Application(middlewares=[mw])`,
        `app.middlewares.append(mw)`."""
        out: dict[_Key, list[_Key]] = defaultdict(list)
        for rel, tree in self.trees.items():
            local = {n.name for n in ast.walk(tree) if isinstance(n, _Def | ast.ClassDef)}
            for n in ast.walk(tree):
                value = _bound_value(n)
                listed: list[ast.expr] = []
                apps: list[str] = []
                if isinstance(value, ast.Call) and _last(_dotted(value.func)) == "Application":
                    apps = [_dotted(t) for t in getattr(n, "targets", [])]
                    given = next((k.value for k in value.keywords if k.arg == "middlewares"), None)
                    listed = list(getattr(given, "elts", []))
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                    receiver = _dotted(n.func.value)
                    if receiver.endswith("middlewares") and n.func.attr in ("append", "insert"):
                        listed = n.args[-1:]  # `app.middlewares.append(mw)`, `.insert(0, mw)`
                    elif receiver.endswith("middlewares") and n.func.attr == "extend" and n.args:
                        listed = list(getattr(n.args[0], "elts", []))
                    apps = [receiver.removesuffix(".middlewares")] if listed else []
                keys = [self.receiver_key(a, rel) for a in apps]
                for m in listed:
                    if isinstance(m, ast.Attribute) and isinstance(m.value, ast.Call):
                        m = m.value.func  # `OwnerCheck(db).check`: a method of the class
                    if found := self.resolve(_dotted(m), rel):
                        out[(found[0], found[1].name)] += keys
                    elif isinstance(m, ast.Name) and m.id in local:
                        out[(rel, m.id)] += keys  # a middleware an app factory defines
        return out

    def is_middleware(self, n: ast.stmt, apps: list[_Key]) -> bool:
        """A middleware in any of its forms: `@web.middleware`, an old-style factory
        `(app, handler)`, a class with `__call__(request, handler)`, or code installed as one
        (uninstalled, the first three count for any app: what installs them may go unseen)."""
        if isinstance(n, _Def):
            params = [a.arg for a in n.args.args]
            return bool(
                any(_last(_dotted(d)) == "middleware" for d in n.decorator_list)
                or params[:2] == ["app", "handler"]
                or apps
            )  # a name alone (`log_middleware`) makes no middleware: an unused helper is none
        return isinstance(n, ast.ClassDef) and bool(
            apps
            or any(
                isinstance(m, _Def) and m.name == "__call__" and len(m.args.args) >= 3
                for m in n.body
            )
        )

    def route_reads(self, fn: ast.AST, rel: str, *, hop: bool) -> set[str] | None:
        """The path ids code reads of `match_info`; None for any (whole, a computed key, the path
        parsed beside the caller)."""
        parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
        keys: set[str] | None = set()
        path = False
        for x in ast.walk(fn):
            if isinstance(x, ast.Attribute) and x.attr == "match_info":
                above = parent.get(id(x))
                if isinstance(above, ast.Attribute) and above.attr in _ROUTE_NAMES:
                    continue  # `match_info.route.name`: the route, not its ids
                key = _key_of(x, parent)
                keys = None if key is None or keys is None else keys | key
            elif isinstance(x, ast.Attribute) and x.attr in _PATH_READS:
                path = path or not _only_compared(x, fn, parent)  # `path in PUBLIC` parses no id
            elif hop and isinstance(x, ast.Call) and (found := self.resolve(_dotted(x.func), rel)):
                inner = self.route_reads(found[1], found[0], hop=False)  # one hop (D2)
                keys = None if inner is None or keys is None else keys | inner
        if path and self.sees_caller(fn, rel):
            return None  # it parses the path and checks the caller itself
        return keys

    def table(self, node: ast.AST, rel: str) -> _Model | None:
        """The checkout Core table a name in `rel` is (`notes`, `models.notes`), or the table of
        a column of one (`notes.c.id`)."""
        while (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "c"
        ):
            node = node.value.value  # iterative: a long `.c.c..` chain nests deep
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        dotted = _dotted(node)
        if (rel, dotted) in self.tables:
            return rel, dotted
        full = self.modules.full(dotted, rel)
        mod, _, name = full.rpartition(".")
        where = self.module_file(mod) if mod else None
        return (where, name) if where and (where, name) in self.tables else None

    def sql(self, node: ast.AST | None, rel: str) -> str | None:
        """A literal SQL string, or the module constant holding one."""
        if (text := _const(node)) is not None:
            return text
        if isinstance(node, ast.Call) and _last(_dotted(node.func)) == "text" and node.args:
            return self.sql(node.args[0], rel)  # `sa.text("SELECT ..")`
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            found = self.resolve(node.value.id, rel)  # `Queries.GET_NOTE`
            cls = found[1] if found and isinstance(found[1], ast.ClassDef) else None
            for s in cls.body if cls else []:
                if node.attr in {_dotted(x) for x in getattr(s, "targets", [])}:
                    return _const(_bound_value(s))
            return None
        if not isinstance(node, ast.Name):
            return None
        if (rel, node.id) in self.strings:
            return self.strings[(rel, node.id)]
        mod, _, name = self.modules.full(node.id, rel).rpartition(".")
        where = self.module_file(mod) if mod else None
        return self.strings.get((where, name)) if where else None


class _AioWalk(_Walk):
    """One aiohttp handler: ids from `request.match_info`, the request its parameter (or a class
    view's `self.request`)."""

    client = _AIO_CLIENT

    def __init__(
        self,
        o: AiohttpOwnership,
        rel: str,
        fn: _Def | None,
        path_ids: set[str],
        *,
        chain: list[tuple[str, ast.ClassDef]] | None = None,
        bound_ids: set[str] | None = None,
        hop: bool = True,
    ) -> None:
        self.ao = o  # before the base walk's aliasing, which reads through it
        bound_method = fn is not None and fn.args.args and fn.args.args[0].arg in ("self", "cls")
        params = _params(fn, method=bool(chain) or bool(bound_method)) if fn else []
        self.requests = {"self.request", *params[:1]}
        self.session_maps: set[str] = set()  # `session = await get_session(request)`
        self.callers: set[str] = set()  # `user_id = await authorized_userid(request)`
        self.match_maps: set[str] = set()  # `mi = request.match_info`
        self.texts: dict[str, str] = {}  # `sql = "SELECT .."`
        self.docs: dict[str, ast.Dict] = {}  # `q = {"_id": ..}`
        self.rls: ast.AST | None = None  # SQL setting the connection's state (row-level security)
        super().__init__(o, rel, fn, path_ids, chain=chain, bound_ids=bound_ids, hop=hop)

    def alias(self, fn: _Def) -> None:
        sites: dict[str, list[ast.AST | None]] = defaultdict(list)
        for n in _scope(fn):  # a nested function's bindings are its own, never the handler's
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                sites[n.id].append(self.parent.get(id(n)))
        single = {name: where[0] for name, where in sites.items() if len(where) == 1}
        # the request and its match_info first: the base pass reads path ids through them
        for name, site in single.items():
            value = _bound_value(site)
            if value is not None and _dotted(value) in self.requests:
                self.requests.add(name)  # `request = self.request`, `req = request`
        for name, site in single.items():
            value = _bound_value(site)
            if value is not None and self.is_view_args(value):
                self.match_maps.add(name)  # `mi = request.match_info`
        super().alias(fn)
        for name, site in single.items():
            if isinstance(site, ast.withitem) and isinstance(site.context_expr, ast.Call):
                self.sessions.add(name)  # `async with pool.acquire() as conn`
                continue
            value = _bound_value(site)
            value = value.value if isinstance(value, ast.Await) else value
            if name in self.ids or name in self.requests or name in self.match_maps:
                continue
            if (text := _const(value)) is not None:
                if isinstance(value, ast.expr) and (_SQL.match(text) or _SQL_SETS.match(text)):
                    self.texts[name] = text
                    self.queries[name] = value
            elif isinstance(value, ast.Dict):
                self.docs[name] = value
                self.queries[name] = value  # read where it runs
            elif isinstance(value, ast.Call) and _SESSIONS.match(self.full(value.func)):
                self.session_maps.add(name)
            elif self.app_state(value) or (
                isinstance(value, ast.Call) and self.app_state(value.func)
            ):
                self.sessions.add(name)  # `s = request.app["Session"]()`, `request.app["db"]`
            elif value is not None and self.is_caller(value):
                self.callers.add(name)

    def app_state(self, node: ast.AST | None) -> bool:
        """`request.app["db"]`, `request.config_dict["Session"]`: what the app holds."""
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Attribute):
            return False
        return node.value.attr in ("app", "config_dict") and self.is_request(node.value.value)

    def facts(self) -> HandlerFacts:
        found = super().facts()
        if self.rls is not None:  # the database narrows the rows by what the handler set
            return HandlerFacts(handoff=self.span(self.rls), takes_id=True)
        return found

    def is_request(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name | ast.Attribute) and _dotted(node) in self.requests

    def is_view_args(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in getattr(self, "match_maps", ()):
            return True
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "match_info"
            and self.is_request(node.value)
        )

    def is_id(self, node: ast.AST | None) -> bool:
        """A path id, also wrapped (`ObjectId(note_id)`)."""
        if (
            isinstance(node, ast.Call)
            and _dotted(node.func) in _ID_WRAPPERS
            and len(node.args) == 1
            and not node.keywords
        ):
            return self.is_id(node.args[0])
        return super().is_id(node)

    def is_caller(self, node: ast.AST) -> bool:
        """`await authorized_userid(request)`, `check_permission(request, ..)`,
        `request["user"]`, a session's `user_id`, a name bound to one of these."""
        if isinstance(node, ast.Name) and node.id in getattr(self, "callers", ()):
            return True
        if isinstance(node, ast.Await):
            node = node.value
        if isinstance(node, ast.Call) and _SECURITY.match(self.full(node.func)):
            return True
        mapping, key = _mapping_key(node)
        keyed = key is not None and bool(_CALLER_KEY.match(key))
        inline = mapping.value if isinstance(mapping, ast.Await) else mapping
        session = isinstance(inline, ast.Call) and bool(_SESSIONS.match(self.full(inline.func)))
        if (
            keyed
            and mapping is not None
            and (
                self.is_request(mapping)
                or session  # `(await get_session(request)).get("user_id")`
                or _dotted(mapping) in getattr(self, "session_maps", ())
            )
        ):
            return True
        return super().is_caller(node)

    def session_like(self, func: ast.AST) -> bool:
        """Also a session or connection the handler opened (`async with app["db"]() as s`)."""
        receiver = func.value if isinstance(func, ast.Attribute) else None
        if isinstance(receiver, ast.Name) and receiver.id in self.sessions:
            return True
        return super().session_like(func)

    # ---- reads beyond Flask's
    def read(self, call: ast.Call) -> Lookup | None:
        if id(call) in self.consumed:
            return None
        if (seen := next((n for n in ast.walk(call) if self.is_caller(n)), None)) is not None:
            self.sees(seen)  # the caller set in a write the read consumes (`SET owner_id = $1`)
        for alternative in (self.sql_read, self.mongo_read):
            found = alternative(call)
            if found is None or isinstance(found, Lookup):
                return found
        return super().read(call)

    def target(
        self, call: ast.AST, depth: int = 0
    ) -> tuple[_Model, list[ast.Call], list[ast.expr]] | None:
        found = super().target(call, depth)
        if found is not None or not isinstance(call, ast.Call):
            return found
        # `conn.execute(notes.select().where(..))`, `fetch_one(query=..)`: the select names the
        # table, whatever ran it
        statement = (
            call.args[0]
            if call.args
            else next((k.value for k in call.keywords if k.arg == "query"), None)
        )
        if _last(_dotted(call.func)) in _RUNNERS and statement is not None:
            inner = self.select(statement, depth + 1)
            if inner is not None:
                return inner[0], [call, *inner[1]], []
        # Gino: `await Note.delete.where(Note.id == ..).gino.status()`
        gino = call.func.value if isinstance(call.func, ast.Attribute) else None
        if isinstance(gino, ast.Attribute) and gino.attr == "gino":
            links: list[ast.Call] = []
            cur: ast.AST = gino.value
            while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
                if cur.func.attr not in ("where", "values"):
                    return None
                links.append(cur)
                cur = cur.func.value
            if (
                links
                and isinstance(cur, ast.Attribute)
                and cur.attr in ("delete", "update", "query")
            ):
                model = self.model_of(cur.value)
                if model is not None and model not in self.ao.tables:
                    return model, links, []
            return None
        # Tortoise and Gino: `await Note.get(id=..)`, `Note.filter(id=..).first()`
        links = []
        cur = call
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr not in _MODEL_READS:
                return None
            links.append(cur)
            cur = cur.func.value
        model = self.model_of(cur) if links and isinstance(cur, ast.Name | ast.Attribute) else None
        if model is None or model in self.ao.tables:
            return None
        positional = [a for c in links if _last(_dotted(c.func)) == "get" for a in c.args]
        return model, links, positional

    def terms(self, links: list[ast.Call], model: _Model) -> list[ast.expr | None]:
        out: list[ast.expr | None] = []
        for c in links:
            name = _last(_dotted(c.func))
            if name == "values":
                continue  # Core's `update().values(..)` sets columns, it narrows nothing
            if name in ("get", "get_or_none", "filter") and (
                c.keywords or (c.args and name != "get")
            ):  # Tortoise: by keyword; a positional `Q(..)` we don't read
                out += [k.value if k.arg is not None else None for k in c.keywords]
                for a in c.args:  # `Q(owner_id=..)` and `Q(..) | Q(..)` read as unknown terms
                    if not (name == "get" and self.is_id(a)):
                        out += self.comparisons(a, model)
                continue
            out += super().terms([c], model)
        return out

    def select(self, node: ast.AST, depth: int = 0) -> tuple[_Model, list[ast.Call]] | None:
        found = super().select(node, depth)
        if found is not None or depth > 8:
            return found
        if isinstance(node, ast.Name) and node.id in self.queries:
            return self.select(self.queries[node.id], depth + 1)
        links: list[ast.Call] = []
        cur = node
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr in _TABLE_CALLS:
                if cur.args:
                    break  # `sa.select(notes.c.id, ..)`, read below
                table = self.ao.table(cur.func.value, self.rel)  # `notes.select()`
                return (table, [*links, cur]) if table else None
            if cur.func.attr not in _CORE_LINKS:
                return None
            links.append(cur)
            cur = cur.func.value
        if (
            isinstance(cur, ast.Call)
            and _last(_dotted(cur.func)) in ("update", "delete")
            and len(cur.args) == 1
            and not cur.keywords
            and self.ao.library(_dotted(cur.func), self.rel)
        ):  # `sa.update(notes)`, `sa.delete(Note)`
            model = self.model_of(cur.args[0])
            return (model, links) if model is not None else None  # the statement, not a term
        if not (isinstance(cur, ast.Call) and _last(_dotted(cur.func)) == "select" and cur.args):
            return None
        # `sa.select([notes])`, `sa.select(notes.c.id, notes.c.title)`: one table's columns
        items = cur.args[0].elts if isinstance(cur.args[0], ast.List | ast.Tuple) else cur.args
        tables = {self.ao.table(i, self.rel) for i in items}
        if len(tables) != 1 or None in tables:
            return None
        return next(iter(tables)), [*links, cur]

    def model_of(self, node: ast.AST, depth: int = 0) -> _Model | None:
        return super().model_of(node, depth) or self.ao.table(node, self.rel)

    def column(self, node: ast.AST, model: _Model) -> bool:
        """`Note.id`, and a Core table's `notes.c.id`."""
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "c"
        ):
            return self.ao.table(node.value.value, self.rel) == model
        return super().column(node, model)

    def sql_read(self, call: ast.Call) -> Lookup | bool | None:
        """`await conn.fetchrow("SELECT .. FROM notes WHERE id = $1", note_id)`: the table, and
        the values its WHERE binds. False when the call isn't one."""
        if _last(_dotted(call.func)) not in _SQL_CALLS or self.checkout(call.func):
            return False
        first = (
            call.args[0]
            if call.args
            else next((k.value for k in call.keywords if k.arg == "query"), None)
        )
        if isinstance(first, ast.JoinedStr):  # `f"SET LOCAL app.user_id = '{me}'"`
            head = "".join(v.value for v in first.values if isinstance(v, ast.Constant))
            if _SQL_SETS.match(head):
                self.consume(call)
                self.rls = self.rls or call
                return None
        if isinstance(first, ast.Name) and first.id in self.texts:
            sql: str | None = self.texts[first.id]
        else:
            sql = self.ao.sql(first, self.rel)
        if sql is not None and _SQL_SETS.match(sql):
            self.consume(call)
            self.rls = self.rls or call  # `SELECT set_config('app.user_id', ..)`, `SET LOCAL`
            return None
        sql = sql.strip().removesuffix(";").rstrip() if sql is not None else None
        statement = _SQL.match(sql) if sql is not None else None
        if sql is None or statement is None:
            return False
        self.consume(call)
        if ";" in sql or "--" in sql or "/*" in sql:
            self.mark(call)  # several statements or a comment: not read
            return None
        where = _SQL_WHERE.search(statement["rest"])
        if where is None or _SQL_NARROWS.search(statement["rest"]):
            self.mark(call)  # no WHERE, or a join, subquery or OR that may narrow it
            return None
        terms = [_SQL_TERM.match(t) for t in re.split(r"(?i)\s+and\s+", where["where"].strip())]
        values = self.bound(call, first, sql, statement.start("rest") + where.start("where"))
        if any(t is None for t in terms) or values is None:
            self.mark(call)  # a term we don't read, or values we can't place
            return None
        bound: list[ast.expr] = []
        for term in terms:
            assert term is not None
            value = values.get(term["num"] or term["name"] or term["pyname"])
            if value is None:
                self.mark(call)
                return None
            bound.append(value)
        return self.judge(call, statement["table"], bound)

    def bound(
        self, call: ast.Call, first: ast.AST | None, sql: str, where_at: int
    ) -> dict[str | None, ast.expr] | None:
        """The value each WHERE placeholder takes: `$2` by number, `:id` by name (`values=`), or
        a `%s`/`?` by position after the ones the SET clause takes. None when not told."""
        args = [a for a in call.args if a is not first]
        named = next((k.value for k in call.keywords if k.arg in ("values", "parameters")), None)
        if len(args) == 1 and isinstance(args[0], ast.Tuple | ast.List):
            args = list(args[0].elts)  # `execute(sql, (note_id,))`
        if len(args) == 1 and isinstance(args[0], ast.Dict):
            named, args = args[0], []
        out: dict[str | None, ast.expr] = {}
        if isinstance(named, ast.Dict):
            for k, v in zip(named.keys, named.values, strict=True):
                if _const(k) is None:
                    return None
                out[_const(k)] = v
        for i, a in enumerate(args, start=1):
            out[str(i)] = a  # `$1`
        positional = list(_POSITIONAL.finditer(sql))
        after = [m for m in positional if m.start() >= where_at]
        if after:
            before = len(positional) - len(after)
            if len(after) != 1 or len(args) != len(positional):
                return None  # more than one positional WHERE term: which value is which
            out[None] = args[before]
        return out

    def mongo_read(self, call: ast.Call) -> Lookup | bool | None:
        """`await db.notes.find_one({"_id": ObjectId(note_id)})`: the collection, and the values
        its filter document binds. False when the call isn't one."""
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _MONGO_CALLS:
            return False
        if self.checkout(call.func):
            return False
        filters = (
            call.args[0]
            if call.args
            else next((k.value for k in call.keywords if k.arg == "filter"), None)
        )
        if isinstance(filters, ast.Name) and filters.id in self.docs:
            filters = self.docs[filters.id]  # `q = {"_id": ..}; find_one(q)`
        if not isinstance(filters, ast.Dict):
            return False
        self.consume(call)
        if any(k is None or (_const(k) or "$").startswith("$") for k in filters.keys):
            self.mark(call)  # `**more` or an operator (`$or`): not read
            return None
        return self.judge(call, _collection(call.func.value), list(filters.values))

    def checkout(self, func: ast.AST) -> bool:
        """A function this repository defines (`from . import db; db.fetchrow(..)`), not a
        driver's: what it runs isn't read."""
        return isinstance(func, ast.Name | ast.Attribute) and bool(
            self.o.resolve(_dotted(func), self.rel)
        )

    def judge(self, call: ast.Call, record: str, values: list[ast.expr]) -> Lookup | None:
        """A literal-SQL or Mongo read: judged when it binds the path id and only literals. The
        session criteria and query classes that narrow SQLAlchemy reads don't reach it."""
        span = self.span(call)
        tied = any(self.mentions_caller(v) for v in values)
        if not any(self.names_id(v) for v in values):
            if tied:
                self.mark(call)
            return None
        if tied:
            return Lookup(span, scoped=True, record_type=record)  # never credited (D35)
        if not all(self.is_id(v) or isinstance(v, ast.Constant) for v in values):
            self.mark(call)  # narrowed by something else too: to what isn't told
            return None
        return Lookup(span, record_type=record)


def _scope(fn: _Def) -> Iterator[ast.AST]:
    """The nodes of a function's own scope: a nested function, class or lambda binds its own
    names (an inner `req = None` leaves the handler's `req` alone)."""
    stack: list[ast.AST] = list(reversed(fn.body))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, _Def | ast.ClassDef | ast.Lambda):
            stack.extend(reversed(list(ast.iter_child_nodes(n))))


def _collection(node: ast.AST) -> str:
    """A Motor/PyMongo collection's name: `db.notes`, `db["notes"]`, `db.get_collection(..)`."""
    if isinstance(node, ast.Subscript):
        return _const(node.slice) or ""
    if isinstance(node, ast.Call) and _last(_dotted(node.func)) == "get_collection" and node.args:
        return _const(node.args[0]) or ""
    return _last(_dotted(node))


def _only_compared(x: ast.AST, fn: ast.AST, parent: dict[int, ast.AST]) -> bool:
    """The path only compared with fixed values (`request.path in PUBLIC`, `.startswith("/s")`),
    directly or through a name bound to it once (`path = request.path`). A comparison with
    anything the middleware computes (`f"/users/{uid}/"`, a call, a local) may tie the path to
    the caller: it is a read."""
    bound = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    if isinstance(fn, _Def):
        bound |= {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}

    def fixed(operand: ast.AST) -> bool:
        """Literals and module-level names only (`PUBLIC`, `config.OPEN_PATHS`, `("/a", "/b")`)."""
        for n in ast.walk(operand):
            if isinstance(n, ast.Name) and n.id in bound:
                return False
            if not isinstance(
                n,
                ast.Constant
                | ast.Name
                | ast.Attribute
                | ast.Tuple
                | ast.List
                | ast.Set
                | ast.expr_context,
            ):
                return False
        return True

    def compared(n: ast.AST) -> bool:
        above = parent.get(id(n))
        if isinstance(above, ast.Compare):
            return all(fixed(o) for o in [above.left, *above.comparators] if o is not n)
        call = parent.get(id(above)) if isinstance(above, ast.Attribute) else None
        return (
            isinstance(above, ast.Attribute)
            and above.attr in ("startswith", "endswith")
            and isinstance(call, ast.Call)
            and call.func is above
            and not call.keywords
            and all(fixed(a) for a in call.args)
        )

    if compared(x):
        return True
    site = parent.get(id(x))
    targets = site.targets if isinstance(site, ast.Assign) and site.value is x else []
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return False
    name = targets[0].id
    uses = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == name]
    stores = [n for n in uses if isinstance(n.ctx, ast.Store)]
    loads = [n for n in uses if isinstance(n.ctx, ast.Load)]
    return len(stores) == 1 and all(compared(n) for n in loads)


def _mapping_key(node: ast.AST) -> tuple[ast.AST | None, str | None]:
    """(the mapping, the constant key) of `m["k"]` or `m.get("k")`."""
    if isinstance(node, ast.Subscript):
        return node.value, _const(node.slice)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        return node.func.value, _const(node.args[0])
    return None, None
