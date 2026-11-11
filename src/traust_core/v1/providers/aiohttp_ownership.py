"""aiohttp ownership facts. The reader judges only (D35): a read of a record by the path id alone
is judged, and anything else reads unknown. It is the Flask reader's (same resolution, same
SQLAlchemy reads) with aiohttp's ids, caller and middleware, SQLAlchemy Core tables, literal SQL
and Motor (MongoDB) filters."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterator

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.flask_ownership import (
    _CLIENT,
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
from traust_core.v1.providers.route_ownership import Lookup
from traust_core.v1.providers.route_plumbing import _Modules, _Row, _Source

# the request's data a client chose (`request.match_info` holds the path ids, read as ids)
_AIO_CLIENT = _CLIENT | {"query", "post", "text", "read", "content", "rel_url", "multipart"}
# who the caller is: aiohttp-security, and a mapping key holding it (`request["user"]`,
# a session's `user_id`, aiohttp-jwt's payload)
_SECURITY = re.compile(r"^aiohttp_security(\.\w+)*\.(authorized_userid|check_authorized)$")
_CALLER_KEY = re.compile(
    r"(?i)^_?(current_?)?(user|me|account|identity|member|principal|owner|tenant|caller|uid|"
    r"sub|auth(_?user)?|login|payload|jwt|claims)(_?(id|obj|info|data))?$"
)
_SESSIONS = re.compile(r"^aiohttp_session(\.\w+)*\.get_session$")
# what a middleware may read of the route without reading its ids
_ROUTE_NAMES = {"route", "apps", "current_app", "http_exception", "expect_handler"}
# literal SQL: one statement whose WHERE is only AND-ed `column = placeholder` terms
_SQL = re.compile(
    r"(?is)^\s*(select\s.+?\sfrom|update|delete\s+from)\s+\"?(?P<table>\w+)\"?"
    r"(?P<rest>.*)$"
)
_SQL_WHERE = re.compile(r"(?is)\swhere\s(?P<where>.+?)(\s(order|group|limit|returning|for)\s.*)?$")
_SQL_TERM = re.compile(r"(?is)^\s*\"?(\w+)\"?\s*=\s*(\$\d+|%s|\?|:\w+|%\(\w+\)s)\s*$")
_SQL_CALLS = {"fetchrow", "fetch", "fetchval", "fetchone", "fetchall", "execute", "fetch_one"}
# Motor / PyMongo reads and writes taking a filter document
_MONGO_CALLS = {
    "find_one", "find", "find_one_and_update", "find_one_and_delete", "find_one_and_replace",
    "update_one", "update_many", "delete_one", "delete_many", "replace_one", "count_documents",
}  # fmt: skip
_TABLE_CALLS = {"select", "update", "delete"}  # `notes.select()`, Core's
# what runs a Core select, whatever the connection (aiopg, databases, an async engine)
_RUNNERS = {
    "execute", "fetchrow", "fetch", "fetchval", "scalar", "scalars", "fetchone", "fetch_one",
    "fetch_all",
}  # fmt: skip


def own_aiohttp(rows: list[_Row], sources: list[_Source], modules: _Modules) -> None:
    """Fill `ownership` on the aiohttp rows' authenticated id routes, judging only (D35)."""
    if any(r.family is RouteFamily.AIOHTTP for r in rows):
        own_routes(rows, RouteFamily.AIOHTTP, AiohttpOwnership(sources, modules))


class AiohttpOwnership(FlaskOwnership):
    """What an aiohttp handler does with the path ids and the caller."""

    def __init__(self, sources: list[_Source], modules: _Modules) -> None:
        super().__init__(sources, modules)
        # SQLAlchemy Core tables: `notes = sa.Table("notes", meta, sa.Column("owner_id", ..))`
        self.tables: dict[_Model, tuple[str, ...]] = {}
        for rel, tree in self.trees.items():
            for n in tree.body:
                value = _bound_value(n)
                if not (isinstance(value, ast.Call) and _last(_dotted(value.func)) == "Table"):
                    continue
                columns = tuple(
                    c
                    for a in value.args
                    if isinstance(a, ast.Call)
                    and _last(_dotted(a.func)) == "Column"
                    and (c := _const(a.args[0]) if a.args else None)
                )
                for target in n.targets if isinstance(n, ast.Assign) else [n.target]:  # type: ignore[union-attr]
                    if isinstance(target, ast.Name):
                        name = _const(value.args[0]) if value.args else None
                        self.tables[(rel, target.id)] = columns
                        self.records[(rel, target.id)] = name or target.id
                        self.fields[name or target.id] = columns
                        self.plain[(rel, target.id)] = True
        # checkout middleware reading the route's ids runs before every handler
        self.hooks += [(None, reads) for reads in self.middleware_reads()]

    def walk(self, rel: str, fn: _Def | None, path_ids: set[str], **kwargs: object) -> _Walk:
        return _AioWalk(self, rel, fn, path_ids, **kwargs)  # type: ignore[arg-type]

    def middleware_reads(self) -> Iterator[set[str] | None]:
        """The path ids each checkout middleware reads (`request.match_info["id"]`); None for
        any (the mapping whole, a computed key)."""
        for tree in self.trees.values():
            for n in ast.walk(tree):
                if not isinstance(n, _Def) or not (
                    any(_last(_dotted(d)) == "middleware" for d in n.decorator_list)
                    or "middleware" in n.name.lower()
                ):
                    continue
                parent = {id(c): p for p in ast.walk(n) for c in ast.iter_child_nodes(p)}
                keys: set[str] | None = set()
                for x in ast.walk(n):
                    if isinstance(x, ast.Attribute) and x.attr == "match_info":
                        above = parent.get(id(x))
                        if isinstance(above, ast.Attribute) and above.attr in _ROUTE_NAMES:
                            continue  # `match_info.route.name`: the route, not its ids
                        key = _key_of(x, parent)
                        keys = None if key is None or keys is None else keys | key
                if keys is None or keys:
                    yield keys

    def table(self, node: ast.AST, rel: str) -> _Model | None:
        """The checkout Core table a name in `rel` is (`notes`, `db.notes`)."""
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        dotted = _dotted(node)
        if (rel, dotted) in self.tables:
            return rel, dotted
        full = self.modules.full(dotted, rel)
        mod, _, name = full.rpartition(".")
        where = self.module_file(mod) if mod else None
        return (where, name) if where and (where, name) in self.tables else None


class _AioWalk(_Walk):
    """One aiohttp handler: ids from `request.match_info`, the request its parameter (or a class
    view's `self.request`)."""

    client = _AIO_CLIENT

    def __init__(self, o: AiohttpOwnership, rel: str, fn: _Def | None, path_ids: set[str], **kw):  # type: ignore[no-untyped-def]
        params = _params(fn, method=bool(kw.get("chain"))) if fn is not None else []
        self.requests = {"self.request", *params[:1]}
        self.session_maps: set[str] = set()  # `session = await get_session(request)`
        self.callers: set[str] = set()  # `user_id = await authorized_userid(request)`
        super().__init__(o, rel, fn, path_ids, **kw)  # type: ignore[arg-type]
        self.ao = o

    def alias(self, fn: _Def) -> None:
        super().alias(fn)
        sites: dict[str, list[ast.AST | None]] = defaultdict(list)
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                sites[n.id].append(self.parent.get(id(n)))
        for name, where in sites.items():
            value = _bound_value(where[0]) if len(where) == 1 else None
            value = value.value if isinstance(value, ast.Await) else value
            if isinstance(value, ast.Call) and _SESSIONS.match(self.full(value.func)):
                self.session_maps.add(name)
            elif value is not None and name not in self.ids and self.is_caller(value):
                self.callers.add(name)
            elif value is not None and _dotted(value) in self.requests and name not in self.ids:
                self.requests.add(name)  # `req = self.request`

    def is_request(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name | ast.Attribute) and _dotted(node) in self.requests

    def is_view_args(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "match_info"
            and self.is_request(node.value)
        )

    def is_caller(self, node: ast.AST) -> bool:
        """`await authorized_userid(request)`, `check_authorized(request)`, `request["user"]`,
        a session's `user_id`."""
        if isinstance(node, ast.Name) and node.id in getattr(self, "callers", ()):
            return True
        if isinstance(node, ast.Await):
            node = node.value
        if isinstance(node, ast.Call) and _SECURITY.match(self.full(node.func)):
            return True
        mapping, key = _mapping_key(node)
        keyed = key is not None and bool(_CALLER_KEY.match(key))
        if (
            keyed
            and mapping is not None
            and (self.is_request(mapping) or _dotted(mapping) in self.session_maps)
        ):
            return True
        return super().is_caller(node)

    # ---- reads beyond Flask's
    def read(self, call: ast.Call) -> Lookup | None:
        if id(call) in self.consumed:
            return None
        for alternative in (self.sql_read, self.mongo_read):
            found = alternative(call)
            if found is not False:
                return found  # type: ignore[return-value]
        return super().read(call)

    def target(self, call: ast.AST, depth: int = 0):  # type: ignore[no-untyped-def]
        found = super().target(call, depth)
        if found is not None or not isinstance(call, ast.Call):
            return found
        # `conn.execute(notes.select().where(..))`: the select names the table, whatever ran it
        if _last(_dotted(call.func)) in _RUNNERS and call.args:
            inner = self.select(call.args[0], depth + 1)
            if inner is not None:
                return inner[0], [call, *inner[1]], []
        return None

    def select(self, node: ast.AST, depth: int = 0):  # type: ignore[no-untyped-def]
        found = super().select(node, depth)
        if found is not None or depth > 8:
            return found
        links: list[ast.Call] = []
        cur = node
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr in _TABLE_CALLS:
                if cur.args:
                    break  # `sa.select([notes])`, read below
                table = self.ao.table(cur.func.value, self.rel)  # `notes.select()`
                return (table, [*links, cur]) if table else None
            if cur.func.attr not in {"where", "filter", "filter_by", "values", "returning",
                                     "order_by", "limit", "offset", "with_for_update"}:  # fmt: skip
                return None
            links.append(cur)
            cur = cur.func.value
        # `sa.select([notes])` (SQLAlchemy 1.x)
        if (
            isinstance(cur, ast.Call)
            and _last(_dotted(cur.func)) == "select"
            and len(cur.args) == 1
            and isinstance(cur.args[0], ast.List | ast.Tuple)
            and len(cur.args[0].elts) == 1
        ):
            table = self.ao.table(cur.args[0].elts[0], self.rel)
            return (table, [*links, cur]) if table else None
        return None

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

    def terms(self, links: list[ast.Call], model: _Model) -> list[ast.expr | None]:
        # Core's `update().values(..)` sets columns, it narrows nothing
        return super().terms([c for c in links if _last(_dotted(c.func)) != "values"], model)

    def sql_read(self, call: ast.Call) -> Lookup | bool | None:
        """`await conn.fetchrow("SELECT .. FROM notes WHERE id = $1", note_id)`: the table, and
        the values its WHERE binds. False when the call isn't one."""
        if _last(_dotted(call.func)) not in _SQL_CALLS or not call.args:
            return False
        sql = _const(call.args[0])
        if sql is None:
            return False
        statement = _SQL.match(sql)
        if statement is None:
            return False
        self.consume(call)
        if ";" in sql.strip().rstrip(";") or "--" in sql or "/*" in sql:
            self.mark(call)  # several statements or a comment: not read
            return None
        where = _SQL_WHERE.search(statement["rest"])
        values = [*call.args[1:]]
        if len(values) == 1 and isinstance(values[0], ast.Tuple | ast.List):
            values = list(values[0].elts)  # `execute(sql, (note_id,))`
        if where is None or re.search(r"(?i)\b(join|union|or|in|exists|select)\b", where["where"]):
            self.mark(call)
            return None
        terms = re.split(r"(?i)\s+and\s+", where["where"].strip())
        if not all(_SQL_TERM.match(t) for t in terms) or len(values) != len(terms):
            self.mark(call)  # a term we don't read, or bound by keyword
            return None
        return self.judge(call, statement["table"], [v for v in values])

    def mongo_read(self, call: ast.Call) -> Lookup | bool | None:
        """`await db.notes.find_one({"_id": ObjectId(note_id)})`: the collection, and the values
        its filter document binds. False when the call isn't one."""
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _MONGO_CALLS:
            return False
        if not call.args or not isinstance(call.args[0], ast.Dict):
            return False
        self.consume(call)
        filters = call.args[0]
        if any(k is None or _const(k) is None or _const(k).startswith("$") for k in filters.keys):  # type: ignore[union-attr]
            self.mark(call)  # `**more` or an operator (`$or`): not read
            return None
        values = [_unwrap_id(v) for v in filters.values]
        return self.judge(call, _last(_dotted(call.func.value)), values)

    def judge(self, call: ast.Call, record: str, values: list[ast.expr]) -> Lookup | None:
        span = self.span(call)
        if self.o.narrowed:
            self.mark(call)
            return None
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


def _unwrap_id(node: ast.expr) -> ast.expr:
    """`ObjectId(note_id)`, `uuid.UUID(..)`: the id it wraps."""
    if (
        isinstance(node, ast.Call)
        and _last(_dotted(node.func)) in ("ObjectId", "UUID", "int", "str")
        and len(node.args) == 1
        and not node.keywords
    ):
        return node.args[0]
    return node
