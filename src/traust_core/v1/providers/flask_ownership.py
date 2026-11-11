"""Flask ownership facts. The reader judges only (D35): a read of a model's rows by the path id
alone is judged, and anything else reads unknown."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterator

from traust_core.v1.models.code_facts import RouteFamily, RouteOwnership
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import HandlerFacts, Lookup, path_params
from traust_core.v1.providers.route_plumbing import _Modules, _Row, _Source

_Def = ast.FunctionDef | ast.AsyncFunctionDef
_Found = tuple[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef]

# a query's reads and deletes; anything else (`join`, `update`, `union`) is unread
_FILTERS = {
    "get", "get_or_404", "first", "first_or_404", "one", "one_or_none", "one_or_404", "all",
    "filter", "filter_by", "where", "delete", "count", "scalar", "scalar_one",
    "scalar_one_or_none", "scalars",
}  # fmt: skip
# methods that shape the rows a query returns, never which rows
_SHAPES = {
    "options", "order_by", "limit", "offset", "with_for_update", "execution_options", "distinct",
    "populate_existing", "enable_eagerloads", "unique",
}  # fmt: skip
# what an `options(..)`/`order_by(..)` argument may call: loaders and orderings, on the model
_SHAPING_CALLS = {
    "joinedload", "selectinload", "subqueryload", "lazyload", "noload", "raiseload",
    "load_only", "defer", "undefer", "contains_eager", "desc", "asc", "nulls_last",
    "nulls_first",
}  # fmt: skip
# `db.session.execute(select(..))` and the Flask-SQLAlchemy helpers taking a select
_EXECUTORS = {"execute", "scalars", "scalar", "first_or_404", "one_or_404"}
_ID_CASTS = {"int", "str", "UUID", "uuid.UUID"}
_RESPONSES = {
    "jsonify", "render_template", "abort", "redirect", "url_for", "make_response", "flash",
    "Response", "str", "int", "dict", "list", "len",
}  # fmt: skip
# request data a client chose
_CLIENT = {
    "args", "form", "json", "values", "data", "files", "headers", "cookies", "get_json",
    "get_data", "environ",
}  # fmt: skip
# who the caller is: flask-login and its kin, flask-jwt-extended, flask-httpauth, `g`, `session`
_CALLER_NAMES = {"current_user", "current_identity"}
_CALLER_CALLS = {"get_jwt_identity", "get_jwt", "get_current_user", "current_user", "username"}
# library decorators that act on nothing the view reads; the route registration itself
_LIBRARY_DECORATORS = re.compile(
    r"^(login_required|fresh_login_required|roles_required|roles_accepted|"
    r"permission_required|auth_required|jwt_required|token_required|cached|memoize|limit|"
    r"exempt|doc|response|input|output|marshal_with|marshal|expect|use_kwargs|use_args|"
    r"arguments|paginate|"
    r"route|get|post|put|patch|delete|head|options|cross_origin|csrf_exempt)$"
)
# hooks that run before a view and see the route's values (its path ids)
_ROUTE_HOOKS = {"url_value_preprocessor", "url_defaults", "app_url_value_preprocessor"}
_BEFORE_HOOKS = {"before_request", "before_app_request"}
# what narrows every query a session runs: a global criteria or a custom query class
_GLOBAL_NARROWING = re.compile(r"\bwith_loader_criteria\b|do_orm_execute|\bquery_cls\s*=")
_MAX_DEPTH = 8
_CREDITS = {RouteOwnership.SCOPED, RouteOwnership.CHECKED, RouteOwnership.NONE}


def own_flask(rows: list[_Row], sources: list[_Source], modules: _Modules) -> None:
    """Fill `ownership` on the Flask rows' authenticated id routes, judging only (D35)."""
    flask = [r for r in rows if r.family is RouteFamily.FLASK]
    if not flask:
        return
    reader = FlaskOwnership(sources, modules)
    for row in flask:
        if row.options_exempt:
            continue  # Flask answers OPTIONS itself, never running the view
        if not (path_params(row.pattern) or row.dynamic):
            continue
        row.own(reader.facts(row), reader.fields)
        credited = row.ownership in _CREDITS or (
            row.ownership is RouteOwnership.NOT_APPLICABLE
            and row.guarded
            and not row.unguards
            and path_params(row.pattern)
        )
        if credited:
            row.ownership, row.ownership_evidence = RouteOwnership.UNKNOWN, None


class FlaskOwnership:
    """What a Flask view does with the path ids and the caller."""

    def __init__(self, sources: list[_Source], modules: _Modules) -> None:
        self.modules = modules
        self.trees = {s.file.rel: s.tree for s in sources}
        self.defs: dict[tuple[str, str], ast.ClassDef | _Def] = {}
        self.bound: dict[str, set[str]] = defaultdict(set)  # each file's module-level names
        for rel, tree in self.trees.items():
            for n in tree.body:
                if isinstance(n, ast.ClassDef | _Def):
                    self.defs[(rel, n.name)] = n
                self.bound[rel] |= _binds(n)
        texts = [s.file.text for s in sources]
        # a session criteria or query class of the checkout's may narrow every read
        self.narrowed = any(_GLOBAL_NARROWING.search(t) for t in texts) or any(
            self.narrows(rel, n)
            for rel, tree in self.trees.items()
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and _last(_dotted(n.func)) == "SQLAlchemy"
        )
        # a hook that sees the route's values runs before every view
        self.route_hooks = any(
            isinstance(n, _Def)
            and any(
                _last(_dotted(d)) in _ROUTE_HOOKS
                or (_last(_dotted(d)) in _BEFORE_HOOKS and _reads_view_args(n))
                for d in n.decorator_list
            )
            for tree in self.trees.values()
            for n in ast.walk(tree)
        ) or any(
            isinstance(n, ast.Call) and _last(_dotted(n.func)) in _ROUTE_HOOKS
            for tree in self.trees.values()
            for n in ast.walk(tree)
        )
        self.fields: dict[str, tuple[str, ...]] = {}
        self.plain: dict[str, bool] = {}
        for (rel, name), node in self.defs.items():
            if isinstance(node, ast.ClassDef):
                fields, plain = self.model(rel, node, 0)
                self.fields.setdefault(name, fields)
                # two classes of one name: neither is told apart
                self.plain[name] = plain and name not in self.plain

    def narrows(self, rel: str, call: ast.Call) -> bool:
        """`SQLAlchemy(query_class=..)`, a `model_class` with a query of its own, or a
        `query_cls` session option: every `Model.query` may be narrowed."""
        for k in call.keywords:
            if k.arg is None or k.arg == "query_class":
                return True
            if k.arg == "model_class":
                found = self.resolve(_dotted(k.value), rel)
                if found is None or not isinstance(found[1], ast.ClassDef):
                    return True
                if not self.model(found[0], found[1], 0)[1]:
                    return True
            if k.arg == "session_options":
                keys = k.value.keys if isinstance(k.value, ast.Dict) else None
                if keys is None or any(x is None or _const(x) == "query_cls" for x in keys):
                    return True
        return False

    def model(self, rel: str, cls: ast.ClassDef, depth: int) -> tuple[tuple[str, ...], bool]:
        """A class's fields, its checkout bases' included, and whether `Model.query` is
        Flask-SQLAlchemy's own (no `query_class` or query property of the checkout's)."""
        fields: list[str] = []
        plain = True
        for b in cls.bases:
            found = self.resolve(_dotted(b), rel) if depth < _MAX_DEPTH else None
            if found is not None and isinstance(found[1], ast.ClassDef):
                inherited, base_plain = self.model(found[0], found[1], depth + 1)
                fields += inherited
                plain = plain and base_plain
        for n in cls.body:
            for target in _targets(n):
                name = _dotted(target)
                if name in ("query_class", "query", "__mapper_args__"):
                    plain = False
                elif name and not name.startswith("__"):
                    fields.append(name)
        return tuple(fields), plain

    def resolve(self, dotted: str, rel: str, depth: int = 0) -> _Found | None:
        """The checkout class or function a name in `rel` is, through imports and re-exports."""
        head, _, rest = dotted.partition(".")
        if not rest and (rel, head) in self.defs:
            return rel, self.defs[(rel, head)]
        full = self.modules.full(dotted, rel)
        mod, _, name = full.rpartition(".")
        where = self.modules.file(mod) if mod else None
        if where is None:
            return None
        if (where, name) in self.defs:
            return where, self.defs[(where, name)]
        return self.resolve(name, where, depth + 1) if depth < _MAX_DEPTH else None

    def library(self, dotted: str, rel: str) -> bool:
        """A name `rel` imports from a library, not from the checkout or its own definition."""
        full = self.modules.full(dotted, rel)
        return bool(full) and not self.modules.local(full)

    def library_decorator(self, d: ast.AST, rel: str) -> bool:
        """A library decorator acting on nothing the view reads, or a route registration;
        attribute forms (`auth.login_required`, `cache.cached`) on an instance of a library
        class bound at module level."""
        dotted = _dotted(d)
        if not _LIBRARY_DECORATORS.match(_last(dotted)):
            return False
        if "." in dotted and self.library_instance(dotted.partition(".")[0], rel):
            return True
        return self.library(dotted, rel)

    def library_instance(self, name: str, rel: str, depth: int = 0) -> bool:
        """`auth = HTTPBasicAuth()`, `bp = Blueprint(..)`, `db = SQLAlchemy()`: a name bound
        once at module level to an instance of a library class, here or in the checkout module
        it is imported from."""
        full = self.modules.full(name, rel)
        if full:
            mod, _, attr = full.rpartition(".")
            where = self.modules.file(mod) if mod else None
            if where is None or depth >= _MAX_DEPTH:
                return False
            return self.library_instance(attr, where, depth + 1)
        return name in self.bound.get(rel, set()) and self.instance_of_library(name, rel)

    def instance_of_library(self, name: str, rel: str) -> bool:
        sites = [
            n.value
            for n in self.trees[rel].body
            if isinstance(n, ast.Assign | ast.AnnAssign)
            and name in {_dotted(t) for t in _targets(n)}
        ]
        return (
            len(sites) == 1
            and isinstance(sites[0], ast.Call)
            and self.library(_dotted(sites[0].func), rel)
        )

    # ---- views
    def facts(self, row: _Row) -> HandlerFacts:
        span = CodeSpan(path=RepoPath(row.handler_path), line=row.handler_line)
        unread = HandlerFacts(handoff=span, takes_id=True)
        if self.route_hooks:
            return unread
        rel = row.handler_path
        fn = self.handler(rel, row.handler_line)
        if fn is None:
            return unread
        cls: ast.ClassDef | None = None
        if row.view_class is not None:
            found = self.defs.get((rel, row.view_class.rsplit(".", 1)[-1]))
            cls = found if isinstance(found, ast.ClassDef) else None
            if cls is None or not self.plain_class(rel, cls):
                return unread
        ids = set(path_params(row.pattern))
        walk = _Walk(self, rel, fn, ids, cls=cls)
        return walk.facts()

    def handler(self, rel: str, line: int) -> _Def | None:
        tree = self.trees.get(rel)
        if tree is None:
            return None
        return next((n for n in ast.walk(tree) if isinstance(n, _Def) and n.lineno == line), None)

    def plain_class(self, rel: str, cls: ast.ClassDef) -> bool:
        """A class view whose own code runs only in its verb methods: no `dispatch_request` of
        its own, and every class-level decorator (`decorators`, `method_decorators`) a
        library's."""
        if any(isinstance(n, _Def) and n.name == "dispatch_request" for n in cls.body):
            return False
        if not all(self.library_decorator(d, rel) for d in cls.decorator_list):
            return False
        for n in cls.body:
            if any(_dotted(t) in ("decorators", "method_decorators") for t in _targets(n)):
                value = n.value if isinstance(n, ast.Assign | ast.AnnAssign) else None
                items = value.elts if isinstance(value, ast.List | ast.Tuple) else None
                if items is None or not all(self.library_decorator(d, rel) for d in items):
                    return False
        return True


class _Walk:
    """One view's body: the reads it makes by the path ids, and whether it sees the caller."""

    def __init__(
        self,
        o: FlaskOwnership,
        rel: str,
        fn: _Def,
        path_ids: set[str],
        *,
        cls: ast.ClassDef | None = None,
        bound_ids: set[str] | None = None,
        hop: bool = True,
    ) -> None:
        self.o, self.rel, self.fn, self.cls, self.hop = o, rel, fn, cls, hop
        params = _params(fn, method=cls is not None)
        self.path_ids = set(path_ids)
        self.ids = (set(path_ids) if bound_ids is None else set(bound_ids)) & set(params)
        self.bags = {a.arg for a in (fn.args.vararg, fn.args.kwarg) if a}
        self.parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
        self.lookups: list[Lookup] = []
        self.caller: CodeSpan | None = None
        self.impure: ast.AST | None = None
        self.consumed: set[int] = set()
        self.alias()

    def span(self, node: ast.AST) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.rel), line=getattr(node, "lineno", self.fn.lineno))

    def alias(self) -> None:
        """`note_id = int(note_id)`: a name bound once, to a path id, is one."""
        sites: dict[str, list[ast.AST | None]] = defaultdict(list)
        for n in _own(self.fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                sites[n.id].append(self.parent.get(id(n)))
        for name, where in sites.items():
            value = _bound_value(where[0]) if len(where) == 1 else None
            if value is not None and self.is_id(value):
                self.ids.add(name)
            elif name in self.ids:
                self.ids.discard(name)  # the parameter rebound: no longer the path id

    def facts(self) -> HandlerFacts:
        if not all(self.o.library_decorator(d, self.rel) for d in self.fn.decorator_list):
            return HandlerFacts(handoff=self.span(self.fn), takes_id=True)  # runs first
        for n in _own(self.fn):
            self.node(n)
        exposed = [x for x in self.lookups if not x.scoped]
        if not exposed and self.impure is not None:
            return HandlerFacts(handoff=self.span(self.impure), takes_id=True)
        return HandlerFacts(
            lookups=tuple(self.lookups),
            caller=self.caller,
            takes_id=True,
            ignores_id=not (self.ids or self.bags),
        )

    def mark(self, node: ast.AST) -> None:
        self.impure = self.impure or node

    def consume(self, node: ast.AST) -> None:
        self.consumed |= {id(x) for x in ast.walk(node)}

    def sees(self, node: ast.AST) -> None:
        self.caller = self.caller or self.span(node)

    def node(self, n: ast.AST) -> None:
        if id(n) in self.consumed:
            return
        parent = self.parent.get(id(n))
        if not isinstance(n, ast.Name) and self.is_id(n):
            self.consume(n)
            if _bound_value(parent) is not n:
                self.mark(n)  # the id reaches something other than a read
            return
        if self.is_caller(n):
            self.sees(n)
            self.consume(n)
            return
        if isinstance(n, ast.Call):
            self.call(n)
        elif isinstance(n, ast.Attribute) and self.is_request(n.value) and n.attr in _CLIENT:
            self.mark(n)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.ids:
            if _bound_value(parent) is not n:
                self.mark(n)  # the id reaches something other than the read
        elif (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.bags) or (
            isinstance(n, ast.Subscript | ast.Lambda | ast.Yield | ast.YieldFrom)
        ):
            self.mark(n)

    def call(self, call: ast.Call) -> None:
        if (lookup := self.read(call)) is not None:
            self.lookups.append(lookup)
            return
        if id(call) in self.consumed:
            return
        dotted = _dotted(call.func)
        if dotted.startswith("self.") and self.cls is not None and dotted.count(".") == 1:
            self.consume(call)
            self.take(call, self.follow(call, dotted.removeprefix("self.")))
            return
        found = self.o.resolve(dotted, self.rel) if dotted else None
        if found is not None:
            self.sees(call)  # checkout code may read the caller itself
            self.mark(call)
            return
        if dotted in _RESPONSES or (
            _last(dotted) in _RESPONSES and self.o.library(dotted, self.rel)
        ):
            return
        self.mark(call)

    def take(self, call: ast.Call, facts: HandlerFacts | None) -> None:
        if facts is None or facts.handoff is not None or not facts.lookups:
            self.mark(call)
            return
        self.lookups.extend(facts.lookups)
        self.caller = self.caller or facts.caller

    def follow(self, call: ast.Call, method: str) -> HandlerFacts | None:
        """One hop into a method of the view's class (D2), with the ids it is handed."""
        assert self.cls is not None
        fn = next((n for n in self.cls.body if isinstance(n, _Def) and n.name == method), None)
        if fn is None or not self.hop or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        params = _params(fn, method=True)
        if any(k.arg is None for k in call.keywords) or len(call.args) > len(params):
            return None
        handed = [*zip(params, call.args, strict=False)]
        handed += [(k.arg, k.value) for k in call.keywords if k.arg is not None]
        walk = _Walk(
            self.o,
            self.rel,
            fn,
            self.path_ids,
            cls=self.cls,
            bound_ids={p for p, a in handed if self.is_id(a)},
            hop=False,
        )
        return walk.facts()

    # ---- reads
    def read(self, call: ast.Call) -> Lookup | None:
        """A read of one model's rows by the path id: `Note.query.get_or_404(id)`,
        `db.session.get(Note, id)`, `db.session.query(Note).filter_by(id=id).first()`,
        `db.session.execute(select(Note).where(Note.id == id)).scalar_one()`; scoped when it
        also names the caller."""
        if id(call) in self.consumed:
            return None
        found = self.target(call)
        if found is None:
            return None
        model, links, positional = found
        self.consume(call)
        span = self.span(call)
        if self.o.narrowed or not self.o.plain.get(model, False):
            self.mark(call)  # a query class or session criteria that may narrow the rows
            return None
        shaping = [
            a
            for c in links
            if _last(_dotted(c.func)) in _SHAPES
            for a in [*c.args, *(k.value for k in c.keywords)]
        ]
        if any(self.mentions_caller(a) for a in shaping) or not all(
            self.shaping_only(a, model) for a in shaping
        ):
            self.mark(call)
            return None
        terms = [*positional, *self.terms(links, model)]
        if any(t is None for t in terms):
            self.mark(call)  # narrowed by something whose meaning we don't read
            return None
        values = [t for t in terms if t is not None]
        tied = any(self.mentions_caller(v) for v in values)
        if not any(self.names_id(v) for v in values):
            if tied:
                self.mark(call)  # the caller's rows, read by no path id
            return None
        if tied:
            return Lookup(span, scoped=True, record_type=model)  # never credited (D35)
        if not all(self.is_id(v) or isinstance(v, ast.Constant) for v in values):
            self.mark(call)  # narrowed by something else too: to what isn't told
            return None
        return Lookup(span, record_type=model)

    def target(self, call: ast.Call) -> tuple[str, list[ast.Call], list[ast.expr]] | None:
        """(model, the query's calls, positional id arguments) of a read, or None."""
        dotted = _dotted(call.func)
        last = _last(dotted)
        # `db.session.get(Note, id)`, `db.get_or_404(Note, id)`
        if last in ("get", "get_or_404") and len(call.args) == 2:
            model = self.model_of(call.args[0])
            if model is not None and self.session_like(call.func):
                return model, [call], [call.args[1]]
        # `db.session.execute(select(Note)..)`, `db.first_or_404(select(..))`
        if last in _EXECUTORS and call.args and self.session_like(call.func):
            inner = self.select(call.args[0])
            if inner is not None:
                return inner[0], [call, *inner[1]], []
        links: list[ast.Call] = []
        cur: ast.AST = call
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr not in _FILTERS | _SHAPES:
                if cur.func.attr == "query" and len(cur.args) == 1 and not links:
                    return None
                break
            links.append(cur)
            cur = cur.func.value
        if not links:
            return None
        # `Note.query.<links>`
        if isinstance(cur, ast.Attribute) and cur.attr == "query":
            model = self.model_of(cur.value)
            positional = [
                a for c in links if _last(_dotted(c.func)) in ("get", "get_or_404") for a in c.args
            ]
            return (model, links, positional) if model is not None else None
        # `db.session.query(Note).<links>`
        if (
            isinstance(cur, ast.Call)
            and _last(_dotted(cur.func)) == "query"
            and len(cur.args) == 1
            and self.session_like(cur.func)
        ):
            model = self.model_of(cur.args[0])
            positional = [
                a for c in links if _last(_dotted(c.func)) in ("get", "get_or_404") for a in c.args
            ]
            return (model, [*links, cur], positional) if model is not None else None
        # `select(Note).where(..)` reached through a chain: read by its executor
        return None

    def select(self, node: ast.AST) -> tuple[str, list[ast.Call]] | None:
        links: list[ast.Call] = []
        cur = node
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr not in _FILTERS | _SHAPES:
                return None
            links.append(cur)
            cur = cur.func.value
        if (
            isinstance(cur, ast.Call)
            and _last(_dotted(cur.func)) == "select"
            and len(cur.args) == 1
            and self.o.library(_dotted(cur.func), self.rel)
        ):
            model = self.model_of(cur.args[0])
            return (model, [*links, cur]) if model is not None else None
        return None

    def session_like(self, func: ast.AST) -> bool:
        """`db.session.<m>`, `db.<m>`, `session.<m>`: a Flask-SQLAlchemy or SQLAlchemy object
        the module binds to a library instance, never checkout code we'd have to read."""
        receiver = func.value if isinstance(func, ast.Attribute) else None
        dotted = _dotted(receiver)
        if not dotted or dotted.partition(".")[2] not in ("", "session"):
            return False
        head = dotted.partition(".")[0]
        return self.o.library_instance(head, self.rel) or self.o.library(head, self.rel)

    def model_of(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        found = self.o.resolve(_dotted(node), self.rel)
        return found[1].name if found is not None and isinstance(found[1], ast.ClassDef) else None

    def terms(self, links: list[ast.Call], model: str) -> list[ast.expr | None]:
        """The values a query's filters compare its columns with; None for a filter we don't
        read (a function of a column, an `or_`, a join)."""
        out: list[ast.expr | None] = []
        for c in links:
            name = _last(_dotted(c.func))
            if name == "filter_by":
                out += [k.value if k.arg is not None else None for k in c.keywords]
                out += [None for _ in c.args]
            elif name in ("filter", "where"):
                for a in c.args:
                    out += self.comparisons(a, model)
            elif name in _FILTERS and name not in ("get", "get_or_404") and (c.args or c.keywords):
                if name in _EXECUTORS:
                    continue
                out.append(None)
        return out

    def comparisons(self, node: ast.AST, model: str) -> list[ast.expr | None]:
        """`Note.id == id`, `and_(a, b)`, `a & b`: the value side of each equality on a model
        column; None for anything else."""
        if isinstance(node, ast.Call) and _last(_dotted(node.func)) == "and_":
            return [x for a in node.args for x in self.comparisons(a, model)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitAnd):
            return [*self.comparisons(node.left, model), *self.comparisons(node.right, model)]
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left, right = node.left, node.comparators[0]
            for column, value in ((left, right), (right, left)):
                if self.column(column, model):
                    return [value]
        return [None]

    def column(self, node: ast.AST, model: str) -> bool:
        """`Note.id`, `Note.__table__.c.id`: a column of the read model."""
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name | ast.Attribute)
            and self.model_of(node.value) == model
        )

    def shaping_only(self, node: ast.AST, model: str) -> bool:
        """`joinedload(Note.owner)`, `Note.created.desc()`, a literal: shapes, never narrows."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Attribute):
            return (
                self.column(node, model)
                or self.model_of(node) is not None
                or (isinstance(node.value, ast.Attribute) and self.shaping_only(node.value, model))
            )
        if isinstance(node, ast.Call):
            func = _dotted(node.func)
            known = _last(func) in _SHAPING_CALLS and (
                self.o.library(func, self.rel)
                or (
                    isinstance(node.func, ast.Attribute)
                    and self.shaping_only(node.func.value, model)
                )
            )
            return known and all(self.shaping_only(a, model) for a in node.args)
        return isinstance(node, ast.Name) and self.model_of(node) is not None

    # ---- ids and the caller
    def is_id(self, node: ast.AST | None) -> bool:
        """A path id: its parameter, `kwargs["id"]`, `request.view_args["id"]`, `int(id)`."""
        if isinstance(node, ast.Name):
            return node.id in self.ids
        if isinstance(node, ast.Subscript):
            bag = _dotted(node.value)
            return (bag in self.bags or self.is_view_args(node.value)) and _const(
                node.slice
            ) in self.path_ids
        if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
            func = _dotted(node.func)
            if func in _ID_CASTS:
                return self.is_id(node.args[0])
            if func.endswith(".get") and isinstance(node.func, ast.Attribute):
                bag = node.func.value
                if _dotted(bag) in self.bags or self.is_view_args(bag):
                    return _const(node.args[0]) in self.path_ids
        return False

    def names_id(self, node: ast.AST) -> bool:
        return any(self.is_id(n) for n in ast.walk(node))

    def is_request(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and self.flask_name(node.id, "request")

    def is_view_args(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "view_args"
            and self.is_request(node.value)
        )

    def flask_name(self, name: str, wanted: str) -> bool:
        return self.o.modules.full(name, self.rel) == f"flask.{wanted}"

    def is_caller(self, node: ast.AST) -> bool:
        """`current_user`, `g.user`, `session["uid"]`, `get_jwt_identity()`,
        `auth.current_user()`, `request.authorization`."""
        if isinstance(node, ast.Name) and node.id in _CALLER_NAMES:
            return self.o.library(node.id, self.rel)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and self.flask_name(node.value.id, "g"):
                return True
            if node.attr == "authorization" and self.is_request(node.value):
                return True
        if isinstance(node, ast.Name) and self.flask_name(node.id, "session"):
            return True
        if isinstance(node, ast.Call) and _last(_dotted(node.func)) in _CALLER_CALLS:
            func = _dotted(node.func)
            if "." not in func:
                return self.o.library(func, self.rel)
            return self.o.library_instance(func.partition(".")[0], self.rel)
        return False

    def mentions_caller(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if self.is_caller(n):
                self.sees(n)
                return True
        return False


def _reads_view_args(fn: _Def) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr == "view_args" for n in ast.walk(fn))


def _binds(n: ast.stmt) -> set[str]:
    if isinstance(n, ast.ClassDef | _Def):
        return {n.name}
    if isinstance(n, ast.Import | ast.ImportFrom):
        return {a.asname or a.name.split(".")[0] for a in n.names if a.name != "*"}
    return {x.id for x in ast.walk(n) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store)}


def _targets(n: ast.AST) -> list[ast.expr]:
    if isinstance(n, ast.Assign):
        return list(n.targets)
    return [n.target] if isinstance(n, ast.AnnAssign) and n.value is not None else []


def _bound_value(site: ast.AST | None) -> ast.expr | None:
    """What a single-target assignment binds: `x = v` or `x: T = v`."""
    if isinstance(site, ast.Assign) and len(site.targets) == 1:
        return site.value
    return site.value if isinstance(site, ast.AnnAssign) else None


def _own(fn: _Def) -> Iterator[ast.AST]:
    """A function's own nodes, its body only: nested functions and classes are not run."""
    stack: list[ast.AST] = list(reversed(fn.body))
    while stack:
        n = stack.pop()
        yield n
        stack.extend(
            reversed([c for c in ast.iter_child_nodes(n) if not isinstance(c, _Def | ast.ClassDef)])
        )


def _params(fn: _Def, *, method: bool) -> list[str]:
    names = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]]
    return names[1:] if method and names[:1] in (["self"], ["cls"]) else names


def _const(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dotted(node: ast.AST | None) -> str:
    """`a.b.c` for a name or attribute chain (a call's function), else empty."""
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        else:
            return ".".join(reversed(parts))


def _last(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]
