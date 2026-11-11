"""Flask ownership facts. The reader judges only (D35): a read of a model's rows by the path id
alone is judged, and anything else reads unknown."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterator

from traust_core.v1.models.code_facts import RouteFamily, RouteOwnership
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    HandlerFacts,
    Lookup,
    path_params,
    privileged_only,
)
from traust_core.v1.providers.route_plumbing import _Modules, _Row, _Source

_Def = ast.FunctionDef | ast.AsyncFunctionDef
_Found = tuple[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef]
_Model = tuple[str, str]  # (file, class name)

# a query's reads and deletes: the rows it returns are the rows it names
_TERMINALS = {
    "get", "get_or_404", "get_one", "first", "first_or_404", "one", "one_or_none", "one_or_404",
    "all", "delete", "count", "scalar", "scalar_one", "scalar_one_or_none", "scalars",
}  # fmt: skip
_FILTERS = {"filter", "filter_by", "where"}
# methods that shape the rows a query returns, never which rows
_SHAPES = {
    "options", "order_by", "limit", "offset", "with_for_update", "execution_options", "distinct",
    "populate_existing", "enable_eagerloads", "unique",
}  # fmt: skip
_QUERY = _TERMINALS | _FILTERS | _SHAPES
# what an `options(..)`/`order_by(..)` argument may call: loaders and orderings, on the model
_SHAPING_CALLS = {
    "joinedload", "selectinload", "subqueryload", "lazyload", "noload", "raiseload",
    "load_only", "defer", "undefer", "contains_eager", "desc", "asc", "nulls_last",
    "nulls_first",
}  # fmt: skip
_GETTERS = {"get", "get_or_404", "get_one"}  # `db.session.get(Note, id)`, `db.get_or_404(..)`
_EXECUTORS = {"execute", "scalars", "scalar", "first_or_404", "one_or_404"}  # taking a select
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
# who the caller is, by where it is imported from: flask-login and its kin, flask-jwt-extended
_CALLER_OBJECTS = re.compile(
    r"^(flask_login|flask_security|flask_user|flask_praetorian|flask_jwt|flask_jwt_extended)"
    r"(\.\w+)*"
    r"\.(current_user|current_identity)$"
)
_CALLER_FUNCTIONS = re.compile(
    r"^(flask_jwt_extended|flask_praetorian)(\.\w+)*\."
    r"(get_jwt_identity|get_jwt|get_current_user|current_user)$"
)
# `g` attributes that hold the caller, not request bookkeeping (`g.request_id`)
_G_CALLER = re.compile(r"(?i)user|account|identity|member|principal|auth|owner|tenant|caller")
_AUTH_METHODS = {"current_user", "username"}  # a flask-httpauth instance's
# library decorators that act on nothing the view reads; the route registration itself
_LIBRARY_DECORATORS = re.compile(
    r"^(login_required|fresh_login_required|roles_required|roles_accepted|"
    r"permission_required|auth_required|jwt_required|token_required|cached|memoize|limit|"
    r"exempt|doc|response|input|output|marshal_with|marshal_list_with|marshal|expect|"
    r"use_kwargs|use_args|arguments|paginate|param|header|produces|deprecated|hide|"
    r"swag_from|validate|route|get|post|put|patch|delete|head|options|cross_origin|"
    r"csrf_exempt)$"
)
_ROLE_DECORATORS = {"roles_required", "roles_accepted", "permission_required"}
_VALUE_HOOKS = {"url_value_preprocessor", "app_url_value_preprocessor"}
_BEFORE_HOOKS = {"before_request", "before_app_request"}
# a module import naming a library, never the checkout, whatever directory shares its name
_LIBRARY_ROOTS = re.compile(
    r"^(flask|flask_\w+|werkzeug|sqlalchemy|sqlmodel|jinja2|marshmallow|webargs|apispec|"
    r"apiflask|flasgger|pydantic|jwt|authlib|itsdangerous|asgiref)$"
)
_MAX_DEPTH = 8
_CREDITS = {RouteOwnership.SCOPED, RouteOwnership.CHECKED, RouteOwnership.NONE}
_EMPTY = ast.Module(body=[], type_ignores=[])


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
        guards = None if row.unguards else [*row.guards, *row.scope_guards, *reader.roles(row)]
        row.own(reader.facts(row), reader.fields, guards=guards)
        admin = guards is not None and any(privileged_only(g) for g in guards)
        credited = row.ownership in _CREDITS or (
            row.ownership is RouteOwnership.NOT_APPLICABLE
            and row.guarded
            and not row.unguards
            and not admin
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
        self.by_name: dict[str, list[tuple[str, ast.ClassDef]]] = defaultdict(list)
        self.bound: dict[str, set[str]] = defaultdict(set)  # each file's module-level names
        self.stars: dict[str, list[str]] = defaultdict(list)  # `from .models import *` modules
        for rel, tree in self.trees.items():
            for n in tree.body:
                if isinstance(n, ast.ClassDef | _Def):
                    self.defs[(rel, n.name)] = n
                if isinstance(n, ast.ClassDef):
                    self.by_name[n.name].append((rel, n))
                if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                    self.stars[rel].append(_relative(rel, n.module, n.level))
                self.bound[rel] |= _binds(n)
        self.narrowed = any(self.narrows(rel, tree) for rel, tree in self.trees.items())
        self.hooks = [h for rel, tree in self.trees.items() for h in self.route_hooks(rel, tree)]
        self.fields: dict[str, tuple[str, ...]] = {}
        self.plain: dict[_Model, bool] = {}
        for (rel, name), node in self.defs.items():
            if isinstance(node, ast.ClassDef):
                fields, plain, columns = self.model(rel, node, 0)
                self.plain[(rel, name)] = plain
                # two classes of one name (`Note` the model, `Note` a schema): the model's fields
                if name not in self.fields or columns:
                    self.fields[name] = fields

    # ---- the checkout
    def narrows(self, rel: str, tree: ast.Module) -> bool:
        """What may narrow every read: a session criteria, a query event, a query class of the
        checkout's (`SQLAlchemy(query_class=..)`, `db.Model.query_class = ..`,
        `query_property(TenantQuery)`, `query_cls=`)."""
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                name = _last(_dotted(n.func))
                listens = name == "listens_for" and any(
                    _const(a) in ("do_orm_execute", "before_compile") for a in n.args
                )
                if (
                    name == "with_loader_criteria"
                    or listens
                    or (name == "query_property" and (n.args or n.keywords))
                    or any(k.arg == "query_cls" for k in n.keywords)
                    or (name == "SQLAlchemy" and self.sqlalchemy_narrows(rel, n))
                ):
                    return True
            elif isinstance(n, ast.Assign | ast.AnnAssign) and any(
                _last(_dotted(t)) == "query_class" for t in _targets(n)
            ):
                return True
        return False

    def sqlalchemy_narrows(self, rel: str, call: ast.Call) -> bool:
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

    def route_hooks(
        self, rel: str, tree: ast.Module
    ) -> Iterator[tuple[str | None, set[str] | None]]:
        """(the receiver whose routes it runs before, None for all; the path values it reads,
        None for any) of each `url_value_preprocessor` and `before_request` reading
        `view_args`."""
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _last(_dotted(n.func)) in _VALUE_HOOKS:
                yield None, None  # registered by call: whatever it is handed
            if not isinstance(n, _Def):
                continue
            for d in n.decorator_list:
                hook, receiver = _last(_dotted(d)), _dotted(d).rpartition(".")[0]
                if hook in _VALUE_HOOKS:
                    params = _params(n, method=False)
                    reads = _keys_read(n, params[1] if len(params) > 1 else None)
                elif hook in _BEFORE_HOOKS:
                    reads = _view_args_read(n)
                    if reads is not None and not reads:
                        continue
                else:
                    continue
                yield self.hook_scope(hook, receiver.partition(".")[0], rel), reads

    def hook_scope(self, hook: str, receiver: str, rel: str) -> str | None:
        """A blueprint's hook runs before its own routes; an app's or an `app_*` hook, before
        every route."""
        if hook.startswith("app_") or hook == "before_app_request" or not receiver:
            return None
        site = self.binding(receiver, rel)
        if isinstance(site, ast.Call) and _last(_dotted(site.func)) in ("Flask", "APIFlask"):
            return None
        return receiver

    def model(self, rel: str, cls: ast.ClassDef, depth: int) -> tuple[tuple[str, ...], bool, bool]:
        """A class's fields (columns, relationships, annotated and `declared_attr` ones), its
        checkout bases' included; whether its query is Flask-SQLAlchemy's own (no `query_class`
        or query property of its own); and whether it declares columns at all."""
        fields: list[str] = []
        plain, columns = True, False
        for b in cls.bases:
            found = self.resolve(_dotted(b), rel) if depth < _MAX_DEPTH else None
            if found is not None and isinstance(found[1], ast.ClassDef):
                inherited, base_plain, base_columns = self.model(found[0], found[1], depth + 1)
                fields += inherited
                plain, columns = plain and base_plain, columns or base_columns
        for n in cls.body:
            if isinstance(n, _Def) and any(
                _last(_dotted(d)) == "declared_attr" for d in n.decorator_list
            ):
                fields.append(n.name)
                continue
            annotated = isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
            for target in _targets(n) or ([n.target] if annotated else []):  # type: ignore[union-attr]
                name = _dotted(target)
                if name in ("query_class", "query"):
                    plain = False
                elif name and not name.startswith("__"):
                    fields.append(name)
                    columns = columns or _declares_column(n)
        return tuple(fields), plain, columns

    def resolve(self, dotted: str, rel: str, depth: int = 0) -> _Found | None:
        """The checkout class or function a name in `rel` is, through imports, re-exports and
        `*` imports."""
        if depth > _MAX_DEPTH:
            return None
        head, _, rest = dotted.partition(".")
        if not rest and (rel, head) in self.defs:
            return rel, self.defs[(rel, head)]
        full = self.modules.full(dotted, rel)
        if full:
            mod, _, name = full.rpartition(".")
            where = self.module_file(mod)
            if where is None:
                return None
            if (where, name) in self.defs:
                return where, self.defs[(where, name)]
            return self.resolve(name, where, depth + 1)
        if not rest and head not in self.bound[rel]:
            for module in self.stars[rel]:
                where = self.module_file(module)
                if where is not None and (found := self.resolve(head, where, depth + 1)):
                    return found
        return None

    def module_file(self, module: str) -> str | None:
        """The checkout file a module is; never one for a library root a directory shares its
        name with (`tests/flask/`)."""
        if module in self.modules.by_module:
            return self.modules.by_module[module]
        if _LIBRARY_ROOTS.match(module.partition(".")[0]):
            return None
        return self.modules.file(module)

    def origin(self, dotted: str, rel: str, depth: int = 0) -> str:
        """The full name a name in `rel` is imported as, through checkout re-exports
        (`from .auth import current_user`); "" for a name it doesn't import."""
        full = self.modules.full(dotted, rel)
        if not full or depth > _MAX_DEPTH:
            return full
        mod, _, name = full.rpartition(".")
        where = self.module_file(mod)
        if where is None or name not in self.modules.imported.get(where, {}):
            return full
        return self.origin(name, where, depth + 1) or full

    def library(self, dotted: str, rel: str) -> bool:
        """A name `rel` imports from a library, not from the checkout or its own definition."""
        full = self.origin(dotted, rel)
        if not full:
            return False
        if self.module_file(full.rpartition(".")[0] or full) or self.module_file(full):
            return False
        # a checkout package's module not in the tree (`from .auth import ..`) is still its own
        return bool(_LIBRARY_ROOTS.match(full.partition(".")[0])) or not self.modules.local(full)

    def binding(self, name: str, rel: str, depth: int = 0) -> ast.expr | None:
        """What a name is bound to, once, anywhere in its file (an app factory's local `app`)
        or in the checkout module it is imported from; None when bound more than once."""
        full = self.modules.full(name, rel)
        if full:
            mod, _, attr = full.rpartition(".")
            where = self.module_file(mod) if mod else None
            if where is None or depth >= _MAX_DEPTH:
                return None
            return self.binding(attr, where, depth + 1)
        sites = [
            n.value
            for n in ast.walk(self.trees.get(rel, _EMPTY))
            if isinstance(n, ast.Assign | ast.AnnAssign)
            and n.value is not None
            and name in {_dotted(t) for t in _targets(n)}
        ]
        return sites[0] if len(sites) == 1 else None

    def binding_file(self, name: str, rel: str, depth: int = 0) -> str:
        full = self.modules.full(name, rel)
        if not full or depth >= _MAX_DEPTH:
            return rel
        mod, _, attr = full.rpartition(".")
        where = self.module_file(mod) if mod else None
        return self.binding_file(attr, where, depth + 1) if where else rel

    def library_instance(self, name: str, rel: str) -> bool:
        """`auth = HTTPBasicAuth()`, `bp = Blueprint(..)`, `db = SQLAlchemy()`: a name bound once
        to an instance of a library class."""
        site = self.binding(name, rel)
        return isinstance(site, ast.Call) and self.library(
            _dotted(site.func), self.binding_file(name, rel)
        )

    def library_decorator(self, d: ast.AST, rel: str) -> bool:
        """A library decorator acting on nothing the view reads, or a route registration;
        attribute forms (`auth.login_required`, `ns.param`) on a library instance."""
        dotted = _dotted(d)
        if not _LIBRARY_DECORATORS.match(_last(dotted)):
            return False
        if "." in dotted and self.library_instance(dotted.partition(".")[0], rel):
            return True
        return self.library(dotted, rel)

    def roles(self, row: _Row) -> list[str]:
        """A role decorator's full text (`roles_required('admin')`), so an admin-only route
        reads as one: the guard label carries only its name."""
        fn = self.handler(row.handler_path, row.handler_line)
        if fn is None:
            return []
        return [
            ast.unparse(d)[:200]
            for d in fn.decorator_list
            if isinstance(d, ast.Call)
            and _last(_dotted(d)) in _ROLE_DECORATORS
            and self.library_decorator(d, row.handler_path)
        ]

    def calls_caller(self, found: _Found) -> bool:
        """Whether checkout code the view calls reads the caller itself."""
        rel, node = found
        walk = _Walk(self, rel, None, set())
        return any(walk.is_caller(n) for n in ast.walk(node))

    # ---- views
    def facts(self, row: _Row) -> HandlerFacts:
        span = CodeSpan(path=RepoPath(row.handler_path), line=row.handler_line)
        unread = HandlerFacts(handoff=span, takes_id=True)
        ids = set(path_params(row.pattern))
        if any(
            (scope is None or scope == row.receiver) and (reads is None or bool(reads & ids))
            for scope, reads in self.hooks
        ):
            return unread
        rel = row.handler_path
        fn = self.handler(rel, row.handler_line)
        if fn is None:
            return unread
        chain: list[tuple[str, ast.ClassDef]] = []
        if row.view_class is not None:
            chain = self.class_chain(row.view_class.rsplit(".", 1)[-1], rel)
            if not chain or not self.plain_chain(chain):
                return unread
        return _Walk(self, rel, fn, ids, chain=chain).facts()

    def handler(self, rel: str, line: int) -> _Def | None:
        tree = self.trees.get(rel)
        if tree is None:
            return None
        return next((n for n in ast.walk(tree) if isinstance(n, _Def) and n.lineno == line), None)

    def class_chain(self, name: str, rel: str) -> list[tuple[str, ast.ClassDef]]:
        """A view class and its checkout bases, the class first: found in the handler's file,
        else as the checkout's one class of that name."""
        here = self.defs.get((rel, name))
        named = self.by_name.get(name, [])
        start = (rel, here) if isinstance(here, ast.ClassDef) else None
        start = start or (named[0] if len(named) == 1 else None)
        chain: list[tuple[str, ast.ClassDef]] = []
        queue = [start] if start else []
        while queue and len(chain) < _MAX_DEPTH * 4:
            where, cls = queue.pop(0)  # type: ignore[misc]
            if not isinstance(cls, ast.ClassDef) or any(c is cls for _, c in chain):
                continue
            chain.append((where, cls))
            queue += [b for base in cls.bases if (b := self.resolve(_dotted(base), where))]
        return chain

    def plain_chain(self, chain: list[tuple[str, ast.ClassDef]]) -> bool:
        """A class view whose own code runs only in its verb methods: no `dispatch_request` of
        the checkout's, and every decorator its classes carry or list (`decorators`,
        `method_decorators`) a library's."""
        for rel, cls in chain:
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
        fn: _Def | None,
        path_ids: set[str],
        *,
        chain: list[tuple[str, ast.ClassDef]] | None = None,
        bound_ids: set[str] | None = None,
        hop: bool = True,
    ) -> None:
        self.o, self.rel, self.fn, self.hop = o, rel, fn, hop
        self.chain = chain or []
        params = _params(fn, method=bool(self.chain)) if fn is not None else []
        self.path_ids = set(path_ids)
        self.ids = (set(path_ids) if bound_ids is None else set(bound_ids)) & set(params)
        self.bags = {a.arg for a in (fn.args.vararg, fn.args.kwarg) if a} if fn else set()
        self.parent = (
            {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)} if fn else {}
        )
        self.lookups: list[Lookup] = []
        self.caller: CodeSpan | None = None
        self.impure: ast.AST | None = None
        self.consumed: set[int] = set()
        self.queries: dict[str, ast.expr] = {}  # a name bound once to a query not yet run
        self.sessions: set[str] = set()  # `with Session(engine) as s`
        self.rebound: set[str] = set()
        if fn is not None:
            self.alias(fn)

    def span(self, node: ast.AST) -> CodeSpan:
        line = getattr(node, "lineno", self.fn.lineno if self.fn else 1)
        return CodeSpan(path=RepoPath(self.rel), line=line)

    def alias(self, fn: _Def) -> None:
        """Names bound once: to a path id (`note_id = int(note_id)`), to a query not yet run
        (`stmt = select(Note).where(..)`), or by `with` to a library session."""
        sites: dict[str, list[ast.AST | None]] = defaultdict(list)
        for n in _own(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                sites[n.id].append(self.parent.get(id(n)))
        for name, where in sites.items():
            site = where[0] if len(where) == 1 else None
            if isinstance(site, ast.withitem) and self.session_factory(site.context_expr):
                self.sessions.add(name)
                continue
            value = _bound_value(site)
            if value is not None and self.is_id(value):
                self.ids.add(name)
            elif name in self.ids:
                self.ids.discard(name)  # the parameter rebound: no longer the path id
            elif value is not None and self.pending(value):
                self.queries[name] = value
        # a name bound more than once (`q = q.filter_by(..)`) is never read as one query
        self.rebound = {n for n, w in sites.items() if len(w) > 1}

    def session_factory(self, expr: ast.AST) -> bool:
        """`Session(engine)`, `async_session()`: a library session."""
        if not isinstance(expr, ast.Call):
            return False
        dotted = _dotted(expr.func)
        return self.o.library(dotted, self.rel) or self.o.library_instance(
            dotted.partition(".")[0], self.rel
        )

    def pending(self, value: ast.expr) -> bool:
        """A query built but not run: `Note.query.filter_by(..)`, `select(Note).where(..)`."""
        if self.select(value) is not None:
            return True
        found = self.target(value)
        return found is not None and not any(
            isinstance(c.func, ast.Attribute) and c.func.attr in _TERMINALS for c in found[1]
        )

    def facts(self) -> HandlerFacts:
        assert self.fn is not None
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
        if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None:
            names = {_dotted(t) for t in _targets(n)}
            if names & set(self.queries):
                self.consume(n)  # a query bound to a name: read where it runs
                return
            if names & self.rebound and self.pending(n.value):
                self.consume(n)
                self.mark(n)  # a query refined across statements: what it reads isn't told
                return
        if isinstance(n, ast.Call):
            self.call(n)
        elif isinstance(n, ast.Attribute) and self.is_request(n.value) and n.attr in _CLIENT:
            self.mark(n)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.ids:
            if _bound_value(parent) is not n:
                self.mark(n)  # the id reaches something other than the read
        elif (
            isinstance(n, ast.Name)
            and isinstance(n.ctx, ast.Load)
            and (n.id in self.bags or n.id in self.queries or n.id in self.rebound)
        ) or isinstance(n, ast.Subscript | ast.Lambda | ast.Yield | ast.YieldFrom):
            self.mark(n)

    def call(self, call: ast.Call) -> None:
        if (lookup := self.read(call)) is not None:
            self.lookups.append(lookup)
            return
        if id(call) in self.consumed:
            return
        dotted = _dotted(call.func)
        if dotted.startswith("self.") and self.chain and dotted.count(".") == 1:
            self.consume(call)
            self.take(call, self.follow(call, dotted.removeprefix("self.")))
            return
        found = self.o.resolve(dotted, self.rel) if dotted else None
        if found is not None:
            if self.o.calls_caller(found):
                self.sees(call)  # checkout code that reads the caller itself
            self.mark(call)
            return
        response = _last(dotted) in _RESPONSES and self.o.library(dotted, self.rel)
        if dotted in _RESPONSES or response:
            return
        self.mark(call)

    def take(self, call: ast.Call, facts: HandlerFacts | None) -> None:
        if facts is None or facts.handoff is not None or not facts.lookups:
            self.mark(call)
            return
        self.lookups.extend(facts.lookups)
        self.caller = self.caller or facts.caller

    def follow(self, call: ast.Call, method: str) -> HandlerFacts | None:
        """One hop into a method of the view's class or its checkout bases (D2), with the ids
        it is handed."""
        found = next(
            (
                (r, n)
                for r, c in self.chain
                for n in c.body
                if isinstance(n, _Def) and n.name == method
            ),
            None,
        )
        if found is None or not self.hop or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        where, fn = found
        params = _params(fn, method=True)
        if any(k.arg is None for k in call.keywords) or len(call.args) > len(params):
            return None
        handed = [*zip(params, call.args, strict=False)]
        handed += [(k.arg, k.value) for k in call.keywords if k.arg is not None]
        walk = _Walk(
            self.o,
            where,
            fn,
            self.path_ids,
            chain=self.chain,
            bound_ids={p for p, a in handed if self.is_id(a)},
            hop=False,
        )
        return walk.facts()

    # ---- reads
    def read(self, call: ast.Call) -> Lookup | None:
        """A read of one model's rows by the path id: `Note.query.get_or_404(id)`,
        `db.session.get(Note, id)`, `db.session.query(Note).filter_by(id=id).first()`,
        `db.session.execute(select(Note).where(Note.id == id)).scalar_one()`, a query bound to
        a name and run later; scoped when it also names the caller."""
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
            return Lookup(span, scoped=True, record_type=model[1])  # never credited (D35)
        if not all(self.is_id(v) or isinstance(v, ast.Constant) for v in values):
            self.mark(call)  # narrowed by something else too: to what isn't told
            return None
        return Lookup(span, record_type=model[1])

    def target(
        self, call: ast.AST, depth: int = 0
    ) -> tuple[_Model, list[ast.Call], list[ast.expr]] | None:
        """(model, the query's calls, positional id arguments) of a read, or None."""
        if not isinstance(call, ast.Call) or depth > _MAX_DEPTH:
            return None
        last = _last(_dotted(call.func))
        getter = last in _GETTERS and len(call.args) == 2 and self.session_like(call.func)
        if getter and (model := self.model_of(call.args[0])) is not None:
            return model, [call], [call.args[1]]
        if last in _EXECUTORS and call.args and self.session_like(call.func):
            inner = self.select(call.args[0], depth + 1)
            if inner is not None:
                return inner[0], [call, *inner[1]], []
        links: list[ast.Call] = []
        cur: ast.AST = call
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr not in _QUERY:
                break
            links.append(cur)
            cur = cur.func.value
        if not links:
            return None
        positional = [a for c in links if _last(_dotted(c.func)) in _GETTERS for a in c.args]
        if isinstance(cur, ast.Name) and cur.id in self.queries:  # `q.first()`
            base = self.target(self.queries[cur.id], depth + 1)
            if base is not None:
                return base[0], [*links, *base[1]], [*positional, *base[2]]
            inner = self.select(self.queries[cur.id], depth + 1)
            return (inner[0], [*links, *inner[1]], positional) if inner else None
        if isinstance(cur, ast.Attribute) and cur.attr == "query":  # `Note.query.<links>`
            model = self.model_of(cur.value)
            return (model, links, positional) if model is not None else None
        if (  # `db.session.query(Note).<links>`
            isinstance(cur, ast.Call)
            and _last(_dotted(cur.func)) == "query"
            and len(cur.args) == 1
            and self.session_like(cur.func)
        ):
            model = self.model_of(cur.args[0])
            return (model, [*links, cur], positional) if model is not None else None
        return None

    def select(self, node: ast.AST, depth: int = 0) -> tuple[_Model, list[ast.Call]] | None:
        """`select(Note).where(..)`, `sa.select(..)`, `db.select(..)`, or a name bound to one."""
        if depth > _MAX_DEPTH:
            return None
        if isinstance(node, ast.Name) and node.id in self.queries:
            return self.select(self.queries[node.id], depth + 1)
        links: list[ast.Call] = []
        cur = node
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr == "select":
                break
            if cur.func.attr not in _FILTERS | _SHAPES:
                return None
            links.append(cur)
            cur = cur.func.value
        if isinstance(cur, ast.Name) and cur.id in self.queries and links:
            base = self.select(self.queries[cur.id], depth + 1)
            return (base[0], [*links, *base[1]]) if base else None
        if not (isinstance(cur, ast.Call) and _last(_dotted(cur.func)) == "select"):
            return None
        func = _dotted(cur.func)
        library = self.o.library(func, self.rel) or (
            "." in func and self.o.library_instance(func.partition(".")[0], self.rel)
        )
        if not library or len(cur.args) != 1:
            return None
        model = self.model_of(cur.args[0])
        return (model, [*links, cur]) if model is not None else None

    def session_like(self, func: ast.AST) -> bool:
        """`db.session.<m>`, `db.<m>`, `session.<m>`, `s.<m>` from `with Session() as s`: a
        Flask-SQLAlchemy or SQLAlchemy object, never checkout code we'd have to read."""
        receiver = func.value if isinstance(func, ast.Attribute) else None
        dotted = _dotted(receiver)
        if not dotted or dotted.partition(".")[2] not in ("", "session"):
            return False
        head = dotted.partition(".")[0]
        if head in self.sessions:
            return True
        return self.o.library_instance(head, self.rel) or self.o.library(head, self.rel)

    def model_of(self, node: ast.AST) -> _Model | None:
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        found = self.o.resolve(_dotted(node), self.rel)
        if found is None or not isinstance(found[1], ast.ClassDef):
            return None
        return found[0], found[1].name

    def terms(self, links: list[ast.Call], model: _Model) -> list[ast.expr | None]:
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
            elif name in _TERMINALS - _GETTERS - _EXECUTORS and (c.args or c.keywords):
                out.append(None)
        return out

    def comparisons(self, node: ast.AST, model: _Model) -> list[ast.expr | None]:
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

    def column(self, node: ast.AST, model: _Model) -> bool:
        """`Note.id`: a column of the read model."""
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name | ast.Attribute)
            and self.model_of(node.value) == model
        )

    def shaping_only(self, node: ast.AST, model: _Model) -> bool:
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
            on_model = isinstance(node.func, ast.Attribute) and self.shaping_only(
                node.func.value, model
            )
            known = _last(func) in _SHAPING_CALLS and (self.o.library(func, self.rel) or on_model)
            return known and all(self.shaping_only(a, model) for a in node.args)
        return isinstance(node, ast.Name) and self.model_of(node) is not None

    # ---- ids and the caller
    def is_id(self, node: ast.AST | None) -> bool:
        """A path id: its parameter, `kwargs["id"]`, `request.view_args["id"]`, `int(id)`."""
        if isinstance(node, ast.Name):
            return node.id in self.ids
        if isinstance(node, ast.Subscript):
            bag = node.value
            in_bag = _dotted(bag) in self.bags or self.is_view_args(bag)
            return in_bag and _const(node.slice) in self.path_ids
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

    def full(self, node: ast.AST) -> str:
        if not isinstance(node, ast.Name | ast.Attribute):
            return ""
        return self.o.origin(_dotted(node), self.rel)

    def is_request(self, node: ast.AST) -> bool:
        return self.full(node) == "flask.request"

    def is_view_args(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "view_args"
            and self.is_request(node.value)
        )

    def is_caller(self, node: ast.AST) -> bool:
        """`current_user`, `flask_login.current_user`, `g.user`, `session["uid"]`,
        `get_jwt_identity()`, `auth.current_user()`, `request.authorization`; through checkout
        re-exports."""
        if isinstance(node, ast.Name | ast.Attribute):
            full = self.full(node)
            if _CALLER_OBJECTS.match(full) or full == "flask.session":
                return True
            if full.startswith("flask.g.") and _G_CALLER.search(full.removeprefix("flask.g.")):
                return True
            if isinstance(node, ast.Attribute) and node.attr == "authorization":
                return self.is_request(node.value)
        if isinstance(node, ast.Call):
            if _CALLER_FUNCTIONS.match(self.full(node.func)):
                return True
            func = _dotted(node.func)
            if _last(func) in _AUTH_METHODS and "." in func:
                return self.o.library_instance(func.partition(".")[0], self.rel)
        return False

    def mentions_caller(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if self.is_caller(n):
                self.sees(n)
                return True
        return False


def _relative(rel: str, module: str | None, level: int) -> str:
    """The module a `from <level dots><module> import *` names from `rel`."""
    if not level:
        return module or ""
    parts = rel.removesuffix(".py").split("/")[:-level]
    return ".".join([*parts, *([module] if module else [])])


def _keys_read(fn: _Def, values: str | None) -> set[str] | None:
    """The constant keys a `url_value_preprocessor` reads from its `values`
    (`values.pop("lang_code")`); None when it uses them otherwise (whole, a computed key)."""
    if values is None:
        return set()
    parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
    keys: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and n.id == values and isinstance(n.ctx, ast.Load):
            key = _key_of(n, parent)
            if key is None:
                return None
            keys |= key
    return keys


def _view_args_read(fn: _Def) -> set[str] | None:
    """The keys a `before_request` reads from `request.view_args`: empty when it only tests it,
    None when it uses it whole."""
    parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
    keys: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr == "view_args":
            key = _key_of(n, parent)
            if key is None:
                return None
            keys |= key
    return keys


def _key_of(n: ast.AST, parent: dict[int, ast.AST]) -> set[str] | None:
    """The constant key a mapping is read by (`m["k"]`, `m.get("k")`, `m.pop("k")`); empty for
    a truth test; None for any other use."""
    above = parent.get(id(n))
    if isinstance(above, ast.Subscript) and (key := _const(above.slice)) is not None:
        return {key}
    if isinstance(above, ast.Attribute) and above.attr in ("get", "pop", "setdefault"):
        call = parent.get(id(above))
        key = _const(call.args[0]) if isinstance(call, ast.Call) and call.args else None
        return {key} if key is not None else None
    if isinstance(above, ast.If | ast.BoolOp | ast.UnaryOp):
        return set()
    return None


def _declares_column(n: ast.AST) -> bool:
    if isinstance(n, ast.AnnAssign) and "Mapped" in ast.unparse(n.annotation):
        return True
    return any(
        isinstance(x, ast.Call)
        and _last(_dotted(x.func)) in ("Column", "mapped_column", "relationship", "ForeignKey")
        for x in ast.walk(n)
    )


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
