"""Django and DRF ownership facts. The reader judges only (D35): a read of a model's rows by the
path id alone is judged, and anything else reads unknown."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import HandlerFacts, Lookup

_Def = ast.FunctionDef | ast.AsyncFunctionDef
_Found = tuple[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef]
Resolve = Callable[[str, str], _Found | None]
_Mro = list[tuple[str, ast.ClassDef | str]]

_RELATIONS = {"ForeignKey", "OneToOneField", "ManyToManyField"}
_USER_MODELS = re.compile(r"(?i)(^|\.)(User|AUTH_USER_MODEL|get_user_model)$")
_USER_BASES = {"AbstractUser", "AbstractBaseUser"}
# a queryset's reads and deletes; anything else (`update`, `exclude`, `extra`) is unread
_FILTERS = {
    "get", "filter", "first", "last", "delete", "exists", "all",
    "aget", "afirst", "alast", "adelete", "aexists",
}  # fmt: skip
# queryset methods that shape the rows a read returns, never which rows
_SHAPES = {
    "select_related", "prefetch_related", "only", "defer", "select_for_update", "order_by",
    "values", "values_list", "using", "distinct", "reverse", "iterator",
}  # fmt: skip
_SHORTCUTS = {"get_object_or_404", "aget_object_or_404", "get_list_or_404", "aget_list_or_404"}
_ID_CASTS = {"int", "str", "UUID", "uuid.UUID"}
_RESPONSES = {
    "render", "render_to_response", "JsonResponse", "HttpResponse", "Response", "redirect",
    "HttpResponseRedirect", "HttpResponseNotFound", "HttpResponseForbidden", "Http404",
    "PermissionDenied", "NotFound", "model_to_dict", "str", "int", "dict", "list",
}  # fmt: skip
# request data a client chose: any use leaves the view unsettled
_CLIENT = {"POST", "GET", "data", "body", "FILES", "headers", "COOKIES", "META", "query_params"}
# what a request knows of its caller
_CALLER = {"user", "session", "auth"}
# library decorators that act on nothing the view reads
_LIBRARY_DECORATORS = re.compile(
    r"^(login_required|permission_required|user_passes_test|staff_member_required|"
    r"require_\w+|csrf_\w+|ensure_csrf_cookie|cache_page|cache_control|never_cache|vary_on_\w+|"
    r"gzip_page|condition|etag|last_modified|api_view|permission_classes|"
    r"authentication_classes|throttle_classes|action|method_decorator|atomic|"
    r"non_atomic_requests|xframe_options_\w+|sensitive_\w+|extend_schema|swagger_auto_schema|"
    r"ratelimit)$"
)
# DRF's `@<action>.mapping.<verb>`: the same action, answering another verb
_ACTION_MAPPING = re.compile(r"^\w+\.mapping\.(get|post|put|patch|delete|head|options|trace)$")
# what middleware reads of the route a view is resolved to (its path ids); a bare path comparison
# (`request.path == "/health"`) acts on no object
_ROUTE_READS = {"view_kwargs", "resolver_match", "view_args"}
# methods that change which object a generic view or `get_object()` reads, or run before it
_READ_OVERRIDES = {
    "filter_queryset", "get_permissions", "check_object_permissions", "dispatch", "setup",
    "initial", "initialize_request", "perform_authentication",
}  # fmt: skip
_MAX_ALIASES = 8
_MAX_BASES = 64
# DRF filter backends that narrow by query parameters, never by the caller
_LIBRARY_FILTERS = {"SearchFilter", "OrderingFilter", "DjangoFilterBackend"}


@dataclass(frozen=True)
class _Model:
    fields: tuple[str, ...]
    managers: dict[str, bool]  # each declared manager: Django's own `Manager`, or not
    default: bool  # the default manager (shortcuts, generic views) is Django's own
    base: bool  # the base manager (`Meta.base_manager_name`) is Django's own

    def reads_all(self, manager: str) -> bool | None:
        """Whether `<Model>.<manager>` reads every row; None when it isn't a manager."""
        if manager == "_base_manager":
            return self.base
        if manager == "_default_manager" or (manager == "objects" and not self.managers):
            return self.default
        return self.managers.get(manager)


_UNREAD = _Model((), {}, False, False)


@dataclass(frozen=True)
class _Scope:
    """A class view's methods and class attributes, the first in method resolution order."""

    methods: dict[str, tuple[str, _Def]]
    attrs: dict[str, tuple[str, ast.expr]]

    @staticmethod
    def of(mro: _Mro) -> _Scope:
        methods: dict[str, tuple[str, _Def]] = {}
        attrs: dict[str, tuple[str, ast.expr]] = {}
        for where, c in mro:
            for n in c.body if isinstance(c, ast.ClassDef) else []:
                if isinstance(n, _Def):
                    methods.setdefault(n.name, (where, n))
                elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):
                    attrs.setdefault(n.targets[0].id, (where, n.value))
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value:
                    attrs.setdefault(n.target.id, (where, n.value))
        return _Scope(methods, attrs)


class DjangoOwnership:
    """What a Django or DRF view does with the path ids and the caller."""

    def __init__(self, sources: list[tuple[str, ast.Module, str]], resolve: Resolve) -> None:
        self.resolve = resolve
        self.imports = {rel: _imports(tree) for rel, tree, _ in sources}
        # the modules each file `*`-imports, in order: what a name they bind comes from
        self.stars = {
            rel: [
                "." * n.level + (n.module or "")
                for n in tree.body
                if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            ]
            for rel, tree, _ in sources
        }
        self.models: dict[str, _Model] = {}
        # `request.user.notes` -> `Note`; None when two models share the related name
        self.related: dict[str, str | None] = {}
        classes: dict[str, list[tuple[str, ast.ClassDef]]] = defaultdict(list)
        for rel, tree, _ in sources:
            for n in ast.walk(tree):
                if isinstance(n, ast.ClassDef):
                    classes[n.name].append((rel, n))
        user_models = {
            name
            for name, cs in classes.items()
            if any({_last(_dotted(b)) for b in c.bases} & _USER_BASES for _, c in cs)
        }
        # a checkout middleware that reads the route may act on the id before any view runs
        self.path_middleware = any(
            isinstance(n, ast.ClassDef | ast.FunctionDef)
            and ("middleware" in n.name.lower() or n.name == "process_view")
            and _reads_route(n)
            for _, tree, _ in sources
            for n in ast.walk(tree)
        )
        self.default_filters = _default_filters(sources)
        names = self.model_names(classes)
        pending = sorted(names)
        while pending:  # parents first, without recursion: inheritance may run deep
            ready = [
                n for n in pending if all(p in self.models for p in _parents(n, classes, names))
            ]
            if not ready:
                self.models |= dict.fromkeys(pending, _UNREAD)  # an inheritance cycle
                break
            for name in ready:
                self.add_model(name, classes, names, user_models)
            pending = [n for n in pending if n not in self.models]
        self.fields = {name: m.fields for name, m in self.models.items()}

    def django_db(self, rel: str, dotted: str) -> bool:
        """Whether a name in `rel` comes from `django.db` (`models.Model`, `m.CharField`)."""
        head = dotted.partition(".")[0]
        bound = self.imports.get(rel, {})
        if head in bound:
            origin = bound[head]
            return origin is not None and origin.startswith("django.db")
        stars = self.stars.get(rel, [])
        return bool(stars) and all(s.startswith("django.db") for s in stars)

    def library_decorator(self, d: ast.AST, rel: str) -> bool:
        """A decorator of a library's that acts on nothing the view reads (`login_required`),
        imported under its own name rather than a checkout namesake; or DRF's
        `@<action>.mapping.<verb>`."""
        dotted = _dotted(d)
        if _ACTION_MAPPING.match(dotted):
            return True
        if not _LIBRARY_DECORATORS.match(_last(dotted)):
            return False
        if not self.imported(dotted, rel):
            return False
        if _last(dotted) == "method_decorator" and isinstance(d, ast.Call):
            wrapped = d.args[0] if d.args else _kwarg(d, "decorator")
            items = wrapped.elts if isinstance(wrapped, ast.List | ast.Tuple) else [wrapped]
            return all(x is not None and self.library_decorator(x, rel) for x in items)
        return True

    def imported(self, dotted: str, rel: str) -> bool:
        """A name `rel` imports from a library (or a `*` import of one), not checkout code."""
        head = dotted.partition(".")[0]
        origin = self.imports.get(rel, {}).get(head)
        if origin is None and head not in self.imports.get(rel, {}):
            origin = next(iter(self.stars.get(rel, [])), None)
        return (
            origin is not None and not origin.startswith(".") and self.resolve(dotted, rel) is None
        )

    def model_names(self, classes: dict[str, list[tuple[str, ast.ClassDef]]]) -> set[str]:
        """The checkout's models: on Django's `Model`, on a checkout model (abstract bases), or
        on a library base while declaring Django fields (`TimeStampedModel`)."""

        def django_fields(rel: str, c: ast.ClassDef) -> bool:
            return any(
                isinstance(n, ast.Assign | ast.AnnAssign)
                and isinstance(n.value, ast.Call)
                and self.django_db(rel, _dotted(n.value.func))
                for n in c.body
            )

        names: set[str] = set()
        grew = True
        while grew:
            grew = False
            for name, cs in classes.items():
                if name in names:
                    continue
                if any(
                    any(
                        (_last(_dotted(b)) == "Model" and self.django_db(rel, _dotted(b)))
                        or _last(_dotted(b)) in names
                        for b in c.bases
                    )
                    or (
                        c.bases
                        and not any(_last(_dotted(b)) in classes for b in c.bases)
                        and django_fields(rel, c)
                    )
                    for rel, c in cs
                ):
                    names.add(name)
                    grew = True
        return names

    def add_model(
        self,
        name: str,
        classes: dict[str, list[tuple[str, ast.ClassDef]]],
        names: set[str],
        user_models: set[str],
    ) -> None:
        """A model, with the fields and managers it inherits from the checkout's models."""
        [(rel, cls), *others] = classes[name]
        fields: list[str] = []
        managers: dict[str, bool] = {}
        inherited: bool | None = None
        inherited_base: bool | None = None
        for parent in (self.models[p] for p in _parents(name, classes, names)):
            fields.extend(parent.fields)
            managers = {**parent.managers, **managers}
            if inherited is None and parent.managers:
                inherited, inherited_base = parent.default, parent.base
        own: list[tuple[str, bool]] = []
        meta: dict[str, str | None] = {}
        for n in cls.body:
            if isinstance(n, ast.ClassDef) and n.name == "Meta":
                meta |= {
                    _dotted(s.targets[0]): _const(s.value)
                    for s in n.body
                    if isinstance(s, ast.Assign) and len(s.targets) == 1
                }
            target = n.targets[0] if isinstance(n, ast.Assign) and len(n.targets) == 1 else None
            target = n.target if isinstance(n, ast.AnnAssign) else target
            value = n.value if isinstance(n, ast.Assign | ast.AnnAssign) else None
            if target is None or value is None:
                continue
            field = _dotted(target)
            if not isinstance(value, ast.Call):
                if field == "objects" or field in managers:
                    own.append(
                        (field, False)
                    )  # a manager bound elsewhere: what it reads isn't told
                continue
            kind = _dotted(value.func)
            if _last(kind).endswith("Manager") or "_queryset" in kind or "as_manager" in kind:
                # Django's own manager reads every row; anyone else's may narrow them
                own.append((field, _last(kind) == "Manager" and self.django_db(rel, kind)))
                continue
            fields.append(field)
            if _last(kind) in _RELATIONS:
                # a relation is stored as `<name>_id`: the record is tied to something
                fields.append(f"{field}_id")
                to = value.args[0] if value.args else _kwarg(value, "to")
                text = _const(to) or _dotted(to)
                user = bool(text) and bool(_USER_MODELS.search(text) or _last(text) in user_models)
                if user and _last(kind) != "ManyToManyField":
                    related = _const(_kwarg(value, "related_name")) or f"{name.lower()}_set"
                    # one related name for two models: which a read names isn't told
                    self.related[related] = None if related in self.related else name
        managers |= dict(own)
        if "default_manager_name" in meta:
            default = managers.get(meta["default_manager_name"] or "", False)
        elif own:
            default = own[0][1]
        else:
            default = inherited if inherited is not None else True
        if "base_manager_name" in meta:
            base = managers.get(meta["base_manager_name"] or "", False)
        else:
            base = inherited_base if inherited_base is not None else True
        if others:  # two models of one name: neither is told apart
            managers, default, base = dict.fromkeys(managers, False), False, False
        self.models[name] = _Model(tuple(fields), managers, default, base)

    def model_of(self, node: ast.AST, rel: str) -> str | None:
        """The checkout model a name in `rel` is (`Note`, `models.Note`, an alias)."""
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        dotted = _dotted(node)
        found = self.resolve(dotted, rel)
        if found is not None:
            return found[1].name if isinstance(found[1], ast.ClassDef) else None
        return dotted if isinstance(node, ast.Name) and dotted in self.models else None

    # ---- views
    def function(
        self, rel: str, fn: _Def, path_ids: set[str], *, drf: bool, mro: _Mro | None = None
    ) -> HandlerFacts:
        """A function view, or a method of the class view whose `mro` is given."""
        reads_object = None
        scope = _Scope.of(mro or [])
        if mro and isinstance(owner := mro[0][1], ast.ClassDef):
            where = mro[0][0]

            def reads_object() -> HandlerFacts:
                return self.generic(where, owner, mro, drf=drf, path_ids=path_ids)

        walk = _ViewWalk(self, rel, fn, path_ids, drf=drf, reads_object=reads_object, scope=scope)
        params = _params(fn)
        takes = bool(path_ids) or len(params) > 1 or fn.args.vararg or fn.args.kwarg
        return walk.facts(takes_id=bool(takes))

    def generic(
        self,
        rel: str,
        cls: ast.ClassDef,
        mro: _Mro,
        *,
        drf: bool,
        path_ids: set[str] | frozenset[str] = frozenset(),
    ) -> HandlerFacts:
        """A library detail view's read (`RetrieveAPIView`, a viewset's `retrieve`/`destroy`,
        `DetailView`, `get_object()`): its object comes from `get_object()`, by default
        `get_queryset()` read by the lookup kwarg."""
        span = _span(rel, cls)
        scope = _Scope.of(mro)
        if set(scope.methods) & _READ_OVERRIDES or self.path_middleware:
            return HandlerFacts(handoff=span, takes_id=True)
        if self.class_decorated(mro):
            return HandlerFacts(handoff=span, takes_id=True)
        ids = set(path_ids)
        if "get_object" in scope.methods:
            # its own read: `filter_queryset` runs only if it calls it, which reads unknown
            where, fn = scope.methods["get_object"]
            walk = _ViewWalk(self, where, fn, set(), drf=drf, kwargs_ids=ids, scope=scope)
            facts = walk.facts(takes_id=True)
            # an override runs the object permissions only if it calls them itself
            checks = any(
                isinstance(n, ast.Call) and _dotted(n.func) == "self.check_object_permissions"
                for n in ast.walk(fn)
            )
            return self.object_checked(facts, scope) if checks else facts
        if drf and self.filtered(scope):
            return HandlerFacts(handoff=span, takes_id=True)
        if "get_queryset" in scope.methods:
            where, fn = scope.methods["get_queryset"]
            body = [s for s in fn.body if not _docstring(s)]
            if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
                return HandlerFacts(handoff=_span(where, fn), takes_id=True)
            walk = _ViewWalk(self, where, fn, set(), drf=drf, kwargs_ids=ids, scope=scope)
            return self.object_checked(walk.queryset(body[0].value), scope)
        attr = next((scope.attrs[a] for a in ("queryset", "model") if a in scope.attrs), None)
        if attr is None:
            return HandlerFacts(handoff=span, takes_id=True)
        where, value = attr
        if (model := self.model_of(value, where)) is not None:
            if not self.models.get(model, _UNREAD).default:  # `model = Note`: by its pk
                return HandlerFacts(handoff=_span(where, value), takes_id=True)
            lookup = Lookup(_span(where, value), record_type=model)
            return self.object_checked(HandlerFacts(lookups=(lookup,), takes_id=True), scope)
        walk = _ViewWalk(self, where, cls, set(), drf=drf, kwargs_ids=ids, scope=scope)
        return self.object_checked(walk.queryset(value), scope)

    def class_decorated(self, mro: _Mro) -> bool:
        """A checkout class in the view's bases carries a decorator that may run first
        (`@method_decorator(only_mine, name="dispatch")`)."""
        return any(
            not self.library_decorator(d, where)
            for where, c in mro
            if isinstance(c, ast.ClassDef)
            for d in c.decorator_list
        )

    def object_checked(self, facts: HandlerFacts, scope: _Scope) -> HandlerFacts:
        """A permission class of the checkout's with `has_object_permission` sees the caller
        (`get_object()` runs it); it is read, never credited (D35)."""
        if not facts.lookups or facts.caller is not None or "permission_classes" not in scope.attrs:
            return facts
        where, value = scope.attrs["permission_classes"]
        for name in _names(value) or []:
            if (found := self.object_permission(name, where)) is not None:
                return replace(facts, caller=_span(*found))
        return facts

    def object_permission(self, name: str, rel: str) -> tuple[str, ast.ClassDef] | None:
        """The checkout class defining the `has_object_permission` a permission class runs,
        its own or inherited."""
        queue, seen = [(name, rel)], set()
        while queue and len(seen) < _MAX_BASES:
            dotted, where = queue.pop(0)
            found = self.resolve(dotted, where)
            if found is None or not isinstance(found[1], ast.ClassDef) or id(found[1]) in seen:
                continue
            seen.add(id(found[1]))
            if any(
                isinstance(n, _Def) and n.name == "has_object_permission" for n in found[1].body
            ):
                return found[0], found[1]
            queue += [(_dotted(b), found[0]) for b in found[1].bases]
        return None

    def filtered(self, scope: _Scope) -> bool:
        """Whether DRF's `filter_queryset` may narrow the read by something of the checkout's."""
        custom_set = "filterset_class" in scope.attrs
        if "filter_backends" not in scope.attrs:
            return self.default_filters or custom_set
        names = _names(scope.attrs["filter_backends"][1])
        return names is None or custom_set or any(_last(x) not in _LIBRARY_FILTERS for x in names)

    def plain_serializer(self, node: ast.AST | None, rel: str) -> bool:
        """A checkout serializer with no code, nested serializer or method field: it only renders
        the object."""
        found = self.resolve(_dotted(node), rel) if node is not None else None
        if found is None or not isinstance(found[1], ast.ClassDef):
            return False
        if not any("Serializer" in _dotted(b) for b in found[1].bases):
            return False
        for n in found[1].body:
            if isinstance(n, _Def):
                return False
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
                kind = _last(_dotted(n.value.func))
                if kind == "SerializerMethodField" or not kind.endswith("Field"):
                    return False
        return True


class _ViewWalk:
    """One view's body: the reads it makes by the path ids, and whether it sees the caller."""

    def __init__(
        self,
        o: DjangoOwnership,
        rel: str,
        fn: ast.AST,
        path_ids: set[str],
        *,
        drf: bool,
        reads_object: Callable[[], HandlerFacts] | None = None,
        scope: _Scope | None = None,
        kwargs_ids: set[str] | None = None,
        requests: set[str] | None = None,
        hop: bool = True,
    ) -> None:
        """`path_ids`: the parameters holding a path id; `kwargs_ids`: the ids `self.kwargs`
        holds, the same unless the walk is a hop into a helper."""
        self.o, self.rel, self.fn, self.drf, self.hop = o, rel, fn, drf, hop
        self.reads_object = reads_object
        self.scope = scope or _Scope({}, {})
        params = _params(fn) if isinstance(fn, _Def) else []
        self.path_ids = set(path_ids) if kwargs_ids is None else set(kwargs_ids)
        self.ids = set(path_ids) & set(params)
        self.requests = {"self.request", *params[:1]} if requests is None else requests
        self.querysets: dict[str, ast.expr] = {}
        # `*args`/`**kwargs`: the path ids, unnamed
        unnamed = (fn.args.vararg, fn.args.kwarg) if isinstance(fn, _Def) else ()
        self.bags = {a.arg for a in unnamed if a} | {"self.kwargs"}
        self.parent = {id(c): p for p in ast.walk(fn) for c in ast.iter_child_nodes(p)}
        self.lookups: list[Lookup] = []
        self.records: set[str] = set()
        self.caller: CodeSpan | None = None
        self.impure: ast.AST | None = None
        self.consumed: set[int] = set()
        self.alias(fn)

    def alias(self, fn: ast.AST) -> None:
        """`pk = self.kwargs["pk"]`, `pk = int(pk)`: a name bound once, to a path id, is one."""
        bound: dict[str, list[ast.AST]] = defaultdict(list)
        for n in _own(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                bound[n.id].append(self.parent.get(id(n), n))
        for name, sites in bound.items():
            [site] = sites if len(sites) == 1 else [None]
            value = _bound_value(site)
            if value is not None and self.is_id(value):
                self.ids.add(name)
            elif value is not None and _dotted(value) in self.requests:
                self.requests.add(name)  # `req = self.request`
            elif name in self.ids:
                self.ids.discard(name)  # the parameter rebound: no longer the path id
            elif value is not None:
                self.querysets[name] = value

    def facts(self, *, takes_id: bool) -> HandlerFacts:
        fn = self.fn
        decorators = fn.decorator_list if isinstance(fn, _Def) else []
        if not all(self.o.library_decorator(d, self.rel) for d in decorators):
            return HandlerFacts(handoff=_span(self.rel, fn), takes_id=takes_id)  # runs first
        if self.o.path_middleware:  # route-reading middleware runs before any view
            return HandlerFacts(handoff=_span(self.rel, fn), takes_id=takes_id)
        for n in _own(fn):
            self.node(n)
        exposed = [x for x in self.lookups if not x.scoped]
        if not exposed and self.impure is not None:
            return HandlerFacts(handoff=_span(self.rel, self.impure), takes_id=takes_id)
        return HandlerFacts(
            lookups=tuple(self.lookups),
            caller=self.caller,
            takes_id=takes_id,
            ignores_id=not (self.ids or self.bags - {"self.kwargs"}),
        )

    def queryset(self, value: ast.AST) -> HandlerFacts:
        """`get_queryset`'s returned queryset, read by the path's lookup kwarg."""
        lookup = self.read(value, generic=True)
        for n in ast.walk(value):
            if id(n) not in self.consumed:
                self.node(n)
        if lookup is None:
            return HandlerFacts(handoff=_span(self.rel, value), takes_id=True)
        return HandlerFacts(lookups=(lookup,), caller=self.caller, takes_id=True)

    def mark(self, node: ast.AST) -> None:
        self.impure = self.impure or node

    def consume(self, node: ast.AST) -> None:
        self.consumed |= {id(x) for x in ast.walk(node)}

    def node(self, n: ast.AST) -> None:
        if id(n) in self.consumed:
            return
        parent = self.parent.get(id(n))
        if not isinstance(n, ast.Name) and self.is_id(n):
            self.consume(n)
            if _bound_value(parent) is not n:
                self.mark(n)  # the id reaches something other than a read
            return
        if isinstance(n, ast.Call):
            self.call(n)
        elif isinstance(n, ast.Attribute) and self.is_request(n.value):
            if n.attr in _CLIENT:
                self.mark(n)
            elif n.attr in _CALLER:
                self.caller = self.caller or _span(self.rel, n)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.ids:
            if _bound_value(parent) is not n:
                self.mark(n)  # the id reaches something other than the read
        elif isinstance(n, ast.Name) and n.id in self.bags:
            self.mark(n)  # the unnamed path ids handed on
        elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.requests:
            handed = not isinstance(parent, ast.Attribute) and not (
                isinstance(parent, ast.Call) and _last(_dotted(parent.func)) in _RESPONSES
            )
            if handed:
                self.mark(n)  # the request handed on whole, its caller with it
                self.caller = self.caller or _span(self.rel, n)
        elif isinstance(n, ast.Subscript | ast.Lambda | ast.Yield | ast.YieldFrom):
            self.mark(n)

    def call(self, call: ast.Call) -> None:
        if (lookup := self.read(call)) is not None:
            self.lookups.append(lookup)
            return
        if id(call) in self.consumed:
            return
        dotted = _dotted(call.func)
        method = dotted.removeprefix("self.") if dotted.count(".") == 1 else ""
        if dotted == "self.get_object" and not call.args and not call.keywords:
            self.consume(call)
            self.take(call, self.reads_object() if self.reads_object is not None else None)
            return
        if dotted.startswith("self.") and method in self.scope.methods:
            self.consume(call)
            self.take(call, self.follow(call, *self.scope.methods[method]))
            return
        name, receiver = _last(_dotted(call.func)), _receiver(call)
        if receiver is None and (
            name in _RESPONSES or self.o.plain_serializer(call.func, self.rel)
        ):
            return
        if receiver is not None and _dotted(receiver) in self.records and name == "delete":
            return  # the record the read returned, deleted
        self.mark(call)

    def take(self, call: ast.Call, facts: HandlerFacts | None) -> None:
        """What a hop or `get_object()` read, as this view's own."""
        if facts is None or facts.handoff is not None or not facts.lookups:
            self.mark(call)
            return
        self.lookups.extend(facts.lookups)
        self.caller = self.caller or facts.caller
        self.record(call)

    def follow(self, call: ast.Call, where: str, fn: _Def) -> HandlerFacts | None:
        """One hop into a method of the view's class (D2): the ids and the request it is
        handed, by position or keyword."""
        if not self.hop or any(isinstance(a, ast.Starred) for a in call.args):
            return None
        params = _params(fn)
        handed = [*zip(params, call.args, strict=False)]
        handed += [(k.arg, k.value) for k in call.keywords if k.arg is not None]
        if any(k.arg is None for k in call.keywords) or len(call.args) > len(params):
            return None
        requests = {"self.request", *(p for p, a in handed if self.is_request(a))}
        if len(requests) > 1:
            self.caller = self.caller or _span(self.rel, call)
        walk = _ViewWalk(
            self.o,
            where,
            fn,
            {p for p, a in handed if self.is_id(a)},
            drf=self.drf,
            reads_object=self.reads_object,
            scope=self.scope,
            kwargs_ids=self.path_ids,
            requests=requests,
            hop=False,
        )
        return walk.facts(takes_id=True)

    def record(self, node: ast.AST) -> None:
        parent = self.parent.get(id(node))
        if isinstance(parent, ast.Await):
            parent = self.parent.get(id(parent))
        if isinstance(parent, ast.Assign):
            self.records |= {_dotted(t) for t in parent.targets}

    def read(self, node: ast.AST, *, generic: bool = False) -> Lookup | None:
        """A read of one model's rows: `Note.objects.filter(..).first()`,
        `get_object_or_404(Note, ..)`, `request.user.notes.get(..)`, by the path id; scoped when
        it also names the caller."""
        if not isinstance(node, ast.Call) or id(node) in self.consumed:
            return None
        func = node.func
        if isinstance(func, ast.Call) and _last(_dotted(func.func)) == "sync_to_async":
            func = func.args[0] if len(func.args) == 1 else func  # `sync_to_async(shortcut)(..)`
        if self.shortcut(func):
            if not node.args:
                return None
            target = self.target(node.args[0], default=True)
            if target is None:
                self.mark(node)
                return None
            model, bound, links, plain = target
            calls, filters = [*links, node], [*_filters(links), *node.args[1:]]
        else:
            target = self.target(node)
            if target is None:
                return None
            model, bound, links, plain = target
            calls, filters = links, _filters(links)
        self.consumed |= {id(x) for c in calls for x in ast.walk(c)}
        span = _span(self.rel, node)
        if not plain:
            self.mark(node)  # a library's model, or a manager that may narrow the rows
            return None
        shaping = [
            a
            for c in calls
            if _last(_dotted(c.func)) in _SHAPES
            for a in [*c.args, *(k.value for k in c.keywords)]
        ]
        if not all(_literal(a) for a in shaping):
            any(self.mentions_caller(a) for a in shaping)
            self.mark(node)  # `using(request.user.db)`: shaped by something we can't tell
            return None
        kwargs = [k for c in calls if _last(_dotted(c.func)) not in _SHAPES for k in c.keywords]
        values = [*filters, *(k.value for k in kwargs)]
        tied = bound or any(self.mentions_caller(v) for v in values)
        if not (generic or any(self.names_id(v) for v in values)):
            if tied:
                self.mark(node)  # the caller's rows, read by no path id
            return None
        self.record(node)
        if tied:
            return Lookup(span, scoped=True, record_type=model)  # never credited (D35)
        if filters or not all(
            k.arg is not None and (self.is_id(k.value) or isinstance(k.value, ast.Constant))
            for k in kwargs
        ):
            self.mark(node)  # narrowed by something else too: to what isn't told
            return None
        return Lookup(span, record_type=model)

    def shortcut(self, func: ast.AST) -> bool:
        """`get_object_or_404`, `shortcuts.get_list_or_404`: Django's, not a namesake."""
        dotted = _dotted(func)
        head, _, rest = dotted.partition(".")
        origin = self.o.imports.get(self.rel, {}).get(head)
        if origin is None or _last(dotted) not in _SHORTCUTS:
            return False
        return f"{origin}.{rest}".startswith("django.shortcuts")

    def target(
        self, node: ast.AST, *, default: bool = False, rel: str | None = None, depth: int = 0
    ) -> tuple[str | None, bool, list[ast.Call], bool] | None:
        """(model, None when two share the related name; read through the caller's own
        manager; the queryset calls; whether the manager read reads every row) for `Note` (by
        its default manager when `default`), `Note.objects.filter(..)`,
        `request.user.notes.all()`, or a queryset bound to a name or to `self.queryset`."""
        rel = rel or self.rel
        if depth > _MAX_ALIASES:
            return None
        if (aliased := self.aliased(node, rel)) is not None:
            where, value = aliased
            return self.target(value, default=default, rel=where, depth=depth + 1)
        if default and (model := self.o.model_of(node, rel)) is not None:
            return model, False, [], self.o.models.get(model, _UNREAD).default
        links: list[ast.Call] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            if cur.func.attr not in _FILTERS | _SHAPES:
                return None
            links.append(cur)
            cur = cur.func.value
        if not links:
            return None
        if self.aliased(cur, rel) is not None:
            base = self.target(cur, rel=rel, depth=depth + 1)
            return None if base is None else (base[0], base[1], links + base[2], base[3])
        if not isinstance(cur, ast.Attribute):
            return None
        if (model := self.o.model_of(cur.value, rel)) is not None:
            reads = self.o.models.get(model, _UNREAD).reads_all(cur.attr)
            return None if reads is None else (model, False, links, reads)
        if cur.attr in self.o.related and self.is_user(cur.value):
            return self.o.related[cur.attr], True, links, True
        return None

    def aliased(self, node: ast.AST, rel: str) -> tuple[str, ast.expr] | None:
        """The queryset a name (`queryset = Note.objects.all()`) or `self.queryset` holds."""
        if isinstance(node, ast.Name) and rel == self.rel and node.id in self.querysets:
            return rel, self.querysets[node.id]
        if _dotted(node) in ("self.queryset", "self.model") and isinstance(node, ast.Attribute):
            return self.scope.attrs.get(node.attr)
        return None

    def is_id(self, node: ast.AST | None) -> bool:
        """A path id: its parameter, `kwargs["pk"]`, `self.kwargs.get("pk")`, `int(pk)`."""
        if isinstance(node, ast.Name):
            return node.id in self.ids
        if isinstance(node, ast.Subscript):
            return _dotted(node.value) in self.bags and _const(node.slice) in self.path_ids
        if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
            func = _dotted(node.func)
            if func in _ID_CASTS:
                return self.is_id(node.args[0])
            if func.endswith(".get") and func.removesuffix(".get") in self.bags:
                return _const(node.args[0]) in self.path_ids
        return False

    def names_id(self, node: ast.AST) -> bool:
        return any(self.is_id(n) for n in ast.walk(node))

    def mentions_caller(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and n.attr in _CALLER and self.is_request(n.value):
                self.caller = self.caller or _span(self.rel, n)
                return True
        return False

    def is_request(self, node: ast.AST) -> bool:
        return _dotted(node) in self.requests

    def is_user(self, node: ast.AST | None) -> bool:
        """`request.user`, `self.request.user`."""
        if not (
            isinstance(node, ast.Attribute) and node.attr == "user" and self.is_request(node.value)
        ):
            return False
        self.caller = self.caller or _span(self.rel, node)
        return True


def _imports(tree: ast.Module) -> dict[str, str | None]:
    """What each module-level name is bound to last: an import's origin (`django.shortcuts.
    get_object_or_404`), or None for anything else (a def, an assignment, a conditional import)."""
    bound: dict[str, str | None] = {}
    for n in tree.body:
        if isinstance(n, ast.ImportFrom):
            module = "." * n.level + (n.module or "")
            bound |= {a.asname or a.name: f"{module}.{a.name}" for a in n.names}
        elif isinstance(n, ast.Import):
            bound |= {
                a.asname or a.name.split(".")[0]: a.name if a.asname else a.name.split(".")[0]
                for a in n.names
            }
        elif isinstance(n, _Def | ast.ClassDef):
            bound[n.name] = None  # its body binds only its own names
        else:
            for x in ast.walk(n):
                if isinstance(x, _Def | ast.ClassDef):
                    bound[x.name] = None
                elif isinstance(x, ast.Name) and isinstance(x.ctx, ast.Store):
                    bound[x.id] = None
                elif isinstance(x, ast.alias):
                    bound[x.asname or x.name.split(".")[0]] = None
    return bound


def _parents(
    name: str, classes: dict[str, list[tuple[str, ast.ClassDef]]], names: set[str]
) -> list[str]:
    return [p for b in classes[name][0][1].bases if (p := _last(_dotted(b))) in names and p != name]


def _default_filters(sources: list[tuple[str, ast.Module, str]]) -> bool:
    """Whether a settings module sets DRF's `DEFAULT_FILTER_BACKENDS` to one of the checkout's."""
    for _, tree, text in sources:
        if "DEFAULT_FILTER_BACKENDS" not in text:
            continue
        for n in ast.walk(tree):
            value = None
            if isinstance(n, ast.Dict):
                value = next(
                    (v for k, v in zip(n.keys, n.values, strict=True)
                     if _const(k) == "DEFAULT_FILTER_BACKENDS"),
                    None,
                )  # fmt: skip
            elif isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Subscript) and _const(t.slice) == "DEFAULT_FILTER_BACKENDS"
                for t in n.targets
            ):
                value = n.value
            if value is None:
                continue
            names = _names(value)
            if names is None or any(_last(x) not in _LIBRARY_FILTERS for x in names):
                return True
    return False


def _reads_route(node: ast.AST) -> bool:
    return any(
        (isinstance(n, ast.Attribute | ast.Name) and _dotted(n).split(".")[-1] in _ROUTE_READS)
        or (isinstance(n, _Def) and n.name == "process_view")
        for n in ast.walk(node)
    )


def _assigns(n: ast.Assign, name: str) -> bool:
    return name in {_dotted(t) for t in n.targets}


def _filters(links: list[ast.Call]) -> list[ast.expr]:
    """A queryset's positional filter arguments (`Q(..)`), not the shaping methods'."""
    return [a for c in links if _last(_dotted(c.func)) not in _SHAPES for a in c.args]


def _bound_value(site: ast.AST | None) -> ast.expr | None:
    """What a single-target assignment binds: `x = v` or `x: T = v`."""
    if isinstance(site, ast.Assign) and len(site.targets) == 1:
        return site.value
    return site.value if isinstance(site, ast.AnnAssign) else None


def _literal(node: ast.AST) -> bool:
    """A constant, or a tuple or list of them: `only("title")`, `of=("self",)`."""
    if isinstance(node, ast.Tuple | ast.List):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    return isinstance(node, ast.Constant)


def _docstring(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and _const(stmt.value) is not None


def _own(fn: ast.AST) -> Iterator[ast.AST]:
    """A function's own nodes, its body only: nested functions and classes are not run."""
    body = fn.body if isinstance(fn, _Def) else [fn]
    stack: list[ast.AST] = list(reversed(body))
    while stack:
        n = stack.pop()
        yield n
        stack.extend(
            reversed([c for c in ast.iter_child_nodes(n) if not isinstance(c, _Def | ast.ClassDef)])
        )


def _params(fn: _Def) -> list[str]:
    names = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]]
    return names[1:] if names[:1] == ["self"] else names


def _names(node: ast.AST | None) -> list[str] | None:
    """The classes a list names, by dotted name or string; None when an item can't be read."""
    if not isinstance(node, ast.List | ast.Tuple | ast.Set):
        return None
    names = [_const(e) or _dotted(e) for e in node.elts]
    return names if all(names) else None


def _receiver(call: ast.Call) -> ast.AST | None:
    return call.func.value if isinstance(call.func, ast.Attribute) else None


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


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
    return dotted.split(".")[-1]


def _span(rel: str, node: ast.AST) -> CodeSpan:
    return CodeSpan(path=RepoPath(rel), line=getattr(node, "lineno", 1))
