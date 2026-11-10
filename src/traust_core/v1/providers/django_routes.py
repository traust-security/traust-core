"""Django and Django REST framework routes, read with `ast`: the `urlpatterns` of each urlconf
and the `include()` chains that mount them, DRF routers and the viewsets they register, and each
view's methods and guards."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.providers.python_guards import (
    UNREADABLE,
    GuardReader,
    empty,
    requires_nothing,
)
from traust_core.v1.providers.route_plumbing import (
    _c3,
    _const_str,
    _Def,
    _dotted,
    _guards_in,
    _mark,
    _module_statements,
    _own_nodes,
    _PyIndex,
    _resolve_import,
    _Row,
    _row,
    _targets,
    _unguards_in,
    _unique,
    constants_for,
    file_constants,
)

_PATH_CALLS = {"path", "re_path", "url"}
_HTTP = ("get", "post", "put", "patch", "delete", "head", "options")
# what a library view or viewset answers when the checkout doesn't say
_GENERIC_METHODS = {
    "ListAPIView": ("GET",),
    "CreateAPIView": ("POST",),
    "RetrieveAPIView": ("GET",),
    "DestroyAPIView": ("DELETE",),
    "UpdateAPIView": ("PUT", "PATCH"),
    "ListCreateAPIView": ("GET", "POST"),
    "RetrieveUpdateAPIView": ("GET", "PUT", "PATCH"),
    "RetrieveDestroyAPIView": ("GET", "DELETE"),
    "RetrieveUpdateDestroyAPIView": ("GET", "PUT", "PATCH", "DELETE"),
    "TemplateView": ("GET",),
    "ListView": ("GET",),
    "DetailView": ("GET",),
    "RedirectView": ("GET",),
    "CreateView": ("GET", "POST"),
    "UpdateView": ("GET", "POST"),
    "FormView": ("GET", "POST"),
    "DeleteView": ("GET", "POST"),
}
_VIEWSET_ACTIONS = {
    "ModelViewSet": ("list", "create", "retrieve", "update", "partial_update", "destroy"),
    "ReadOnlyModelViewSet": ("list", "retrieve"),
    "ListModelMixin": ("list",),
    "CreateModelMixin": ("create",),
    "RetrieveModelMixin": ("retrieve",),
    "UpdateModelMixin": ("update", "partial_update"),
    "DestroyModelMixin": ("destroy",),
}
_LIST_ACTIONS = {"list": "GET", "create": "POST"}
_ACTIONS = {"action", "detail_route", "list_route"}
_ALL_ACTIONS = _VIEWSET_ACTIONS["ModelViewSet"]
# library bases that answer no action of their own
_NO_ACTIONS = {"GenericViewSet", "ViewSet", "ViewSetMixin", "GenericAPIView", "APIView", "object"}
_DETAIL_ACTIONS = {
    "retrieve": "GET",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
}
_DECORATOR_METHODS = {
    "require_GET": ("GET",),
    "require_POST": ("POST",),
    "require_safe": ("GET", "HEAD"),
}
_MAX_DEPTH = 12
_LIST_CALLS = {"format_suffix_patterns", "i18n_patterns", "list", "reduce", "sum"}
_DRF_BASES = re.compile(r"APIView|ViewSet")
# CSRF protection (and its exemption) is about forged browser requests, and the method decorators
# about verbs: neither says who the caller is
_NOT_GUARDS = re.compile(r"(?i)csrf|^require_(GET|POST|safe|http_methods)$")
# decorators that set how a view runs, not who may call it
_INERT_DECORATORS = re.compile(
    r"^(api_view|action|detail_route|list_route|cache_page|cache_control|never_cache|vary_on_\w+|"
    r"condition|etag|last_modified|sensitive_\w+|xframe_options_\w+|gzip_page|atomic|"
    r"non_atomic_requests|extend_schema\w*|swagger_auto_schema|ensure_csrf_cookie)$"
)
# DRF's policy decorators: what they name is read as a permission list, or not at all
_POLICY_DECORATORS = {
    "permission_classes", "authentication_classes", "throttle_classes", "renderer_classes",
    "parser_classes", "schema", "versioning_class", "metadata_class",
}  # fmt: skip
# code that decides which permissions apply, or skips checking them
_PERMISSION_METHODS = {
    "get_permissions", "check_permissions", "permission_classes", "initial", "permission_denied",
}  # fmt: skip
# what Django's auth mixins decide by: a view overriding one may let anyone in
_MIXIN_HOOKS = {"has_permission", "handle_no_permission", "get_permission_required", "test_func"}
# Django's views marked `login_not_required`
# library views that answer only the methods a subclass defines
_PLAIN_VIEWS = {"View", "APIView", "GenericAPIView", "ViewSet", "GenericViewSet", "ViewSetMixin"}
_AUTH_VIEWS = {
    "LoginView", "LogoutView", "PasswordResetView", "PasswordResetDoneView",
    "PasswordResetConfirmView", "PasswordResetCompleteView",
}  # fmt: skip
# a library view: its `dispatch` runs before any mixin after it in the method order
_LIBRARY_VIEW = re.compile(r"(View|ViewSet)$")
# DRF's own classes that keep DRF's default permissions; any other sets its own (`ObtainAuthToken`)
_DRF_DEFAULTED = {*_GENERIC_METHODS, *_VIEWSET_ACTIONS, *_NO_ACTIONS, *_PLAIN_VIEWS}
_HANDLERS = ("handler400", "handler403", "handler404", "handler500")
# permissions that admit any caller, or any caller to read
_ANONYMOUS = re.compile(r"^(AllowAny|IsAnonymous\w*)$")
_SAFE = {"GET", "HEAD", "OPTIONS", "any"}


@dataclass
class _View:
    """What a view answers: (method, handler name, definition) per route, and its guards."""

    methods: list[tuple[str, str, ast.AST | None]]
    guards: list[str]
    unguards: list[str]
    # its permission classes, each read per method; None: DRF's defaults apply to a DRF view
    permissions: list[ast.AST] | None
    drf: bool = False
    # the methods whose own decorators guard them: a class view's, not a function view's
    methods_of: set[str] = field(default_factory=set)
    # `@method_decorator(login_required, name="post")` on the class: (guards, unguards) by method
    named: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)
    # a class view's class and its bases, the checkout's resolved
    mro: list[tuple[str, ast.ClassDef | str]] | None = None
    # a routed viewset's actions and the `@action(..)` each runs with (its kwargs apply)
    acting: dict[int, ast.Call] = field(default_factory=dict)


@dataclass
class _Router:
    """A DRF router: what is registered on it, and where it sits."""

    registered: list[tuple[str, ast.Call]] = field(default_factory=list)
    extends: list[tuple[str, str]] = field(default_factory=list)
    # a nested router's parent, the parent's route it nests under, and its lookup prefix
    parent: tuple[tuple[str, str] | None, str, str | None] | None = None
    default: bool = False
    slash: str = "/"
    dynamic: bool = False


@dataclass
class _Django:
    index: _PyIndex
    consts: dict[str, str]
    # the settings guards of the root urlconf being mounted
    current: tuple[list[str], list[ast.AST]] = ([], [])
    rows: list[_Row] = field(default_factory=list)
    included: set[str] = field(default_factory=set)
    mounted: set[str] = field(default_factory=set)
    seen: set[int] = field(default_factory=set)
    trees: dict[str, ast.Module] = field(default_factory=dict)
    _lists: dict[str, dict[str, list[ast.AST]]] = field(default_factory=dict)
    _routers: dict[tuple[str, str], _Router] | None = None
    _readers: dict[str, GuardReader] = field(default_factory=dict)
    homes: dict[int, str] = field(default_factory=dict)  # an entry read from another module
    _defined: dict[str, dict[str, ast.AST]] = field(default_factory=dict)
    following: set[int] = field(default_factory=set)
    origins: dict[tuple[str, str], str] = field(default_factory=dict)
    own_constants: dict[str, dict[str, str]] = field(default_factory=dict)
    _constants: dict[str, dict[str, str]] = field(default_factory=dict)
    _statements: dict[str, list[tuple[ast.stmt, bool]]] = field(default_factory=dict)
    _settings: dict[str, dict[str, ast.AST]] = field(default_factory=dict)
    _written: dict[str, set[str]] = field(default_factory=dict)
    _attributes: set[tuple[str, str]] | None = None

    def __post_init__(self) -> None:
        self.trees = {s.file.rel: s.tree for s in self.index.sources}
        self.own_constants = file_constants([s.file for s in self.index.sources])
        self.projects = self.settings()

    def constants(self, rel: str) -> dict[str, str]:
        if rel not in self._constants:
            self._constants[rel] = constants_for(
                rel,
                self.own_constants,
                self.index.modules.imported.get(rel, {}),
                lambda m: self.file(m, rel),
                self.consts,
            )
        return self._constants[rel]

    def reader(self, rel: str) -> GuardReader:
        """Guards read from `rel`: a name resolves to the checkout code it is bound to."""
        if rel not in self._readers:
            self._readers[rel] = GuardReader(
                lambda name: self.bound_to(name, rel),
                origin=lambda name: self.origin(rel, name),
                local=self.index.modules.local,
            )
        return self._readers[rel]

    def bound_to(self, dotted: str, rel: str) -> ast.AST | None:
        """The checkout definition or value a name in `rel` is bound to, UNREADABLE for checkout
        code we can't read (a conditional def, an object's method); None for a library's."""
        if (found := self.lookup_name(dotted, rel, frozenset())) is not None:
            return found[1]
        return UNREADABLE if self.checkout_bound(dotted, rel, frozenset()) else None

    def checkout_bound(self, dotted: str, rel: str, seen: frozenset[str]) -> bool | None:
        """Whether `rel` binds a name's head to checkout code (True) or a library's (False): any
        conditional checkout binding, else the last binding; None when nothing there binds it."""
        if rel in seen or len(seen) > _MAX_DEPTH:
            return None
        head, _, rest = dotted.partition(".")
        kinds = [
            (kind, conditional)
            for n, conditional in self.statements(rel)
            if (kind := self.binds(n, head, rest, rel, seen | {rel})) is not None
        ]
        settled = [kind for kind, conditional in kinds if not conditional]
        if any(kind for kind, conditional in kinds if conditional):
            return True
        return settled[-1] if settled else (False if kinds else None)

    def binds(
        self, n: ast.stmt, head: str, rest: str, rel: str, seen: frozenset[str]
    ) -> bool | None:
        """Whether statement `n` binds `head` to checkout code, through what it imports."""
        if isinstance(n, ast.ImportFrom):
            module = _resolve_import(rel, n.module, n.level)
            for a in n.names:
                if a.name == "*":
                    where = self.file(module, rel)
                    dotted = f"{head}.{rest}" if rest else head
                    if where is not None:
                        return self.checkout_bound(dotted, where, seen)
                    return True if self.unparsed(module) else None
                if (a.asname or a.name) == head:
                    return self.imported_bound(f"{module}.{a.name}", rest, rel, seen)
            return None
        if isinstance(n, ast.Import):
            for a in n.names:
                if (a.asname or a.name.split(".")[0]) == head:
                    return self.imported_bound(a.name if a.asname else head, rest, rel, seen)
            return None
        return True if head in _bound_names(n) else None

    def imported_bound(self, full: str, rest: str, rel: str, seen: frozenset[str]) -> bool:
        """Whether an imported name is checkout code: the longest part of it that is a checkout
        module binds the rest to checkout code, or that module doesn't parse."""
        if self.unparsed(full) or self.unparsed(full.rpartition(".")[0]):
            return True
        parts = [*full.split("."), *(rest.split(".") if rest else [])]
        for i in range(len(parts), 0, -1):
            if (where := self.file(".".join(parts[:i]), rel)) is not None:
                inner = ".".join(parts[i:])
                return not inner or bool(self.checkout_bound(inner, where, seen))
        return False

    def unparsed(self, module: str) -> bool:
        return bool(module) and any(
            u == module or u.endswith(f".{module}") for u in self.index.unparsed
        )

    def statements(self, rel: str) -> list[tuple[ast.stmt, bool]]:
        if rel not in self._statements:
            tree = self.trees.get(rel)
            self._statements[rel] = list(_module_statements(tree.body, False)) if tree else []
        return self._statements[rel]

    def attributes(self) -> set[tuple[str, str]]:
        """(name, attribute) of every `name.attribute = ..` in the checkout."""
        if self._attributes is None:
            self._attributes = {
                (_dotted(t.value).split(".")[-1], t.attr)
                for assigns in self.index.assigns.values()
                for n in assigns
                for t in _targets(n)
                if isinstance(t, ast.Attribute)
            }
        return self._attributes

    def file(self, module: str, rel: str) -> str | None:
        return self.index.modules.near(module, rel)

    # ---- settings
    def settings(self) -> dict[str, tuple[list[str], list[ast.AST]]]:
        """Each root urlconf's project-wide guards (`LoginRequiredMiddleware`, DRF's
        `DEFAULT_PERMISSION_CLASSES`) from the settings that name it: read as code, only where
        set unconditionally, and only those every settings module of the project agrees on."""
        found: dict[str, list[tuple[list[str], list[ast.AST]]]] = {}
        texts = {src.file.rel: src.file.text for src in self.index.sources}
        for rel in self.trees:
            # a module that names no setting, nor star-imports one that does, changes none
            if not self.names_settings(rel, texts, frozenset()):
                continue
            values = self.setting_values(rel, frozenset())
            if not values.keys() & {"ROOT_URLCONF", "MIDDLEWARE", "REST_FRAMEWORK"}:
                continue
            middleware = [
                "LoginRequiredMiddleware"
                for v in _strings(values.get("MIDDLEWARE"))
                if v == "django.contrib.auth.middleware.LoginRequiredMiddleware"
            ]
            drf = values.get("REST_FRAMEWORK")
            # the last `DEFAULT_PERMISSION_CLASSES` key wins; a `**spread` after it may replace it
            items = (
                list(zip(drf.keys, drf.values, strict=False)) if isinstance(drf, ast.Dict) else []
            )
            last = max(
                (
                    i
                    for i, (k, _) in enumerate(items)
                    if _const_str(k) == "DEFAULT_PERMISSION_CLASSES"
                ),
                default=None,
            )
            spread = any(k is None for k, _ in items[(last or 0) :])
            permissions = items[last][1] if last is not None and not spread else None
            entry = (middleware, _elements(permissions) if permissions is not None else [])
            root_value = values.get("ROOT_URLCONF")
            root = _const_str(root_value)
            where = self.file(root, rel) if root else None
            if where is not None:
                found.setdefault(where, []).append(entry)
            elif root_value is None:
                # no ROOT_URLCONF at all: the urlconfs beside the settings
                home = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
                for conf in self.trees:
                    if conf.startswith(home) and "urlpatterns" in self.lists(conf):
                        found.setdefault(conf, []).append(entry)
            # else: ROOT_URLCONF is set but not a literal (`os.environ.get(..)`, a
            # setting built at runtime): the urlconf it names is unknown, so these
            # settings scope nowhere — the beside-the-settings fallback must not
            # run, or one project's middleware would guard every urlconf beside a
            # settings module in a multi-project checkout. The rows carry no
            # project's settings and read judged.
        return {
            root: (
                [m for m in entries[0][0] if all(m in e[0] for e in entries)],
                [
                    d
                    for d in entries[0][1]
                    if all(_label(d) in {_label(x) for x in e[1]} for e in entries)
                ],
            )
            for root, entries in found.items()
        }

    def names_settings(self, rel: str, texts: dict[str, str], seen: frozenset[str]) -> bool:
        return any(k in texts[rel] for k in ("ROOT_URLCONF", "MIDDLEWARE", "REST_FRAMEWORK")) or (
            "import *" in texts[rel]
            and any(
                self.names_settings(star, texts, seen | {rel})
                for star in self.stars(rel)
                if star not in seen | {rel}
            )
        )

    def setting_values(self, rel: str, seen: frozenset[str]) -> dict[str, ast.AST]:
        """A settings module's unconditional top-level values, over the ones it star-imports."""
        tree = self.trees.get(rel)
        if tree is None or rel in seen:
            return {}
        if rel in self._settings:
            return self._settings[rel]
        values: dict[str, ast.AST] = {}
        read: set[int] = set()  # the statements read as a setting's value
        for n, conditional in _module_statements(tree.body, False):
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                module = _resolve_import(rel, n.module, n.level)
                if (where := self.file(module, rel)) is None:
                    continue
                found = self.setting_values(where, seen | {rel})
                if not conditional:
                    values.update(found)
                    continue
                # `try: from .local import *` may replace whatever that module sets
                for name in {*found, *self.written(where)}:
                    values.pop(name, None)
            elif conditional:
                continue
            elif isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None:
                read.add(id(n))
                for t in _targets(n):
                    if isinstance(t, ast.Name) and t.id.isupper():
                        values[t.id] = n.value
            elif (
                isinstance(n, ast.AugAssign)
                and isinstance(n.op, ast.Add)
                and isinstance(n.target, ast.Name)
                and isinstance(before := values.get(n.target.id), ast.List | ast.Tuple)
                and isinstance(n.value, ast.List | ast.Tuple)
            ):
                read.add(id(n))  # `MIDDLEWARE += [..]`
                values[n.target.id] = ast.List(elts=[*before.elts, *n.value.elts])
        for name in _changed(tree, read):
            values.pop(name, None)
        self._settings[rel] = values
        return values

    def written(self, rel: str) -> set[str]:
        """Every name a module assigns or changes."""
        if rel not in self._written:
            self._written[rel] = _changed(self.trees[rel], set())
        return self._written[rel]

    # ---- urlconfs
    def run(self) -> list[_Row]:
        # a urlconf builds `urlpatterns` or re-exports one (`from .api.urls import urlpatterns`)
        reexported = {
            rel: found[0]
            for rel in self.trees
            if "urlpatterns" not in self.lists(rel)
            if (found := self.imported_list(rel, "urlpatterns")) is not None
        }
        confs = [rel for rel in self.trees if "urlpatterns" in self.lists(rel) or rel in reexported]
        # what each urlconf includes, so the ones nothing includes are the roots
        unplaced = False
        self.included |= set(reexported.values())
        for rel in confs:
            for n in ast.walk(self.trees[rel]):
                if self.is_path(rel, n):
                    target = self.include_target(rel, n)
                    unplaced |= target is _UNPLACED
                    if isinstance(target, str):
                        self.included.add(target)
        roots = [r for r in confs if r not in self.included or r in self.projects]
        for rel in roots:
            self.current = self.projects.get(rel, ([], []))
            # an include we can't follow may be what mounts a urlconf nothing else includes
            self.mount(rel, "", unplaced and rel not in self.projects, frozenset())
        self.current = ([], [])  # what can't be placed takes no project's settings
        # a re-exported list was read where its root mounted it
        self.mounted |= {child for rel, child in reexported.items() if rel in self.mounted}
        # the views a root urlconf names for a request no pattern matches, or one that fails
        for rel in roots:
            for name in _HANDLERS:
                if isinstance(view := self.defined(rel).get(name), ast.expr):
                    if (path := _const_str(view)) is not None and re.fullmatch(r"[\w.]+", path):
                        view = ast.copy_location(ast.parse(path, mode="eval").body, view)
                    self.view_rows(rel, view, f"[{name}]", True, view.lineno)
        # what the walk couldn't place (a urlconf mounted from code it can't read, a route list
        # built by a function) is listed with its prefix unknown, never dropped
        for rel in confs:
            if rel not in self.mounted:
                self.mount(rel, "", True, frozenset())
        for rel, tree in self.trees.items():
            if rel in confs or any(
                m.startswith(("django.urls", "django.conf.urls"))
                for m in self.index.modules.imported.get(rel, {}).values()
            ):
                forwarded = _forwarded(tree)
                for n, _ in self.index.calls.get(rel, []):
                    if self.is_path(rel, n) and id(n) not in self.seen | forwarded:
                        self.entry(rel, n, "", True, frozenset())
        return self.rows

    def is_path(self, rel: str, node: ast.AST) -> bool:
        """A path() call, or a call to the checkout's own helper that builds one
        (`opt_slash_path("_health", health)`)."""
        if not isinstance(node, ast.Call):
            return False
        origin = self.index.modules.imported.get(rel, {}).get(_dotted(node.func), "")
        if _name(node) in _PATH_CALLS or (
            # `from django.urls import path as dj_path`
            origin.startswith(("django.urls.", "django.conf.urls."))
            and origin.rsplit(".", 1)[-1] in _PATH_CALLS
        ):
            return True
        if _route_args(node) == (None, None):
            return False
        fn = self.index.callee(_dotted(node.func), rel)
        return (
            fn is not None
            and fn.node is not None
            and any(isinstance(n, ast.Call) and _name(n) in _PATH_CALLS for n in ast.walk(fn.node))
        )

    def lists(self, rel: str) -> dict[str, list[ast.AST]]:
        """What each module-level list is built from: its assignment, then every `+=`,
        `.append`, `.extend` and `.insert`; a conditional assignment adds to it."""
        if rel in self._lists:
            return self._lists[rel]
        out: dict[str, list[ast.AST]] = {}
        for n, conditional in _module_statements(self.trees[rel].body, False):
            if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None:
                for t in _targets(n):
                    name = _dotted(t)
                    # `urlpatterns = format_suffix_patterns(urlpatterns)` keeps what it held
                    again = any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.value))
                    kept = out.get(name, []) if conditional or again else []
                    out[name] = [*kept, n.value]
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                out.setdefault(n.target.id, []).append(n.value)
            elif (
                isinstance(n, ast.Expr)
                and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Attribute)
                and isinstance(n.value.func.value, ast.Name)
                and n.value.func.attr in ("append", "extend", "insert")
                and n.value.args
            ):
                arg = n.value.args[-1]
                added = arg if n.value.func.attr == "extend" else ast.List(elts=[arg])
                out.setdefault(n.value.func.value.id, []).append(added)
        self._lists[rel] = out
        return out

    def flatten(self, rel: str, node: ast.AST | None, stack: frozenset[str]) -> list[ast.AST]:
        """The path() calls and `router.urls` a urlpatterns expression stands for, in order."""
        if isinstance(node, ast.List | ast.Tuple):
            out: list[ast.AST] = []
            for e in node.elts:
                e = e.value if isinstance(e, ast.Starred) else e
                nested = isinstance(e, ast.Name | ast.List | ast.Tuple | ast.BinOp) or (
                    isinstance(e, ast.Call) and _name(e) in _LIST_CALLS
                )
                out += self.flatten(rel, e, stack) if nested else [e]
            return out
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.flatten(rel, node.left, stack) + self.flatten(rel, node.right, stack)
        if isinstance(node, ast.Name) and f"{rel}:{node.id}" in stack:
            return []
        if isinstance(node, ast.Name) and node.id in self.lists(rel):
            return [
                e
                for part in self.lists(rel)[node.id]
                for e in self.flatten(rel, part, stack | {f"{rel}:{node.id}"})
            ]
        if (urls := _as_urls(node)) is not None:
            return [urls]  # `router.urls`, `router.get_urls()`
        if isinstance(node, ast.Name | ast.Attribute):
            found = self.imported_list(rel, _dotted(node))
            if found is not None:
                # a list another module builds: its entries read in that module
                where, name = found
                out = self.flatten(where, ast.Name(id=name), stack | {f"{rel}:{_dotted(node)}"})
                self.homes.update({id(e): where for e in out})
                return out
            return [node]  # a list we can't read: listed as a placeholder
        if isinstance(node, ast.Call) and _name(node) == "i18n_patterns":
            # its routes sit under the language code: `[language]/about/`
            inner = ast.List(elts=self.flatten(rel, ast.List(elts=node.args), stack))
            prefix = ast.JoinedStr(
                values=[
                    ast.FormattedValue(value=ast.Name(id="language"), conversion=-1),
                    ast.Constant("/"),
                ]
            )
            mounted = ast.Call(
                func=ast.Name(id="path"),
                args=[prefix, ast.Call(func=ast.Name(id="include"), args=[inner], keywords=[])],
                keywords=[],
            )
            return [ast.fix_missing_locations(ast.copy_location(mounted, node))]
        if isinstance(node, ast.Call) and _name(node) in _LIST_CALLS:
            # `reduce(add, groups)` folds its second argument
            args = node.args[1:] if _name(node) == "reduce" else node.args
            return [e for a in args for e in self.flatten(rel, a, stack)]
        # `static(..)`, `debug_toolbar_urls()`: routes a library builds, listed as a placeholder
        return [node] if isinstance(node, ast.Call) else []

    def imported_list(self, rel: str, dotted: str) -> tuple[str, str] | None:
        """The module and name of a urlpatterns list `rel` imports: `from .api import urls`."""
        target = self.index.modules.imported.get(rel, {}).get(dotted.split(".")[0])
        if target is None:
            return None
        home, _, local = ".".join([target, *dotted.split(".")[1:]]).rpartition(".")
        where = self.file(home, rel) if home else None
        return (where, local) if where is not None and local in self.lists(where) else None

    def include_target(
        self, rel: str, call: ast.Call
    ) -> str | ast.Attribute | tuple[str, ast.AST] | None:
        """What a path() includes: a urlconf's file, `router.urls`, or a list of entries."""
        view = _route_args(call)[1]
        if not (isinstance(view, ast.Call) and _name(view) == "include" and view.args):
            return None
        arg = view.args[0]
        if isinstance(arg, ast.Tuple) and arg.elts:
            arg = arg.elts[0]  # `include(("app.urls", "app"))`
        if (module := _const_str(arg)) is not None:
            return self.file(module, rel) or ""
        name = _dotted(arg)
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        module = ".".join([target, *name.split(".")[1:]]) if target is not None else ""
        if module and not isinstance(arg, ast.Call) and (where := self.file(module, rel)):
            return where  # `import notes.urls` .. `include(notes.urls)`
        if (urls := _as_urls(arg)) is not None:
            return urls
        if (found := self.imported_list(rel, name)) is not None:
            return found[0], ast.Name(id=found[1])  # a list another module builds
        if module and not isinstance(arg, ast.Call):
            # a library's urlconf by name; a setting's value (`settings.API_URLCONF`) is unknown
            return self.file(f"{module}.urls", rel) or (
                _UNPLACED if isinstance(arg, ast.Attribute) else ""
            )
        if isinstance(arg, ast.List | ast.Tuple) or (
            isinstance(arg, ast.Name) and arg.id in self.lists(rel)
        ):
            return rel, arg  # a list, or a name bound in this module
        return _UNPLACED  # `include(f"{app}.urls")`, `include(settings.API_URLCONF)`

    # ---- mounting
    def mount(self, rel: str, prefix: str, dynamic: bool, stack: frozenset[str]) -> None:
        if rel in stack or len(stack) > _MAX_DEPTH:
            return
        self.mounted.add(rel)
        for entry in self.flatten(rel, ast.Name(id="urlpatterns"), frozenset()):
            self.entry(rel, entry, prefix, dynamic, stack | {rel})

    def entry(
        self, rel: str, entry: ast.AST, prefix: str, dynamic: bool, stack: frozenset[str]
    ) -> None:
        self.seen.add(id(entry))
        rel = self.homes.get(id(entry), rel)
        if isinstance(entry, ast.Attribute) and entry.attr == "urls":
            self.router(rel, entry, prefix, dynamic)
            return
        if not (isinstance(entry, ast.Call) and self.is_path(rel, entry)):
            # what a library or code we can't read builds: its routes' prefix and views unknown
            text = ast.unparse(entry)[:200]
            pattern = _join(prefix, f"[{text[:80]}]")
            self.emit(
                rel, getattr(entry, "lineno", 1), True, _UNREAD, [("any", pattern, text, None)]
            )
            return
        route, view = _route_args(entry)
        if route is None:
            return
        part, computed = self.part(route, rel)
        pattern, dynamic = _join(prefix, part), dynamic or computed
        target = self.include_target(rel, entry)
        if target is _UNPLACED:
            self.emit(
                rel, entry.lineno, True, _UNREAD, [("any", pattern, ast.unparse(view)[:200], None)]
            )
            return
        if target == "":
            # a library's urlconf: its routes and guards aren't in the checkout
            text = ast.unparse(view)[:200] if view is not None else ""
            self.emit(rel, entry.lineno, dynamic, _UNREAD, [("any", pattern, text, None)])
            return
        if isinstance(target, str):
            self.mount(target, pattern, dynamic, stack)
            return
        if isinstance(target, ast.Attribute):
            self.router(rel, target, pattern, dynamic)
            return
        if target is not None:
            where, entries = target
            for e in self.flatten(where, entries, frozenset()):
                self.entry(where, e, pattern, dynamic, stack)
            return
        self.view_rows(rel, view, pattern, dynamic, entry.lineno)

    def part(self, node: ast.AST, rel: str) -> tuple[str, bool]:
        """A path() pattern's text, and whether it's computed: what isn't a literal or a
        module constant is kept as `[expr]`, which no path parameter looks like."""
        if (text := _const_str(node)) is not None:
            return text, False
        if isinstance(node, ast.Name) and node.id in (consts := self.constants(rel)):
            return consts[node.id], False
        if isinstance(node, ast.JoinedStr):
            parts = [
                v.value if isinstance(v, ast.Constant) else f"[{ast.unparse(v.value)}]"
                for v in node.values
            ]
            return "".join(str(p) for p in parts)[:160], True
        return f"[{ast.unparse(node)[:160]}]", True

    def view_rows(
        self, rel: str, view: ast.AST | None, pattern: str, dynamic: bool, line: int
    ) -> None:
        # decorators applied in the urlconf: `login_required(views.page)`, `cache_page(60)(view)`
        wrappers: list[ast.AST] = []
        while (
            isinstance(view, ast.Call)
            and not (isinstance(view.func, ast.Attribute) and view.func.attr == "as_view")
            and len(view.args) == 1
            and isinstance(view.args[0], ast.Name | ast.Attribute | ast.Call)
        ):
            wrappers.append(view.func)
            view = view.args[0]
        info = self.view(rel, view)
        if info is None:
            text = ast.unparse(view)[:200] if view is not None else ""
            info, routes = replace(_UNREAD), [("any", pattern, text, None)]
        else:
            routes = [(m, pattern, h, n) for m, h, n in info.methods]
        if info.drf and any(_dotted(w).split(".")[-1] == "cache_page" for w in wrappers):
            # a cached response is served before DRF checks permissions (token auth adds no Vary)
            info.permissions = []
        for w in wrappers:
            guards, unguards = _decorator_guards(w, self.reader(rel))
            info.guards = _unique([*info.guards, *guards])
            info.unguards = sorted({*info.unguards, *unguards})
        self.emit(rel, line, dynamic, info, routes)

    def emit(
        self,
        rel: str,
        line: int,
        dynamic: bool,
        info: _View,
        routes: list[tuple[str, str, str, ast.AST | None]],
    ) -> None:
        middleware, defaults = self.current
        for verb, pattern, handler, node in routes:
            guards, unguards, permissions = self.method_guards(node, info)
            named_guards, named_unguards = info.named.get(handler.rsplit(".", 1)[-1], ([], []))
            guards, unguards = [*guards, *named_guards], [*unguards, *named_unguards]
            inherited = permissions is None
            where = self.index.paths.get(id(node), rel) if node is not None else rel
            granted, open_ = _permitted(
                (defaults if inherited else permissions) if info.drf else [],
                verb,
                self.reader(where),
            )
            # `LoginRequiredMiddleware` exempts views marked `login_not_required`, and Django
            # marks its own (login, logout, password reset): it guards only checkout views
            # DRF marks every view of its own `login_required = False`, as another library may
            exempt = (
                "login_not_required" in unguards
                or node is None
                or info.drf
                or any(
                    isinstance(c, str)
                    and (c in _AUTH_VIEWS or (_unknown_view(c) and self.third_party(w, c)))
                    for w, c in info.mro or []
                )
            )
            scope = [] if exempt else list(middleware)
            row = _row(
                RouteFamily.DJANGO_DRF,
                verb,
                pattern or "/",
                handler,
                rel,
                line,
                _unique([*guards, *([] if inherited else granted)]),
                _unique([*scope, *(granted if inherited else [])]),
                sorted({*unguards, *open_}),
            )
            if node is not None:
                self.index.locate(row, node)
            self.rows.append(_mark(row, None, dynamic, rel))

    def method_guards(
        self, node: ast.AST | None, info: _View
    ) -> tuple[list[str], list[str], list[ast.AST] | None]:
        """A view's guards with its method's decorators; an `@action(permission_classes=..)`
        replaces the viewset's permissions."""
        guards, unguards, permissions = list(info.guards), list(info.unguards), info.permissions
        if (
            not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            or node.name not in info.methods_of
        ):
            return guards, unguards, permissions
        acting = info.acting.get(id(node))
        override = (
            next((k.value for k in acting.keywords if k.arg == "permission_classes"), None)
            if acting is not None
            else None
        )
        if override is not None:
            permissions = _elements(override)
        for d in node.decorator_list:
            if d is acting:
                continue
            more, fewer = _decorator_guards(d, self.reader(self.index.paths.get(id(node), "")))
            guards, unguards = [*guards, *more], [*unguards, *fewer]
        return _unique(guards), sorted(set(unguards)), permissions

    # ---- views
    def view(self, rel: str, node: ast.AST | None) -> _View | None:
        """The view a path() names: `View.as_view()`, `ViewSet.as_view({..})`, a function."""
        if node is None:
            return None
        mapping: dict[str, str] | None = None
        init: dict[str | None, ast.AST] = {}
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "as_view"
        ):
            if node.args and isinstance(node.args[0], ast.Dict):
                mapping = {
                    k.value.upper(): v.value
                    for k, v in zip(node.args[0].keys, node.args[0].values, strict=False)
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
                }
            init = {k.arg: k.value for k in node.keywords}
            node = node.func.value
        found = self.definition(_dotted(node), rel)
        if found is None:
            bound = (
                self.binding(_dotted(node), rel)
                if isinstance(node, ast.Name | ast.Attribute)
                else None
            )
            if bound is not None and bound[1] is not node and id(bound[1]) not in self.following:
                self.following.add(id(bound[1]))
                return self.view(*bound)
            return None
        def_rel, definition = found
        if not isinstance(definition, ast.ClassDef):
            return self.function_view(definition)
        info = self.class_view(def_rel, definition, mapping)
        if "permission_classes" in init:
            # `as_view(permission_classes=[AllowAny])` replaces the class attribute
            info.permissions = _elements(init["permission_classes"])
        if None in init:
            # `as_view(**PUBLIC)` may replace anything
            info.permissions, info.unguards = [], sorted({*info.unguards, "as_view(**)"})
        return info

    def definition(
        self, dotted: str, rel: str, seen: frozenset[str] = frozenset()
    ) -> tuple[str, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef] | None:
        """The class or function a name from `rel` is, through its imports and the modules
        (package `__init__`s) that re-export it."""
        found = self.lookup_name(dotted, rel, seen)
        return found if found is not None and not isinstance(found[1], ast.expr) else None  # type: ignore[return-value]

    def binding(self, dotted: str, rel: str) -> tuple[str, ast.AST] | None:
        """What a module-level assignment binds a view name to: `snippet_list = VS.as_view(..)`."""
        found = self.lookup_name(dotted, rel, frozenset())
        return found if found is not None and isinstance(found[1], ast.expr) else None

    def lookup_name(
        self, dotted: str, rel: str, seen: frozenset[str]
    ) -> tuple[str, ast.AST] | None:
        if not dotted or rel in seen or len(seen) > _MAX_DEPTH:
            return None
        name = dotted.split(".")[-1]
        target = self.index.modules.imported.get(rel, {}).get(dotted.split(".")[0])
        candidates: list[str] = []
        if target is not None:
            full = ".".join([target, *dotted.split(".")[1:]])
            where = self.file(full.rpartition(".")[0], rel) or self.file(full, rel)
            if where is not None:
                candidates.append(where)
        if "." not in dotted or target is None:
            candidates.append(rel)
        for where in candidates:
            if (here := self.defined(where).get(name)) is not None:
                return where, here
            if where != rel and name in self.index.modules.imported.get(where, {}):
                return self.lookup_name(name, where, seen | {rel})  # re-exported
            for star in reversed(self.stars(where)) if where != rel else []:
                if (found := self.lookup_name(name, star, seen | {rel, where})) is not None:
                    return found  # `from .other import *`, the last binding it
        if target is not None or name in self.defined(rel):
            return None  # imported from a library, or bound here to what we can't read
        # a name the urlconf never imports (a star import): the checkout's one definition of it
        found = [
            (where, n)
            for where in self.trees
            if isinstance(
                n := self.defined(where).get(name),
                ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
            )
        ]
        return found[0] if len(found) == 1 else None

    def stars(self, rel: str) -> list[str]:
        """The checkout modules `rel` star-imports."""
        return [
            where
            for n in self.trees.get(rel, ast.Module([], [])).body
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
            if (where := self.file(_resolve_import(rel, n.module, n.level), rel)) is not None
        ]

    def defined(self, rel: str) -> dict[str, ast.AST]:
        """A module's top-level classes and functions by name, and the value each assignment
        binds (the last one)."""
        if rel not in self._defined:
            out: dict[str, ast.AST] = {}
            for n in self.trees[rel].body if rel in self.trees else []:
                if isinstance(n, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                    out[n.name] = n
                elif (
                    isinstance(n, ast.Assign)
                    and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name)
                ):
                    out[n.targets[0].id] = n.value
            self._defined[rel] = out
        return self._defined[rel]

    def mro(self, rel: str, cls: ast.ClassDef) -> list[tuple[str, ast.ClassDef | str]]:
        """A class's method resolution order (C3), the checkout's classes resolved, a library's
        by name; depth-first where C3 can't be built."""
        return self.linearize(rel, cls, frozenset()) or self.depth_first(rel, cls, 0)

    def linearize(
        self, rel: str, cls: ast.ClassDef, seen: frozenset[int]
    ) -> list[tuple[str, ast.ClassDef | str]] | None:
        if id(cls) in seen or len(seen) > _MAX_DEPTH:
            return None
        lines: list[list[tuple[str, ast.ClassDef | str]]] = []
        for base in cls.bases:
            name = _dotted(base)
            found = self.definition(name, rel)
            if found is not None and isinstance(found[1], ast.ClassDef) and found[1] is not cls:
                line = self.linearize(found[0], found[1], seen | {id(cls)})
                if line is None:
                    return None
                lines.append(line)
            else:
                lines.append([(rel, name.split(".")[-1])])
                self.origins[(rel, name.split(".")[-1])] = self.origin(rel, name)
        lines.append([line[0] for line in lines])
        merged = _c3(lines, _class_key)
        return [(rel, cls), *merged] if merged is not None else None

    def depth_first(
        self, rel: str, cls: ast.ClassDef, depth: int
    ) -> list[tuple[str, ast.ClassDef | str]]:
        out: list[tuple[str, ast.ClassDef | str]] = [(rel, cls)]
        for base in cls.bases if depth <= _MAX_DEPTH else []:
            name = _dotted(base)
            found = self.definition(name, rel)
            if found is not None and isinstance(found[1], ast.ClassDef) and found[1] is not cls:
                out += self.depth_first(found[0], found[1], depth + 1)
            else:
                out.append((rel, name.split(".")[-1]))
                self.origins[(rel, name.split(".")[-1])] = self.origin(rel, name)
        return out

    def origin(self, rel: str, dotted: str) -> str:
        """The module path a name in `rel` is imported from: `rest_framework.views.APIView`."""
        return self.index.modules.full(dotted, rel)

    def class_view(self, rel: str, cls: ast.ClassDef, mapping: dict[str, str] | None) -> _View:
        mro = self.mro(rel, cls)
        names = [c if isinstance(c, str) else c.name for _, c in mro]
        defined: dict[str, tuple[str, ast.AST]] = {}
        aliases: dict[str, str] = {}
        blocked = False  # a library view earlier in the order may answer any method itself
        for where, c in mro:
            if isinstance(c, str):
                for http in _GENERIC_METHODS.get(c, ()):
                    defined.setdefault(http.lower(), (where, cls))
                blocked |= _unknown_view(c)
            else:
                for n in c.body:
                    if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                        shadowed = blocked and n.name in _HTTP
                        defined.setdefault(n.name, (where, cls if shadowed else n))
                    elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Name):
                        for t in n.targets:  # `post = get`
                            aliases.setdefault(_dotted(t), n.value.id)
        for alias, name in aliases.items():
            if alias not in defined and name in defined:
                defined[alias] = defined[name]
        policy = self.class_policy(mro)
        methods: list[tuple[str, str, ast.AST | None]] = []
        if mapping is not None:
            for verb, action in mapping.items():
                node = defined.get(action, (None, cls))[1]
                methods.append((verb, f"{cls.name}.{action}", node))
        else:
            # what the checkout defines, and what a library generic still answers for itself
            generic = next((_GENERIC_METHODS[n] for n in names if n in _GENERIC_METHODS), ())
            for http in _HTTP:
                if http in defined:
                    methods.append((http.upper(), f"{cls.name}.{http}", defined[http][1]))
                elif http.upper() in generic:
                    methods.append((http.upper(), f"{cls.name}.{http}", cls))
            if not methods:
                methods = [("any", cls.name, cls)]
        if (allowed := _http_method_names(mro)) is not None:
            get = next((m for m in methods if m[0] == "GET"), None)
            if get is not None and "head" in allowed and all(m[0] != "HEAD" for m in methods):
                methods.append(("HEAD", get[1], get[2]))  # `View.setup` serves HEAD with `get`
            # `View.dispatch` answers any other verb with 405
            methods = [m for m in methods if m[0] == "any" or m[0].lower() in allowed]
        policy.methods = methods
        policy.methods_of = {
            n.name for _, _, n in methods if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        policy.drf = any(
            isinstance(c, str) and _drf(self.origins.get((w, c), ""), c) for w, c in mro
        )
        if any(isinstance(c, str) and _unknown_view(c) for _, c in mro) and all(
            m != "any" for m, _, _ in methods
        ):
            # a library view whose own methods we don't know (`LoginView` answers POST)
            policy.methods = [*methods, ("any", cls.name, cls)]
        policy.mro = mro
        return policy

    def class_policy(self, mro: list[tuple[str, ast.ClassDef | str]]) -> _View:
        """A class view's guards, in method resolution order: auth mixins only ahead of the
        library view whose `dispatch` would run first; the nearest `permission_classes`, unless
        a library DRF view (whose default it is) comes first; `get_permissions` read as code we
        don't follow; `method_decorator(name=)` only where no earlier class defines the method."""
        guards: list[str] = []
        unguards: list[str] = []
        named: dict[str, tuple[list[str], list[str]]] = {}
        permissions: list[ast.AST] | None = None
        settled = viewed = False
        earlier: set[str] = set()  # the methods a class earlier in the order defines
        required: ast.AST | None = None  # the nearest `permission_required`
        for where, c in mro:
            if isinstance(c, str):
                origin = self.origins.get((where, c), "")
                own_policy = origin.startswith("rest_framework.") and c not in _DRF_DEFAULTED
                if _LIBRARY_VIEW.search(c) or own_policy:
                    viewed = True
                    third = own_policy or self.third_party(where, c)
                    if not settled and third:
                        # another library's view may set its own permissions
                        unguards.append(c)
                        permissions = []
                    settled = settled or third or _drf(origin, c)
                elif c.endswith("Mixin") and not viewed:
                    more, fewer = _decorator_guards(ast.Name(id=c), self.reader(where))
                    guards, unguards = [*guards, *more], [*unguards, *fewer]
                continue
            own = {n.name for n in c.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
            if not viewed and own & _MIXIN_HOOKS:
                viewed = True  # overrides what the library mixins after it decide by
            dispatch = next(
                (n for n in c.body if isinstance(n, _Def) and n.name == "dispatch"), None
            )
            if dispatch is not None and not _defers(dispatch):
                viewed = True  # its own dispatch may answer before the mixins after it
            for d in c.decorator_list:
                method = (
                    _const_str(next((k.value for k in d.keywords if k.arg == "name"), None))
                    if isinstance(d, ast.Call) and _name(d) == "method_decorator"
                    else None
                )
                more, fewer = _decorator_guards(d, self.reader(where))
                if method is not None and method != "dispatch":
                    if method not in earlier:
                        held = named.setdefault(method, ([], []))
                        held[0].extend(more)
                        held[1].extend(fewer)
                elif "dispatch" not in earlier:
                    guards, unguards = [*guards, *more], [*unguards, *fewer]
            # a DRF view's own dispatch that skips `super()` never runs `initial()`'s checks
            skips = (
                dispatch is not None
                and not _defers(dispatch)
                and any(
                    isinstance(x, str) and _drf(self.origins.get((w, x), ""), x) for w, x in mro
                )
            )
            decided = sorted(own & _PERMISSION_METHODS) + (["dispatch"] if skips else [])
            if decided:
                # which permissions apply is decided by code, wherever it sits in the order
                unguards.append(decided[0])
                permissions, settled = [], True
            per_instance = ("self", "permission_classes") in self.attributes()
            nested = [
                isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef)
                for stmt in c.body
                if not isinstance(stmt, ast.Assign | ast.AnnAssign)
                and (per_instance or not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef))
                for n in ast.walk(stmt)
                if isinstance(n, ast.Assign | ast.AnnAssign | ast.AugAssign)
                and any(_dotted(t).split(".")[-1] == "permission_classes" for t in _targets(n))
            ]
            # set per instance (`self.permission_classes` in `setup()`), else under a condition
            # in the body, after the class (`A.permission_classes = ..`) or by a class decorator
            if any(nested) or (not settled and (nested or self.rebinds(where, c))):
                unguards.append("permission_classes")
                permissions, settled = [], True
            body = {
                _dotted(t): n.value
                for n in c.body
                if isinstance(n, ast.Assign | ast.AnnAssign) and n.value is not None
                for t in _targets(n)
            }
            if not settled and "permission_classes" in body:
                permissions, settled = _elements(body["permission_classes"]), True
            required = body.get("permission_required") if required is None else required
            earlier |= own
        if required is not None and empty(required):
            # `permission_required = ()`: `has_perms(())` admits anyone
            guards = [g for g in guards if g.split(".")[-1] != "PermissionRequiredMixin"]
        return _View([], _unique(guards), sorted(set(unguards)), permissions, named=named)

    def third_party(self, rel: str, name: str) -> bool:
        """A library class neither DRF's nor Django's."""
        origin = self.origins.get((rel, name), "")
        return bool(origin) and not origin.startswith(("rest_framework.", "django."))

    def rebinds(self, rel: str, cls: ast.ClassDef) -> bool:
        """`A.permission_classes = ..` after the class, or a class decorator that may set it."""
        return (cls.name, "permission_classes") in self.attributes() or any(
            (found := self.bound_to(_dotted(d), rel)) is not None
            and (
                found is UNREADABLE
                or isinstance(found, ast.expr)
                or "permission_classes" in ast.unparse(found)
            )
            for d in cls.decorator_list
            if not (isinstance(d, ast.Call) and _name(d) == "method_decorator")
        )

    def function_view(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> _View:
        rel = self.index.paths.get(id(fn), "")
        methods: tuple[str, ...] = ("any",)
        guards: list[str] = []
        unguards: list[str] = []
        permissions: list[ast.AST] | None = None
        names = [_dotted(d).split(".")[-1] for d in fn.decorator_list]
        # DRF's policy decorators only count below `@api_view`, which reads what they set
        api_view = names.index("api_view") if "api_view" in names else None
        for i, (d, name) in enumerate(zip(fn.decorator_list, names, strict=True)):
            if name in _DECORATOR_METHODS:
                methods = _DECORATOR_METHODS[name]
            elif (
                name in ("require_http_methods", "api_view") and isinstance(d, ast.Call) and d.args
            ):
                methods = tuple(m.upper() for m in _strings(d.args[0])) or methods
            if name in _POLICY_DECORATORS:
                if (
                    name == "permission_classes"
                    and api_view is not None
                    and i > api_view
                    and isinstance(d, ast.Call)
                    and d.args
                ):
                    # api_view reads the attribute it sets: one between them may drop it
                    between = fn.decorator_list[api_view + 1 : i]
                    kept = all(self.keeps_attributes(x, rel) for x in between)
                    permissions = _elements(d.args[0]) if kept else []
                continue
            more, fewer = _decorator_guards(d, self.reader(rel))
            guards, unguards = [*guards, *more], [*unguards, *fewer]
        if api_view is not None and "cache_page" in names[:api_view]:
            permissions = []  # a cached response is served before DRF checks permissions
        if (fn.name, "login_required") in self.attributes():
            unguards.append("login_not_required")  # `view.login_required = False`: what it sets
        return _View(
            [(m, fn.name, fn) for m in methods],
            _unique(guards),
            sorted(set(unguards)),
            permissions,
            drf=api_view is not None,
        )

    def keeps_attributes(self, d: ast.AST, rel: str) -> bool:
        """A decorator that keeps the attributes of what it wraps: Django's and DRF's, the inert
        ones, and checkout code using `functools.wraps`."""
        name = _dotted(d)
        if _INERT_DECORATORS.match(name.split(".")[-1]) or self.origin(rel, name).startswith(
            ("django.", "rest_framework.")
        ):
            return True
        found = self.bound_to(name, rel)
        return found is not None and "wraps(" in ast.unparse(found)

    # ---- DRF routers
    def routers(self) -> dict[tuple[str, str], _Router]:
        """Every module-level DRF router (`DefaultRouter()`, drf-nested-routers' nested ones),
        with the viewsets registered on it from any module."""
        if self._routers is not None:
            return self._routers
        found: dict[tuple[str, str], _Router] = {}
        for rel, tree in self.trees.items():
            for n, _ in _module_statements(tree.body, False):
                value = n.value if isinstance(n, ast.Assign | ast.AnnAssign) else None
                if isinstance(value, ast.IfExp):  # `DefaultRouter() if DEBUG else SimpleRouter()`
                    value = value.body
                if not (isinstance(value, ast.Call) and _name(value).endswith("Router")):
                    continue
                kw = {k.arg: k.value for k in value.keywords}
                slash = kw.get("trailing_slash")
                router = found.setdefault((rel, _dotted(_targets(n)[0])), _Router())
                own = self.definition(_dotted(value.func), rel)
                router.default |= "Default" in _name(value) or (
                    # a checkout subclass of DefaultRouter keeps its API root view
                    own is not None
                    and isinstance(own[1], ast.ClassDef)
                    and any(isinstance(c, str) and "Default" in c for _, c in self.mro(*own))
                )
                if slash is None and own is not None and isinstance(own[1], ast.ClassDef):
                    # DRF reads `trailing_slash` off the instance at route-generation
                    # time, so a subclass's class attribute shapes the URLs exactly as
                    # the init kwarg does; the MRO's first definition wins, as at
                    # runtime.
                    for _, c in self.mro(*own):
                        if not isinstance(c, ast.ClassDef):
                            continue
                        for attr in c.body:
                            if isinstance(attr, ast.Assign | ast.AnnAssign) and any(
                                _dotted(t) == "trailing_slash" for t in _targets(attr)
                            ):
                                slash = attr.value
                                break
                        if slash is not None:
                            break
                router.slash = "" if isinstance(slash, ast.Constant) and not slash.value else "/"
                router.dynamic |= slash is not None and not isinstance(slash, ast.Constant)
                if _name(value).startswith("Nested") and len(value.args) >= 2:
                    # `NestedSimpleRouter(parent, r"notes", lookup="note")`
                    parent = self.router_key(rel, _dotted(value.args[0]))
                    route, computed = self.part(value.args[1], rel)
                    lookup = _const_str(kw.get("lookup"))
                    router.parent = (parent, route.strip("^$").strip("/"), lookup)
                    router.dynamic |= computed or parent is None
        self._routers = found
        # `router.trailing_slash = ...` — an instance assignment overrides the init
        # kwarg and any class attribute, as at runtime (DRF reads the attribute at
        # route-generation time). The assignment may sit in the module that binds
        # the router OR in any module that imports it (`from .routers import r;
        # r.trailing_slash = ""` in the urlconf that mounts it), so the receiver is
        # resolved through the import exactly as a register() call is. Assignments
        # that disagree, or a computed one, leave the rows pattern-dynamic: their
        # order across modules is import order, which the walk cannot see.
        assigned: dict[tuple[str, str], list[ast.AST]] = {}
        for rel, tree in self.trees.items():
            # the earliest line this module reads the router's URLs at: an
            # assignment after it cannot change the routes include() already
            # built (router.urls is evaluated where it is included)
            mounted_at: dict[tuple[str, str], int] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in ("urls", "get_urls"):
                    key = self.router_key(rel, _dotted(node.value))
                    if key is not None and key in found:
                        mounted_at[key] = min(mounted_at.get(key, node.lineno), node.lineno)
            for n, conditional in _module_statements(tree.body, False):
                targets = []
                if isinstance(n, ast.Assign):
                    targets = n.targets
                elif isinstance(n, ast.AnnAssign) and n.value is not None:
                    targets = [n.target]  # `router.trailing_slash: bool = False`
                for target in targets:
                    if not (isinstance(target, ast.Attribute) and target.attr == "trailing_slash"):
                        continue
                    key = self.router_key(rel, _dotted(target.value))
                    if key is None or key not in found:
                        continue
                    if conditional:
                        # inside an if/try/for: it may or may not run
                        found[key].dynamic = True
                        continue
                    if key in mounted_at and mounted_at[key] < n.lineno:
                        # the URLs were already built above the assignment
                        continue
                    if key[0] != rel and key not in mounted_at:
                        # a module that neither binds the router nor mounts it:
                        # whether its assignment runs before the include is
                        # import order, which the walk cannot see
                        found[key].dynamic = True
                        continue
                    assigned.setdefault(key, []).append(n.value)
        for key, values in assigned.items():
            constants = {v.value for v in values if isinstance(v, ast.Constant)}
            if any(not isinstance(v, ast.Constant) for v in values) or len(constants) > 1:
                found[key].dynamic = True
            elif constants:
                found[key].slash = "" if not next(iter(constants)) else "/"
        for rel in self.trees:
            for n, _ in self.index.calls.get(rel, []):
                if not isinstance(n.func, ast.Attribute):
                    continue
                if n.func.attr == "register" and _registered(n) is not None:
                    key = self.router_key(rel, _dotted(n.func.value))
                    if key in found:
                        found[key].registered.append((rel, n))
                elif (
                    n.func.attr == "extend"
                    and isinstance(n.func.value, ast.Attribute)
                    and n.func.value.attr == "registry"
                    and n.args
                ):
                    # `router.registry.extend(other.registry)`
                    key = self.router_key(rel, _dotted(n.func.value.value))
                    other = self.router_key(rel, _dotted(n.args[0]).removesuffix(".registry"))
                    if key in found and other in found:
                        found[key].extends.append(other)
        self.helper_registrations(found)
        return found

    def helper_registrations(self, found: dict[tuple[str, str], _Router]) -> None:
        """`def register_routes(router): router.register(..)`, called with a router."""
        helpers: dict[str, list[tuple[str, ast.FunctionDef, list[ast.Call]]]] = {}
        for rel in self.trees:
            by_fn: dict[int, tuple[ast.FunctionDef, list[ast.Call]]] = {}
            for n, fn in self.index.calls.get(rel, []):
                if (
                    isinstance(fn, ast.FunctionDef)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "register"
                    and isinstance(n.func.value, ast.Name)
                    and n.func.value.id in {a.arg for a in fn.args.args}
                    and _registered(n) is not None
                ):
                    by_fn.setdefault(id(fn), (fn, []))[1].append(n)
            for fn, calls in by_fn.values():
                helpers.setdefault(fn.name, []).append((rel, fn, calls))
        if not helpers:
            return
        for where in self.trees:
            for site, _ in self.index.calls.get(where, []):
                if not site.args:
                    continue
                for rel, fn, calls in helpers.get(_dotted(site.func).split(".")[-1], []):
                    target = self.definition(_dotted(site.func), where)
                    if target is None or target[1] is not fn:
                        continue
                    params = [a.arg for a in fn.args.args]
                    for c in calls:
                        i = params.index(c.func.value.id)  # type: ignore[attr-defined]
                        arg = site.args[i] if i < len(site.args) else None
                        key = self.router_key(where, _dotted(arg)) if arg is not None else None
                        if key in found:
                            found[key].registered.append((rel, c))

    def router_key(self, rel: str, name: str) -> tuple[str, str] | None:
        """The (module, name) a router named in `rel` is bound at, through its imports."""
        if (rel, name) in (self._routers or {}) or (
            "." not in name
            and any(
                isinstance(n, ast.Assign | ast.AnnAssign)
                and name in {_dotted(t) for t in _targets(n)}
                for n, _ in _module_statements(self.trees.get(rel, ast.Module([], [])).body, False)
            )
        ):
            return rel, name
        target = self.index.modules.imported.get(rel, {}).get(name.split(".")[0])
        if target is None:
            return None
        full = ".".join([target, *name.split(".")[1:]])
        module, _, local = full.rpartition(".")
        where = self.file(module, rel)
        return (where, local) if where else None

    def router(self, rel: str, urls: ast.Attribute, prefix: str, dynamic: bool) -> None:
        """The routes `router.urls` stands for: each registered viewset's list and detail routes
        and its `@action`s."""
        key = self.router_key(rel, _dotted(urls.value))
        routers = self.routers()
        if key not in routers:  # `admin.site.urls`, a library's router
            self.emit(
                rel, urls.lineno, dynamic, _UNREAD, [("any", prefix, ast.unparse(urls), None)]
            )
            return
        router = routers[key]
        base, base_dynamic = self.router_base(key, frozenset())
        dynamic = dynamic or base_dynamic or router.dynamic
        if router.default:
            # DefaultRouter's API root view
            self.emit(
                rel,
                urls.lineno,
                dynamic,
                _View([], [], [], None, True),
                [("GET", prefix or "/", "APIRootView", None)],
            )
        for k in [key, *router.extends]:
            for where, n in routers[k].registered:
                prefix_node, viewset = _registered(n)  # type: ignore[misc]
                route, computed = self.part(prefix_node, where)
                route = route.strip("^$").strip("/")
                self.viewset_rows(
                    where,
                    viewset,
                    _join(prefix, base + route),
                    dynamic or computed,
                    n.lineno,
                    router.slash,
                )

    def router_base(
        self, key: tuple[str, str] | None, seen: frozenset[tuple[str, str]]
    ) -> tuple[str, bool]:
        """A nested router's routes sit under its parents': `notes/<note_pk>/comments/..`."""
        router = self.routers().get(key) if key is not None else None
        if router is None or router.parent is None or key in seen or key is None:
            return "", key in seen
        parent, route, lookup = router.parent
        above, dynamic = self.router_base(parent, seen | {key})
        # the parent's lookup kwarg: `note` over a viewset looked up by `slug` is `note_slug`
        field = next(
            (
                self.lookup(self.mro(*viewset))
                for where, n in (
                    self.routers()[parent].registered if parent in self.routers() else []
                )
                if (args := _registered(n)) is not None
                and self.part(args[0], where)[0].strip("^$").strip("/") == route
                and (viewset := self.definition(_dotted(args[1]), where)) is not None
                and isinstance(viewset[1], ast.ClassDef)
            ),
            "pk",
        )
        # drf-nested-routers' default lookup is `nested_<depth>`, read but not certain
        nested = f"nested_{self.depth(parent)}"
        return f"{above}{route}/<{lookup or nested}_{field}>/", dynamic or lookup is None

    def depth(self, key: tuple[str, str] | None) -> int:
        """How deep a nested router's parent sits: 1 under a plain router."""
        depth, seen = 1, set()
        while key is not None and key not in seen and (r := self.routers().get(key)) and r.parent:
            seen.add(key)
            depth, key = depth + 1, r.parent[0]
        return depth

    def viewset_rows(
        self, rel: str, node: ast.AST, prefix: str, dynamic: bool, line: int, slash: str = "/"
    ) -> None:
        found = self.definition(_dotted(node), rel)
        if found is None or not isinstance(found[1], ast.ClassDef):
            self.view_rows(rel, node, prefix + slash, dynamic, line)
            return
        where, cls = found
        mro = self.mro(where, cls)
        actions: dict[str, ast.AST] = {}
        extra: list[tuple[str, str, ast.AST, bool, list[str]]] = []
        acting: dict[int, ast.Call] = {}
        library = None  # another library's viewset, whose `@action`s we don't know
        for where_c, c in reversed(mro):
            if isinstance(c, str):
                # a base whose actions we don't know may answer any of them
                known = _VIEWSET_ACTIONS.get(c)
                if known is None and c not in _NO_ACTIONS:
                    known = _ALL_ACTIONS
                    library = c if self.third_party(where_c, c) else library
                for a in known or ():
                    actions[a] = cls  # its own, over those of the classes after it
                continue
            mapped: dict[str, list[tuple[str, ast.AST]]] = {}
            for n in c.body:
                if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                if n.name in _LIST_ACTIONS or n.name in _DETAIL_ACTIONS:
                    actions[n.name] = n
                for d in n.decorator_list:
                    # `@share.mapping.delete`: another verb of the `share` action
                    if (
                        isinstance(d, ast.Attribute)
                        and isinstance(d.value, ast.Attribute)
                        and d.value.attr == "mapping"
                    ):
                        mapped.setdefault(_dotted(d.value.value), []).append((d.attr.upper(), n))
                deco = next((d for d in n.decorator_list if self.is_action(where_c, d)), None)
                if deco is None:
                    continue
                if isinstance(deco, ast.Call):
                    acting[id(n)] = deco
                kw = {k.arg: k.value for k in deco.keywords} if isinstance(deco, ast.Call) else {}
                detail = _dotted(deco).endswith("detail_route") or (
                    isinstance(kw.get("detail"), ast.Constant) and kw["detail"].value is True
                )
                listed = kw.get("methods")
                if isinstance(listed, ast.Name | ast.Attribute):  # `methods=WRITE`, a constant
                    bound = self.binding(_dotted(listed), where_c)
                    listed = bound[1] if bound is not None else listed
                methods = (
                    [m.upper() for m in _strings(listed)]
                    if isinstance(listed, ast.List | ast.Tuple | ast.Set)
                    else ["any"]
                    if listed is not None
                    else ["GET"]
                ) or ["any"]
                url_path = _const_str(kw.get("url_path")) or n.name
                extra.append((n.name, url_path, n, detail, methods))
            for action, url_path, fn0, detail, _ in list(extra):
                for verb, fn in mapped.get(action, []):
                    extra.append((fn.name, url_path, fn, detail, [verb]))
                    # the router builds a mapped verb with its action's kwargs
                    if id(fn0) in acting:
                        acting[id(fn)] = acting[id(fn0)]
        policy = self.class_policy(mro)
        # an empty registration prefix (`register("", ..)`) adds no segment
        prefix = prefix.rstrip("/")
        lead = f"{prefix}/" if prefix else ""
        detail_prefix = f"{lead}<{self.lookup(mro)}>"
        routes = [
            (verb, f"{prefix}{slash}" if prefix else "", f"{cls.name}.{action}", actions[action])
            for action, verb in _LIST_ACTIONS.items()
            if action in actions
        ]
        routes += [
            (verb, f"{detail_prefix}{slash}", f"{cls.name}.{action}", actions[action])
            for action, verb in _DETAIL_ACTIONS.items()
            if action in actions
        ]
        for name, url_path, n, detail, methods in extra:
            base = f"{detail_prefix}/" if detail else lead
            routes += [
                (m, f"{base}{url_path.strip('/')}{slash}", f"{cls.name}.{name}", n) for m in methods
            ]
        if not routes:
            routes = [("any", f"{prefix}{slash}", cls.name, cls)]
        methods_of = {
            n.name for _, _, _, n in routes if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        info = _View(
            [],
            policy.guards,
            policy.unguards,
            policy.permissions,
            True,
            methods_of,
            policy.named,
            mro,
            acting,
        )
        self.emit(rel, line, dynamic, info, routes)
        if library is not None:
            # the routes its `@action`s add (djoser's `users/me/`) aren't in the checkout
            self.emit(rel, line, True, info, [("any", f"{lead}[{library} actions]", cls.name, cls)])

    def is_action(self, rel: str, d: ast.AST) -> bool:
        """`@action`, legacy `@detail_route`/`@list_route`, or an alias of one."""
        name = _dotted(d)
        origin = self.index.modules.imported.get(rel, {}).get(name.split(".")[0], "")
        return name.split(".")[-1] in _ACTIONS or origin.rsplit(".", 1)[-1] in _ACTIONS

    def lookup(self, mro: list[tuple[str, ast.ClassDef | str]]) -> str:
        """The detail route's URL keyword: `lookup_url_kwarg`, `lookup_field`, else `pk`."""
        for attr in ("lookup_url_kwarg", "lookup_field"):
            for _, c in mro:
                if isinstance(c, ast.ClassDef):
                    for n in c.body:
                        if (
                            isinstance(n, ast.Assign)
                            and attr in {_dotted(t) for t in n.targets}
                            and (value := _const_str(n.value)) is not None
                        ):
                            return value
        return "pk"


_UNREAD = _View([], [], [], None)


def _forwarded(tree: ast.Module) -> set[int]:
    """The path() calls inside a helper that passes its own parameters on: the helper's callers
    are the routes."""
    out: set[int] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            params = {a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]}
            out |= {
                id(n)
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and len(n.args) >= 2
                and any(isinstance(a, ast.Name) and a.id in params for a in n.args[:2])
            }
    return out


def _unknown_view(name: str) -> bool:
    """A library view whose own methods we don't know (`LoginView` answers POST)."""
    return bool(_LIBRARY_VIEW.search(name)) and name not in {*_GENERIC_METHODS, *_PLAIN_VIEWS}


def _defers(dispatch: ast.AST) -> bool:
    """A view's own `dispatch` that hands every request to `super().dispatch()` before it could
    answer one itself; `super(Mixin, self)` calls past the mixins."""
    if re.search(r"\bsuper\(\s*\w", ast.unparse(dispatch)):
        return False
    nodes = list(_own_nodes(dispatch))
    calls = [
        n for n in nodes if isinstance(n, ast.Call) and ast.unparse(n.func) == "super().dispatch"
    ]
    if not calls:
        return False
    first = min(c.lineno for c in calls)
    return not any(
        isinstance(n, ast.Return)
        and n.lineno <= first
        and not any(c is n.value or c is getattr(n.value, "value", None) for c in calls)
        for n in nodes
    )


def _bound_names(n: ast.stmt) -> set[str]:
    """The names a module-level statement binds."""
    if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {n.name}
    if isinstance(n, ast.Assign | ast.AnnAssign | ast.AugAssign):
        targets = _targets(n)
    elif isinstance(n, ast.For | ast.AsyncFor):
        targets = [n.target]
    else:
        return set()
    out: set[str] = set()
    while targets:
        t = targets.pop()
        if isinstance(t, ast.Name):
            out.add(t.id)
        elif isinstance(t, ast.Tuple | ast.List):
            targets += t.elts
        elif isinstance(t, ast.Starred):
            targets.append(t.value)
    return out


def _changed(tree: ast.Module, read: set[int]) -> set[str]:
    """The names a module changes other than by the statements read as values: assigned under a
    condition or in place (`|=`), through a subscript or a method call, or deleted."""
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign | ast.AnnAssign | ast.AugAssign) and id(n) not in read:
            out |= {_dotted(t).split(".")[0] for t in _targets(n)}
        if isinstance(n, ast.Delete):
            out |= {_dotted(t) for t in n.targets}
        if isinstance(n, ast.Assign | ast.AugAssign | ast.Delete):
            targets = n.targets if isinstance(n, ast.Assign | ast.Delete) else [n.target]
            out |= {_dotted(t.value) for t in targets if isinstance(t, ast.Subscript)}
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            out.add(_dotted(n.func.value))
    return out


_UNPLACED = "?"  # an include whose target can't be read


def _as_urls(node: ast.AST | None) -> ast.Attribute | None:
    """`router.urls`, and `router.get_urls()` as the same."""
    if isinstance(node, ast.Attribute) and node.attr == "urls":
        return node
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_urls"
        and not node.args
    ):
        return ast.copy_location(ast.Attribute(value=node.func.value, attr="urls"), node)
    return None


def _registered(call: ast.Call) -> tuple[ast.AST, ast.AST] | None:
    """A router `register()` call's prefix and viewset, positional or by keyword."""
    kw = {k.arg: k.value for k in call.keywords}
    prefix = call.args[0] if call.args else kw.get("prefix")
    viewset = call.args[1] if len(call.args) > 1 else kw.get("viewset")
    return (prefix, viewset) if prefix is not None and viewset is not None else None


def _route_args(call: ast.Call) -> tuple[ast.AST | None, ast.AST | None]:
    """A path() call's route and view, positional or by keyword (`path(route=.., view=..)`)."""
    kw = {k.arg: k.value for k in call.keywords}
    route = call.args[0] if call.args else kw.get("route", kw.get("regex"))
    view = call.args[1] if len(call.args) > 1 else kw.get("view")
    return route, view


def _name(call: ast.Call) -> str:
    return _dotted(call.func).split(".")[-1]


def _join(prefix: str, pattern: str) -> str:
    """Django joins an included urlconf's patterns to the prefix that mounts it; a regex keeps
    one `^` at the front and drops the prefix's `$`."""
    if not prefix:
        return pattern
    return prefix.rstrip("$") + pattern.lstrip("^")


def _decorator_guards(d: ast.AST, reader: GuardReader) -> tuple[list[str], list[str]]:
    """The guards and unguards a decorator (or an auth mixin) is, by what it does: the name of
    the decorator itself, never its module's or its arguments' (`extend_schema(request=..)`)."""
    name = _dotted(d).split(".")[-1]
    if name == "method_decorator" and isinstance(d, ast.Call) and d.args:
        inner = d.args[0]
        out = [_decorator_guards(x, reader) for x in _elements(inner)]
        return _unique([g for x, _ in out for g in x]), sorted({u for _, x in out for u in x})
    found = reader.resolve(_dotted(d))
    if "login_not_required" in (name, reader.origin(_dotted(d)).split(".")[-1]) or (
        found is not None and ".login_required = False" in ast.unparse(found)
    ):
        return [], ["login_not_required"]  # what `LoginRequiredMiddleware` exempts
    if _INERT_DECORATORS.match(name) or name in _POLICY_DECORATORS or _NOT_GUARDS.search(name):
        return [], []
    label = _dotted(d)
    if _unguards_in(name):
        return [], [label]
    if isinstance(d, ast.Call) and any(
        k.arg == "optional" and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in d.keywords
    ):
        return [], [f"optional:{label}"]  # `login_required(optional=True)` lets anyone through
    if requires_nothing(d, reader.name(_dotted(d.func)) if isinstance(d, ast.Call) else ""):
        return [], []  # `permission_required([])`: `has_perms(())` admits anyone
    return ([label] if reader.guards(_dotted(d)) else []), []


def _elements(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [
            ast.Name(id=e.value) if isinstance(e, ast.Constant) and isinstance(e.value, str) else e
            for e in node.elts
        ]
    return [node]


def _label(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ast.unparse(node)[:120]


def _allows(node: ast.AST, verb: str, reader: GuardReader) -> str:
    """Whether a permission class refuses an anonymous caller of `verb`: `guard`, `open`, or
    `none` for one whose name says neither. `A | B` is as weak as its weakest side, `A & B` as
    strong as its strongest; `~A` may admit anyone."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr | ast.BitAnd):
        sides = {_allows(node.left, verb, reader), _allows(node.right, verb, reader)}
        order = (
            ("open", "none", "guard")
            if isinstance(node.op, ast.BitOr)
            else ("guard", "none", "open")
        )
        return next(k for k in order if k in sides)
    if isinstance(node, ast.UnaryOp):
        return "open"
    if not isinstance(node, ast.Name | ast.Attribute):
        return "none"  # `[A] if DEBUG else [B]`, `HasScope("x")`: not read
    name = _dotted(node)
    if _ANONYMOUS.match(reader.name(name)) or _unguards_in(name.split(".")[-1]):
        return "open"
    kind = reader.permission(name)
    if kind == "read-only":
        return "open" if verb in _SAFE else "guard"
    return kind


def _permitted(
    permissions: list[ast.AST], verb: str, reader: GuardReader
) -> tuple[list[str], list[str]]:
    """(guards, unguards) of a permission list for one method: DRF requires every class."""
    kinds = [(_label(p), _allows(p, verb, reader)) for p in permissions]
    if any(k == "guard" for _, k in kinds):
        return [label for label, k in kinds if k == "guard"], []
    return [], [label for label, k in kinds if k == "open"]


def _class_key(entry: tuple[str, ast.ClassDef | str]) -> object:
    return id(entry[1]) if isinstance(entry[1], ast.ClassDef) else entry[1]


def _http_method_names(mro: list[tuple[str, ast.ClassDef | str]]) -> set[str] | None:
    """The verbs the nearest checkout `http_method_names` allows; None when no checkout class
    sets it to a literal list (a library's default allows every verb)."""
    for _, c in mro:
        # the class body's last binding of it, annotated or not
        value = next(
            (
                n.value
                for n in reversed(c.body if isinstance(c, ast.ClassDef) else [])
                if isinstance(n, ast.Assign | ast.AnnAssign)
                and any(
                    isinstance(x, ast.Name) and x.id == "http_method_names" for x in _targets(n)
                )
            ),
            None,
        )
        if value is not None:
            literal = isinstance(value, ast.List | ast.Tuple | ast.Set) and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts
            )
            return {s.lower() for s in _strings(value)} if literal else None
    return None


def _drf(origin: str, name: str) -> bool:
    """A DRF library class: imported from rest_framework, or (not imported) named like one."""
    return origin.startswith("rest_framework") or (not origin and bool(_DRF_BASES.search(name)))


def _strings(node: ast.AST | None) -> list[str]:
    return [
        e.value
        for e in getattr(node, "elts", [])
        if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]


def _guards(expr: str) -> list[str]:
    return [g for g in _guards_in(expr) if not _NOT_GUARDS.search(g)]


def _code(node: ast.AST) -> str:
    """A decorator or class attribute's source without its string literals, so a setting's name
    passed as an argument isn't read as a guard's."""
    return " ".join(_dotted(n) for n in ast.walk(node) if isinstance(n, ast.Name | ast.Attribute))


def django_rows(index: _PyIndex, consts: dict[str, str]) -> list[_Row]:
    """The Django and DRF rows of a checkout's parsed Python sources."""
    return _Django(index, consts).run()
