"""Spring MVC/WebFlux and JAX-RS (Quarkus, RESTEasy, Jersey) routes in Java and the guards on
each, parsed with tree-sitter. Guards are method-security annotations,
Spring Security's request-matcher rules (first match wins), Quarkus HTTP permissions, and the
Spring Boot default that authenticates every request when the security starter has no config."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_guards import _guards_in, _mark, _Row, _row, _unique
from traust_core.v1.providers.route_ownership import HandlerFacts, Lookup
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.syntax import java_parser as parser
from traust_core.v1.providers.tree import TreeFile

SPRING_IMPORT = re.compile(r"\borg\.springframework\.web\.bind\.annotation\b")
JAXRS_IMPORT = re.compile(r"\b(?:javax|jakarta)\.ws\.rs\b")
SPRING_MAPPINGS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": None,
}
JAXRS_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
_CONTROLLERS = ("RestController", "Controller")
_GUARD_ANNOTATIONS = (
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "Authenticated",
    "DenyAll",
    "PermissionsAllowed",
)
# Spring enforces these only once method security is enabled; JAX-RS containers enforce them.
_METHOD_SECURITY_ANNOTATIONS = ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed")
_METHOD_SECURITY = re.compile(r"@Enable(?:Global|Reactive)?MethodSecurity\b")
_FILTER_CHAIN = re.compile(
    r"\b(?:SecurityFilterChain|SecurityWebFilterChain|WebSecurityConfigurerAdapter)\b"
)
_SECURITY_STARTER = re.compile(r"spring-boot-starter-security")
_MANIFESTS = ("pom.xml", "build.gradle", "build.gradle.kts")
SPRING_DEFAULT_GUARD = "spring-security:default"
METHOD_SECURITY_OFF = "method-security-not-enabled"
CONDITIONAL_CONFIG = "spring-security:conditional-config"
_MATCHERS = {"requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers", "pathMatchers"}
_ANY = {"anyRequest", "anyExchange"}
_OPEN = {"permitAll", "anonymous"}
_DECISIONS = _OPEN | {
    "denyAll",
    "authenticated",
    "fullyAuthenticated",
    "rememberMe",
    "hasRole",
    "hasAnyRole",
    "hasAuthority",
    "hasAnyAuthority",
    "access",
    "hasIpAddress",
}
_QUARKUS_PERMISSION = re.compile(
    r"^quarkus\.http\.auth\.permission\.([^.]+)\.(paths|policy|methods)$"
)
_QUARKUS_REST_PATH = ("quarkus.rest.path", "quarkus.resteasy.path")
_JAXRS = "quarkus.security.jaxrs"
_TYPE_DECLS = ("class_declaration", "interface_declaration")
_PATH_ANNOTATIONS = ("PathVariable", "PathParam")
_CALLER_TYPES = re.compile(
    r"^(Principal|Authentication|\w*AuthenticationToken|Jwt|OAuth2User|OidcUser|UserDetails|"
    r"SecurityContext|SecurityIdentity|JsonWebToken)$"
)
_CALLER_ANNOTATIONS = ("AuthenticationPrincipal", "CurrentSecurityContext")
_CALLER_CALLS = re.compile(
    r"\b(SecurityContextHolder|getUserPrincipal|getRemoteUser|getCallerPrincipal)\b"
)
_REPOSITORIES = re.compile(r"^\w*(Crud|Jpa|Sorting|Mongo|R2dbc)?Repository(Base)?$|^Panache\w*$")
_ENTITY_MANAGER_LOOKUPS = ("find", "getReference")
_LOOKUP_NAME = re.compile(r"^(find|get|load|fetch|read|delete|remove|exists|lookup|select)")
_AUTHORIZE_NAME = re.compile(r"(?i)^(check|verify|authori[sz]e|assert|ensure|validate|require|can)")
# a value derived from a path id (`new DeviceId(toUUID(id))`, `UUID.fromString(id)`) is that id
_CONVERSION = re.compile(r"(?i)^(to\w*|from\w*|parse\w*|valueOf|of|decode|as\w*|uuid\w*)$")
# method security on the object itself: `#id`, `returnObject`
_OBJECT_SECURITY = re.compile(r"#\w|returnObject|filterObject")


def _name(src: Parsed, ann: Node) -> str:
    return src.text(ann.child_by_field_name("name")).rsplit(".", 1)[-1]


def _annotations(src: Parsed, decl: Node) -> dict[str, Node]:
    mods = next((c for c in decl.named_children if c.type == "modifiers"), None)
    if mods is None:
        return {}
    return {
        _name(src, a): a
        for a in mods.named_children
        if a.type in ("annotation", "marker_annotation")
    }


def _items(node: Node) -> list[Node]:
    if node.type == "element_value_array_initializer":
        return [c for c in node.named_children if c.type != "comment"]
    return [node]


def _attr(src: Parsed, ann: Node, *keys: str) -> list[Node]:
    """An annotation attribute's values; a bare value is `value`."""
    args = ann.child_by_field_name("arguments")
    found: list[Node] = []
    for c in args.named_children if args is not None else []:
        if c.type == "element_value_pair":
            if src.text(c.child_by_field_name("key")) in keys:
                found += _items(c.child_by_field_name("value"))
        elif c.type != "comment" and "value" in keys:
            found += _items(c)
    return found


@dataclass
class _Type:
    src: Parsed
    node: Node
    name: str
    interface: bool
    abstract: bool
    supers: list[str]
    annotations: dict[str, Node]
    methods: dict[str, Node]


def _types(src: Parsed) -> list[_Type]:
    found = []
    for n in walk(src.root):
        if n.type not in _TYPE_DECLS:
            continue
        supers = [
            src.text(t).split("<", 1)[0].rsplit(".", 1)[-1].strip()
            for c in n.named_children
            if c.type in ("superclass", "super_interfaces", "extends_interfaces")
            for t in (
                c.named_children[0].named_children
                if c.named_children and c.named_children[0].type == "type_list"
                else c.named_children
            )
        ]
        body = n.child_by_field_name("body")
        methods = {
            src.text(m.child_by_field_name("name")): m
            for m in (body.named_children if body is not None else [])
            if m.type == "method_declaration"
        }
        mods = next((c for c in n.named_children if c.type == "modifiers"), None)
        found.append(
            _Type(
                src,
                n,
                src.text(n.child_by_field_name("name")),
                n.type == "interface_declaration",
                mods is not None and "abstract" in src.text(mods).split(),
                supers,
                _annotations(src, n),
                methods,
            )
        )
    return found


class _Constants:
    """String constants (`static final String BASE = "/v1"`), by simple and `Class.NAME`."""

    def __init__(self, sources: list[Parsed]) -> None:
        self.values: dict[str, str] = {}
        pending: list[tuple[Parsed, str, Node]] = []
        for src in sources:
            for n in walk(src.root):
                if n.type != "field_declaration":
                    continue
                if src.text(n.child_by_field_name("type")) != "String":
                    continue
                cls = next((p for p in _ancestors(n) if p.type in _TYPE_DECLS), None)
                owner = src.text(cls.child_by_field_name("name")) if cls is not None else ""
                for d in n.named_children:
                    if d.type == "variable_declarator" and d.child_by_field_name("value"):
                        name = src.text(d.child_by_field_name("name"))
                        pending += [(src, name, d.child_by_field_name("value"))]
                        pending += [(src, f"{owner}.{name}", d.child_by_field_name("value"))]
        for _ in range(3):  # constants built from constants
            for src, key, value in pending:
                if key not in self.values and (v := self.resolve(src, value)) is not None:
                    self.values[key] = v

    def resolve(self, src: Parsed, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "string_literal":
            return "".join(src.text(c) for c in node.named_children if c.type == "string_fragment")
        if node.type == "parenthesized_expression" and node.named_children:
            return self.resolve(src, node.named_children[0])
        operator = src.text(node.child_by_field_name("operator"))
        if node.type == "binary_expression" and operator == "+":
            left = self.resolve(src, node.child_by_field_name("left"))
            right = self.resolve(src, node.child_by_field_name("right"))
            return left + right if left is not None and right is not None else None
        if node.type == "identifier":
            return self.values.get(src.text(node))
        if node.type == "field_access":
            owner = src.text(node.child_by_field_name("object")).rsplit(".", 1)[-1]
            return self.values.get(f"{owner}.{src.text(node.child_by_field_name('field'))}")
        return None


def _ancestors(node: Node) -> list[Node]:
    found = []
    while node.parent is not None:
        node = node.parent
        found.append(node)
    return found


def _join(*parts: str) -> str:
    segments = [p.strip("/") for p in parts if p.strip("/")]
    return "/" + "/".join(segments)


def _sample(path: str) -> str:
    """A concrete path a route pattern serves, for matching it against security rules."""
    return re.sub(r"\{[^}]*\}", "x", path)


def _ant(pattern: str) -> re.Pattern[str]:
    out = ""
    for token in re.split(r"(\*\*|\*|\?|\{[^}]*\})", pattern):
        if token == "**":
            out += ".*"
        elif token == "*":
            out += "[^/]*"
        elif token == "?":
            out += "[^/]"
        elif token.startswith("{"):
            out += ".*" if token.startswith("{*") else "[^/]+"
        else:
            out += re.escape(token)
    return re.compile(out.replace("/.*", "(/.*)?") + "/?")


@dataclass
class _Rule:
    patterns: list[re.Pattern[str]] | None  # None: any request
    methods: set[str] | None
    guard: str
    opens: bool

    def matches(self, method: str, path: str) -> bool:
        # a verb-restricted rule only opens, never guards, a route that takes every verb
        if (
            self.methods is not None
            and method not in self.methods
            and not (method == "ALL" and self.opens)
        ):
            return False
        return self.patterns is None or any(p.fullmatch(path) for p in self.patterns)


@dataclass
class _Chain:
    scope: list[re.Pattern[str]] | None
    conditional: bool = False  # its bean exists only under a property or profile
    rules: list[_Rule] = field(default_factory=list)

    def covers(self, path: str) -> bool:
        return self.scope is None or any(p.fullmatch(path) for p in self.scope)


def _matcher_args(
    src: Parsed, consts: _Constants, call: Node
) -> tuple[list[re.Pattern[str]], set[str] | None]:
    args = call.child_by_field_name("arguments")
    patterns: list[re.Pattern[str]] = []
    methods: set[str] = set()
    for a in args.named_children if args is not None else []:
        owner = src.text(a.child_by_field_name("object")) if a.type == "field_access" else ""
        if owner.endswith("HttpMethod"):
            methods.add(src.text(a.child_by_field_name("field")))
            continue
        value = consts.resolve(src, a)
        if value is None:  # new AntPathRequestMatcher("/x"), mvc.pattern("/x")
            strings = (s for s in walk(a) if s.type == "string_literal")
            value = next((consts.resolve(src, s) for s in strings), None)
        if value is not None:
            patterns.append(_ant(value))
    return patterns, methods or None


def _chains(sources: list[Parsed], consts: _Constants) -> list[_Chain]:
    """Spring Security filter chains, the scoped (`securityMatcher`) ones first, each with its
    authorization rules in declaration order."""
    chains: list[_Chain] = []
    for src in sources:
        if not _FILTER_CHAIN.search(src.file.text):
            continue
        for method in (n for n in walk(src.root) if n.type == "method_declaration"):
            calls = sorted(
                (n for n in walk(method) if n.type == "method_invocation"),
                key=lambda n: n.child_by_field_name("name").start_byte,
            )
            cls = next((a for a in _ancestors(method) if a.type == "class_declaration"), None)
            anns = [*_annotations(src, method), *(_annotations(src, cls) if cls else {})]
            chain = _Chain(None, any(a.startswith("Conditional") or a == "Profile" for a in anns))
            for call in calls:
                name = src.text(call.child_by_field_name("name"))
                if name in ("securityMatcher", "securityMatchers", "requestMatcher"):
                    scope, _ = _matcher_args(src, consts, call)
                    chain.scope = (chain.scope or []) + scope
                if name not in _DECISIONS:
                    continue
                target = call.child_by_field_name("object")
                target_name = (
                    src.text(target.child_by_field_name("name"))
                    if (target is not None and target.type == "method_invocation")
                    else ""
                )
                if target_name in _ANY:
                    patterns, methods = None, None
                elif target_name in _MATCHERS:
                    patterns, methods = _matcher_args(src, consts, target)
                    if not patterns and methods is None:
                        continue
                    patterns = patterns or None
                else:
                    continue
                args = src.text(call.child_by_field_name("arguments")).strip("()")[:60]
                chain.rules.append(
                    _Rule(
                        patterns,
                        methods,
                        f"spring-security:{name}" + (f"({args})" if args else ""),
                        name in _OPEN,
                    )
                )
            if chain.rules:
                chains.append(chain)
    return sorted(chains, key=lambda c: c.scope is None)


@dataclass
class _Quarkus:
    permissions: list[tuple[str, set[str] | None, str]] = field(default_factory=list)
    deny_unannotated: bool = False
    default_roles: str | None = None
    prefix: str = ""

    @classmethod
    def of(cls, files: list[TreeFile]) -> _Quarkus:
        props: dict[str, str] = {}
        for f in files:
            if f.name != "application.properties" or "test" in f.parts[:-1]:
                continue
            for raw in f.text.splitlines():
                line = raw.strip()
                if not line or line[0] in "#!" or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().removeprefix("%prod.")
                if not key.startswith("%"):  # other profiles don't run in production
                    props[key] = value.strip()
        sets: dict[str, dict[str, str]] = {}
        for key, value in props.items():
            if m := _QUARKUS_PERMISSION.match(key):
                sets.setdefault(m.group(1), {})[m.group(2)] = value
        found = cls(
            deny_unannotated=props.get(f"{_JAXRS}.deny-unannotated-endpoints") == "true",
            default_roles=props.get(f"{_JAXRS}.default-roles-allowed"),
            prefix=next((props[k] for k in _QUARKUS_REST_PATH if k in props), ""),
        )
        for perm in sets.values():
            if "paths" not in perm or "policy" not in perm:
                continue
            methods = (
                {m.strip().upper() for m in perm["methods"].split(",")}
                if ("methods" in perm)
                else None
            )
            for p in perm["paths"].split(","):
                found.permissions.append((p.strip(), methods, perm["policy"]))
        return found

    def guard(self, method: str, path: str) -> tuple[list[str], list[str]]:
        """(scope guards, unguards) from the most specific HTTP permission covering the path."""
        best: tuple[int, str] | None = None
        for pattern, methods, policy in self.permissions:
            opens_all = method == "ALL" and policy == "permit"
            if methods is not None and method not in methods and not opens_all:
                continue
            exact = not pattern.endswith("*")
            stem = pattern.rstrip("*").rstrip("/")
            if path == pattern if exact else (path == stem or path.startswith(stem + "/")):
                rank = len(stem) * 2 + exact
                if best is None or rank > best[0]:
                    best = (rank, policy)
        if best is None:
            return [], []
        policy = best[1]
        if policy == "permit":
            return [], ["quarkus:permit"]
        return [f"quarkus:{policy}"], []


@dataclass
class _Java:
    sources: list[Parsed]
    manifests: list[TreeFile]
    files: list[TreeFile]
    types: dict[str, list[_Type]] = field(default_factory=dict)
    # controllers whose routes come from an interface not in the checkout (generated at build)
    generated: dict[RouteFamily, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for src in self.sources:
            for t in _types(src):
                self.types.setdefault(t.name, []).append(t)
        self.consts = _Constants(self.sources)
        self.chains = _chains(self.sources, self.consts)
        texts = [s.file.text for s in self.sources]
        self.method_security = any(_METHOD_SECURITY.search(t) for t in texts)
        starter = any(_SECURITY_STARTER.search(m.text) for m in self.manifests)
        self.spring_default = starter and not any(_FILTER_CHAIN.search(t) for t in texts)
        self.quarkus = _Quarkus.of(self.files)
        self.app_path = self._application_path()
        self.fields = _record_fields(self.sources)
        self.repositories = _repository_entities(self.sources)
        self.caller_methods = _caller_methods(self.sources)

    def _application_path(self) -> str:
        paths = {
            v
            for ts in self.types.values()
            for t in ts
            if "ApplicationPath" in t.annotations
            for n in _attr(t.src, t.annotations["ApplicationPath"], "value")
            if (v := self.consts.resolve(t.src, n)) is not None
        }
        return paths.pop() if len(paths) == 1 else ""

    def _hierarchy(self, t: _Type, seen: frozenset[str] = frozenset()) -> list[_Type]:
        """`t`, then its superclasses and interfaces found in the checkout, nearest first."""
        found = [t]
        for name in t.supers:
            if name in seen or name == t.name:
                continue
            for parent in self.types.get(name, [])[:1]:
                found += self._hierarchy(parent, seen | {t.name})
        return found

    def rows(self) -> list[_Row]:
        rows: list[_Row] = []
        for ts in self.types.values():
            for t in ts:
                if not t.interface and not t.abstract:
                    rows += self._resource(t)
        return rows

    def _resource(self, t: _Type) -> list[_Row]:
        chain = self._hierarchy(t)
        if any(c in h.annotations for h in chain for c in _CONTROLLERS) and any(
            SPRING_IMPORT.search(h.src.file.text) for h in chain
        ):
            family = RouteFamily.SPRING
            prefixes = next(
                (
                    self._paths(h, h.annotations["RequestMapping"], "value", "path")
                    for h in chain
                    if "RequestMapping" in h.annotations
                ),
                [("", False)],
            )
        elif any("Path" in h.annotations for h in chain) and any(
            JAXRS_IMPORT.search(h.src.file.text) for h in chain
        ):
            family = RouteFamily.JAX_RS
            prefixes = next(
                (
                    self._paths(h, h.annotations["Path"], "value")
                    for h in chain
                    if "Path" in h.annotations
                ),
                [("", False)],
            )
            prefixes = [(_join(self.quarkus.prefix, self.app_path, p), d) for p, d in prefixes]
        else:
            return []
        if any(name not in self.types for name in t.supers) and any(
            "Override" in _annotations(t.src, m) and self._mapping(family, t, m) is None
            for m in t.methods.values()
        ):
            self.generated.setdefault(family, []).append(t.src.file.rel)
        rows: list[_Row] = []
        done: set[str] = set()
        for owner in chain:
            for name, method in owner.methods.items():
                if name in done:
                    continue
                found = self._mapping(family, owner, method)
                if found is None:
                    continue
                done.add(name)
                verbs, patterns = found
                override = t.methods.get(name) if owner is not t else None
                rows += self._rows(family, t, owner, method, override, verbs, prefixes, patterns)
        return rows

    def _paths(self, t: _Type, ann: Node, *keys: str) -> list[tuple[str, bool]]:
        values = _attr(t.src, ann, *keys)
        if not values:
            return [("", False)]
        out = []
        for v in values:
            resolved = self.consts.resolve(t.src, v)
            out.append((resolved, False) if resolved is not None else (t.src.text(v)[:160], True))
        return out

    def _mapping(
        self, family: RouteFamily, owner: _Type, method: Node
    ) -> tuple[list[str], list[tuple[str, bool]]] | None:
        anns = _annotations(owner.src, method)
        if family is RouteFamily.SPRING:
            name = next((n for n in SPRING_MAPPINGS if n in anns), None)
            if name is None:
                return None
            verb = SPRING_MAPPINGS[name]
            verbs = (
                [verb]
                if verb
                else [
                    owner.src.text(v).rsplit(".", 1)[-1]
                    for v in _attr(owner.src, anns[name], "method")
                ]
                or ["ALL"]
            )
            return verbs, self._paths(owner, anns[name], "value", "path")
        verbs = [v for v in JAXRS_VERBS if v in anns]
        if not verbs:
            return None  # a sub-resource locator, or not a resource method
        paths = self._paths(owner, anns["Path"], "value") if "Path" in anns else [("", False)]
        return verbs, paths

    def _guards(
        self, family: RouteFamily, decls: list[tuple[_Type, Node]]
    ) -> tuple[list[str], list[str]]:
        guards: list[str] = []
        unguards: list[str] = []
        for owner, decl in decls:
            for name, ann in _annotations(owner.src, decl).items():
                if name == "PermitAll":
                    unguards.append("@PermitAll")
                elif name in _GUARD_ANNOTATIONS:
                    args = owner.src.text(ann.child_by_field_name("arguments")).strip("()")[:60]
                    label = f"@{name}" + (f"({args})" if args else "")
                    if "permitAll" in args:
                        unguards.append(label)
                        continue
                    guards.append(label)
                    if (
                        family is RouteFamily.SPRING
                        and name in _METHOD_SECURITY_ANNOTATIONS
                        and not self.method_security
                    ):
                        unguards.append(METHOD_SECURITY_OFF)
        return _unique(guards), sorted(set(unguards))

    def _rows(
        self,
        family: RouteFamily,
        t: _Type,
        owner: _Type,
        method: Node,
        override: Node | None,
        verbs: list[str],
        prefixes: list[tuple[str, bool]],
        patterns: list[tuple[str, bool]],
    ) -> list[_Row]:
        src = owner.src
        name = src.text(method.child_by_field_name("name"))
        decls = [(owner, method)] + ([(t, override)] if override is not None else [])
        guards, unguards = self._guards(family, decls)
        types = [(t, t.node)] + ([(owner, owner.node)] if owner is not t else [])
        scope_guards, scope_unguards = self._guards(family, types)
        annotated = bool(guards or scope_guards or unguards or scope_unguards)
        body = (t.src, override) if override is not None else (src, method)
        guards = _unique([*guards, *_body_guard_calls(*body)])
        facts = _Ownership(self, t).handler(*body, decls)
        rows = []
        for prefix, prefix_dynamic in prefixes:
            for pattern, dynamic in patterns:
                full = _join(prefix, pattern)
                for verb in verbs:
                    g, u = self._config_guards(family, verb, full, annotated)
                    row = _row(
                        family,
                        verb,
                        full,
                        f"{t.name}.{name}",
                        src.file.rel,
                        src.line(method),
                        guards,
                        _unique([*scope_guards, *g]),
                        sorted({*unguards, *scope_unguards, *u}),
                    )
                    _mark(row, None, dynamic or prefix_dynamic, src.file.rel)
                    row.view_class = t.name
                    row.own(facts, self.fields, deploy_time=CONDITIONAL_CONFIG in row.unguards)
                    rows.append(row)
        return rows

    def _config_guards(
        self, family: RouteFamily, verb: str, path: str, annotated: bool
    ) -> tuple[list[str], list[str]]:
        """Scope guards and unguards the security configuration gives a route."""
        if family is RouteFamily.JAX_RS:
            scope, opened = self.quarkus.guard(verb, path)
            if not annotated and self.quarkus.default_roles:
                scope.append("quarkus:default-roles-allowed")
            if not annotated and self.quarkus.deny_unannotated:
                scope.append("quarkus:deny-unannotated-endpoints")
            return scope, opened
        sample = _sample(path)
        covering = [c for c in self.chains if c.covers(sample)]
        if not covering:
            return ([SPRING_DEFAULT_GUARD], []) if self.spring_default else ([], [])
        # which conditional chain runs is decided at deploy time: report what each would do
        candidates = covering if covering[0].conditional else covering[:1]
        scope: list[str] = []
        opened = [CONDITIONAL_CONFIG] if covering[0].conditional else []
        for chain in candidates:
            rule = next((r for r in chain.rules if r.matches(verb, sample)), None)
            if rule is not None:
                (opened if rule.opens else scope).append(rule.guard)
        return _unique(scope), opened


def _record_fields(sources: list[Parsed]) -> dict[str, tuple[str, ...]]:
    """Each class's and record's field names, by simple type name."""
    fields: dict[str, list[str]] = {}
    for src in sources:
        for n in walk(src.root):
            if n.type not in ("class_declaration", "record_declaration"):
                continue
            names = fields.setdefault(src.text(n.child_by_field_name("name")), [])
            if n.type == "record_declaration":
                params = n.child_by_field_name("parameters")
                names += [
                    src.text(p.child_by_field_name("name"))
                    for p in (params.named_children if params else [])
                    if p.type == "formal_parameter"
                ]
            body = n.child_by_field_name("body")
            for f in body.named_children if body else []:
                if f.type == "field_declaration":
                    names += [
                        src.text(d.child_by_field_name("name"))
                        for d in f.named_children
                        if d.type == "variable_declarator"
                    ]
    return {k: tuple(v) for k, v in fields.items()}


def _repository_entities(sources: list[Parsed]) -> dict[str, str]:
    """The entity each checkout repository interface stores (`JpaRepository<Item, Long>`)."""
    found = {}
    for src in sources:
        for n in walk(src.root):
            if n.type not in _TYPE_DECLS:
                continue
            for g in walk(n):
                if g.type == "class_body" or g.type == "interface_body":
                    break
                if g.type != "generic_type" or not g.named_children:
                    continue
                base = src.text(g.named_children[0]).rsplit(".", 1)[-1]
                args = [c for c in g.named_children[1:] if c.type == "type_arguments"]
                if _REPOSITORIES.match(base) and args and args[0].named_children:
                    found[src.text(n.child_by_field_name("name"))] = src.text(
                        args[0].named_children[0]
                    ).split("<", 1)[0]
                    break
    return found


class _Ownership:
    """A handler's ownership facts: its path ids, the caller, lookups by id, checks, one hop."""

    def __init__(self, java: _Java, t: _Type) -> None:
        self.java, self.type = java, t

    def handler(self, src: Parsed, method: Node, decls: list[tuple[_Type, Node]]) -> HandlerFacts:
        params = _params(src, method)
        ids = {name for name, _, anns in params if any(a in anns for a in _PATH_ANNOTATIONS)}
        callers = {n for n, kind, anns in params if _caller(kind, anns)} | self._caller_fields(
            self.type
        )
        check = next(
            (
                self._span(owner.src, ann)
                for owner, decl in decls
                for name, ann in _annotations(owner.src, decl).items()
                if name in ("PreAuthorize", "PostAuthorize")
                and _OBJECT_SECURITY.search(owner.src.text(ann))
            ),
            None,
        )
        facts = self._body(src, self.type, method, ids, callers, hop=True)
        return HandlerFacts(
            lookups=facts.lookups,
            caller=facts.caller,
            check=check,
            hop=facts.hop,
            handoff=facts.handoff,
        )

    def _span(self, src: Parsed, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))

    def _caller_fields(self, t: _Type) -> set[str]:
        names = set()
        for f in t.node.child_by_field_name("body").named_children:
            if f.type != "field_declaration":
                continue
            kind = t.src.text(f.child_by_field_name("type")).split("<", 1)[0]
            if _caller(kind, _annotations(t.src, f)):
                names |= {
                    t.src.text(d.child_by_field_name("name"))
                    for d in f.named_children
                    if d.type == "variable_declarator"
                }
        return names

    def _field_type(self, t: _Type, name: str) -> str | None:
        for f in t.node.child_by_field_name("body").named_children:
            if f.type == "field_declaration" and any(
                d.type == "variable_declarator"
                and t.src.text(d.child_by_field_name("name")) == name
                for d in f.named_children
            ):
                return t.src.text(f.child_by_field_name("type")).split("<", 1)[0]
        return None

    def _body(
        self, src: Parsed, t: _Type, method: Node, ids: set[str], callers: set[str], hop: bool
    ) -> HandlerFacts:
        body = method.child_by_field_name("body")
        if body is None or not ids:
            return HandlerFacts()

        def names(node: Node) -> set[str]:
            return {src.text(n) for n in walk(node) if n.type == "identifier"}

        def is_caller(n: Node) -> bool:
            if n.type == "identifier":
                return src.text(n) in callers
            if n.type != "method_invocation":
                return False
            receiver = src.text(n.child_by_field_name("object"))
            name = src.text(n.child_by_field_name("name"))
            return bool(_CALLER_CALLS.search(src.text(n))) or (
                receiver in ("", "this", "super") and name in self.java.caller_methods
            )

        def calls_caller(node: Node) -> bool:
            return any(is_caller(n) for n in walk(node))

        for d in walk(body):
            value = d.child_by_field_name("value") if d.type == "variable_declarator" else None
            if value is not None and names(value) & ids and _converts(src, value):
                ids = ids | {src.text(d.child_by_field_name("name"))}
        caller = next((self._span(src, n) for n in walk(body) if is_caller(n)), None)
        lookups: list[Lookup] = []
        produced: dict[tuple[int, int], list[int]] = {}  # call span -> the lookups it made
        by_id: dict[str, list[int]] = {}  # path id -> the lookups made with it
        hop_span = handoff = None
        for call in (n for n in walk(body) if n.type == "method_invocation"):
            args = call.child_by_field_name("arguments")
            if args is None or not names(args) & ids:
                continue
            receiver = src.text(call.child_by_field_name("object")).removeprefix("this.")
            name = src.text(call.child_by_field_name("name"))
            start = len(lookups)
            chain = [call]
            while chain[-1].parent is not None and chain[-1].parent.type == "method_invocation":
                chain.append(chain[-1].parent)
            with_caller = calls_caller(args) or any(
                c.child_by_field_name("arguments") is not None
                and calls_caller(c.child_by_field_name("arguments"))
                for c in chain[1:]
            )
            if (
                name in _ENTITY_MANAGER_LOOKUPS
                and args.named_children[:1]
                and (args.named_children[0].type == "class_literal")
            ):
                kind = src.text(args.named_children[0]).removesuffix(".class")
                lookups.append(Lookup(self._span(src, call), with_caller, record_type=kind))
            elif (kind := self.java.repositories.get(self._field_type(t, receiver) or "")) or (
                receiver in self.java.fields and receiver[:1].isupper()
            ):
                if _LOOKUP_NAME.match(name):
                    lookups.append(
                        Lookup(self._span(src, call), with_caller, record_type=kind or receiver)
                    )
            elif (target := self._callee(t, receiver, name)) is not None:
                if not hop:
                    handoff = handoff or self._span(src, call)
                    continue
                hop_span = hop_span or self._span(src, call)
                callee_type, callee = target
                inner = self._hop(src, callee_type, callee, args, ids, callers)
                # handed the caller, and it uses it: to the route, the lookup is scoped
                lookups += [
                    Lookup(x.span, scoped=True, record_type=x.record_type)
                    if with_caller and (x.scoped or x.checked)
                    else x
                    for x in inner.lookups
                ]
                caller = caller or inner.caller
                handoff = handoff or inner.handoff
            elif with_caller and _LOOKUP_NAME.match(name):
                lookups.append(Lookup(self._span(src, call), scoped=True))
            elif with_caller and _AUTHORIZE_NAME.match(name):
                lookups.append(Lookup(self._span(src, call), checked=True))
            elif not receiver[:1].isupper() and _LOOKUP_NAME.match(name):
                lookups.append(Lookup(self._span(src, call)))
            made = list(range(start, len(lookups)))
            produced[(call.start_byte, call.end_byte)] = made
            for used in names(args) & ids:
                by_id.setdefault(used, []).extend(made)
        checked = self._checked(src, body, produced, calls_caller) | {
            i for i, x in enumerate(lookups) if x.scoped or x.checked
        }
        # a scoped lookup or a check against the caller verifies the id: later uses are covered
        checked |= {i for made in by_id.values() if checked & set(made) for i in made}
        return HandlerFacts(
            lookups=tuple(
                Lookup(
                    x.span, x.scoped, x.checked or (i in checked and not x.scoped), x.record_type
                )
                for i, x in enumerate(lookups)
            ),
            caller=caller,
            hop=hop_span,
            handoff=handoff,
        )

    def _checked(
        self,
        src: Parsed,
        body: Node,
        produced: dict[tuple[int, int], list[int]],
        calls_caller: Callable[[Node], bool],
    ) -> set[int]:
        """Lookups whose loaded record a condition compares with the caller."""
        loaded: dict[str, list[int]] = {}
        for d in walk(body):
            value = d.child_by_field_name("value") if d.type == "variable_declarator" else None
            if value is None:
                continue
            made = [i for n in walk(value) for i in produced.get((n.start_byte, n.end_byte), [])]
            if made:
                loaded[src.text(d.child_by_field_name("name"))] = made
        checked: set[int] = set()
        for cond in walk(body):
            if cond.type not in ("if_statement", "ternary_expression"):
                continue
            test = cond.child_by_field_name("condition")
            if test is None or not calls_caller(test):
                continue
            used = {src.text(n) for n in walk(test) if n.type == "identifier"}
            for var, made in loaded.items():
                if var in used:
                    checked.update(made)
        return checked

    def _callee(self, t: _Type, receiver: str, name: str) -> tuple[_Type, Node] | None:
        kind = self._field_type(t, receiver) if receiver not in ("", "this", "super") else t.name
        for candidate in self.java.types.get(kind or "", []):
            for h in self.java._hierarchy(candidate):
                if name in h.methods and not h.interface:
                    return h, h.methods[name]
        return None

    def _hop(
        self, src: Parsed, t: _Type, callee: Node, args: Node, ids: set[str], callers: set[str]
    ) -> HandlerFacts:
        params = [n for n, _, _ in _params(t.src, callee)]
        values = [a for a in args.named_children if a.type != "comment"]
        inner_ids = {
            p
            for p, v in zip(params, values, strict=False)
            if {src.text(n) for n in walk(v) if n.type == "identifier"} & ids
        }
        inner_callers = {
            p
            for p, v in zip(params, values, strict=False)
            if {src.text(n) for n in walk(v) if n.type == "identifier"} & callers
            or _CALLER_CALLS.search(src.text(v))
        } | self._caller_fields(t)
        facts = self._body(t.src, t, callee, inner_ids, inner_callers, hop=False)
        returns = t.src.text(callee.child_by_field_name("type")).split("<", 1)[0]
        record = returns if returns in self.java.fields else None
        return HandlerFacts(
            lookups=tuple(
                Lookup(x.span, x.scoped, x.checked, x.record_type or record) for x in facts.lookups
            ),
            caller=facts.caller,
            handoff=facts.handoff,
        )


def _converts(src: Parsed, value: Node) -> bool:
    """Whether an assigned value is the id itself, converted, rather than something loaded."""
    while value.type in ("cast_expression", "parenthesized_expression"):
        value = value.named_children[-1]
    if value.type in ("identifier", "object_creation_expression"):
        return True
    return value.type == "method_invocation" and bool(
        _CONVERSION.match(src.text(value.child_by_field_name("name")))
    )


def _caller_methods(sources: list[Parsed]) -> frozenset[str]:
    """No-argument helpers that read the caller (`getCurrentUser()`), directly or via another."""
    bodies: dict[str, list[str]] = {}
    for src in sources:
        for m in walk(src.root):
            if m.type != "method_declaration" or m.child_by_field_name("body") is None:
                continue
            params = m.child_by_field_name("parameters")
            if params is not None and params.named_children:
                continue
            bodies.setdefault(src.text(m.child_by_field_name("name")), []).append(
                src.text(m.child_by_field_name("body"))
            )
    found = {n for n, texts in bodies.items() if any(_CALLER_CALLS.search(b) for b in texts)}
    while True:
        more = (
            {
                n
                for n, texts in bodies.items()
                if n not in found
                and any(re.search(rf"\b({'|'.join(found)})\s*\(", b) for b in texts)
            }
            if found
            else set()
        )
        if not more:
            return frozenset(found)
        found |= more


def _params(src: Parsed, method: Node) -> list[tuple[str, str, dict[str, Node]]]:
    """Each parameter's name, type and annotations."""
    params = method.child_by_field_name("parameters")
    return [
        (
            src.text(p.child_by_field_name("name")),
            src.text(p.child_by_field_name("type")).split("<", 1)[0].rsplit(".", 1)[-1],
            _annotations(src, p),
        )
        for p in (params.named_children if params else [])
        if p.type == "formal_parameter"
    ]


def _caller(kind: str, annotations: dict[str, Node]) -> bool:
    return bool(_CALLER_TYPES.match(kind)) or any(a in annotations for a in _CALLER_ANNOTATIONS)


def _body_guard_calls(src: Parsed, method: Node) -> list[str]:
    """Guard-shaped calls a handler makes as bare statements of its own body."""
    body = method.child_by_field_name("body")
    names = [
        src.text(stmt.named_children[0].child_by_field_name("name"))
        for stmt in (body.named_children if body is not None else [])
        if stmt.type == "expression_statement"
        and stmt.named_children
        and stmt.named_children[0].type == "method_invocation"
    ]
    return [f"call:{n}" for n in _guards_in(" ".join(names))]


@dataclass
class JavaRoutes:
    rows: list[_Row]
    evidence: dict[RouteFamily, str]  # a file per family that imports its annotations
    parsed: bool  # whether the Java parser was available
    generated: dict[RouteFamily, list[str]]


def java_rows(files: list[TreeFile]) -> JavaRoutes:
    """The Spring and JAX-RS rows of a checkout, with what route_guards needs to name gaps."""
    java = [f for f in files if f.path.suffix == ".java"]
    evidence: dict[RouteFamily, str] = {}
    for f in java:
        for family, rx in ((RouteFamily.SPRING, SPRING_IMPORT), (RouteFamily.JAX_RS, JAXRS_IMPORT)):
            if family not in evidence and rx.search(f.text):
                evidence[family] = f.rel
    if not evidence:
        return JavaRoutes([], {}, True, {})
    available = parser()
    if available is None:
        return JavaRoutes([], evidence, False, {})
    sources = []
    for f in java:
        data = f.text.encode("utf-8")
        sources.append(Parsed(f, available.parse(data).root_node, data))
    manifests = [f for f in files if f.name in _MANIFESTS]
    java_index = _Java(sources, manifests, files)
    return JavaRoutes(java_index.rows(), evidence, True, java_index.generated)
