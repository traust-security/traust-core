"""Ownership of the object a FastAPI id route acts on, read from its handler, its dependencies and
the same-repository functions they call. Protection counts only from allow-listed shapes (D8)."""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    OWNER_FIELD_RX,
    HandlerFacts,
    Lookup,
)

_Def = ast.FunctionDef | ast.AsyncFunctionDef
_Pos = tuple[int, int]

# record bases a model inherits nothing ownership-relevant from, unless the checkout defines them
_FRAMEWORK_BASES = {
    "BaseModel",
    "SQLModel",
    "Base",
    "DeclarativeBase",
    "TypedDict",
    "Generic",
    "object",
    "Enum",
    "StrEnum",
    "IntEnum",
}
# a query constructor, the methods narrowing it, the links that widen it, and the fetches that
# return a row (None, or a raise, when nothing matched)
_QUERY_ROOTS = {"select", "update", "delete", "insert", "query"}
_QUERY_NARROWING = {"where", "filter", "filter_by"}
_QUERY_WIDENING = {
    "join",
    "outerjoin",
    "join_from",
    "union",
    "union_all",
    "except_",
    "except_all",
    "intersect",
    "intersect_all",
    "select_from",
    "from_statement",
    "correlate",
}
_FETCH_OR_RAISE = {"one", "scalar_one", "one_or_404", "first_or_404", "get_or_404"}
_FETCH = {"first", "one_or_none", "scalar_one_or_none", "scalar", "get", *_FETCH_OR_RAISE}
_LOOKUP_NAME = re.compile(
    r"^(get|find|fetch|load|read|lookup|select|query|search|retrieve|delete|remove|pop|update)"
    r"(_|$)"
)
# a second hop only into an authorization-shaped helper (never credited by its name)
_AUTHORIZE_NAME = re.compile(
    r"^(check|verify|authori[sz]e|assert|ensure|require|validate|enforce|can|has|is|owns)(_|$)"
)
# a check of the id's form, presumed not to act on the object
_VALIDATOR_NAME = re.compile(
    r"^(validate|check|verify|assert|ensure|require)(_(id|ids|uuid|param|params|arg|args|format"
    r"|length|size|range|positive|input|not_none|not_null|not_empty))?$"
)
_CONVERSIONS = {"int", "str", "UUID", "uuid.UUID", "ObjectId", "bytes"}
_INERT = re.compile(r"^(print|len|repr|isinstance|logger|log|logging|LOG|warnings)(\.|$)")
_THROWN = re.compile(r"(Exception|Error)$")
# a caller flag whose holders may act on any record (owner decision 2026-11-02)
_PRIVILEGE_FLAG = re.compile(r"^(is_)?(superuser|admin|staff)$")
_MUTATORS = re.compile(r"^(set\w*|update|pop|clear|setdefault|__setitem__)$")
_SETATTR = {"setattr", "object.__setattr__"}
_FOREIGN_KEY = re.compile(r"""["']([A-Za-z_]\w*)\.\w+["']""")
_MAX_DEPTH = 64


class _Imports(Protocol):
    """route_guards' module index: what each file imports, and which file a module is."""

    imported: dict[str, dict[str, str]]

    def file(self, module: str) -> str | None: ...


def _pos(node: ast.AST) -> _Pos:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _end(node: ast.AST) -> _Pos:
    return (getattr(node, "end_lineno", 0) or 0, getattr(node, "end_col_offset", 0) or 0)


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _unawait(node: ast.AST | None) -> ast.AST | None:
    while isinstance(node, ast.Await):
        node = node.value
    return node


def _names(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node is not None else set()


def _own(fn: ast.AST) -> Iterator[ast.AST]:
    """The nodes of `fn`'s own scope: nested definitions are yielded, their bodies are not."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            stack.extend(ast.iter_child_nodes(node))


def returns_id(fn: _Def, ids: set[str]) -> bool:
    """Whether `fn` returns (or yields) the id itself, or a value built from it (`return
    item_id`, `return int(item_id)`); never a record loaded by it (`session.get(Item, item_id)`)."""
    tainted = set(ids)

    def carries(value: ast.AST) -> bool:
        return bool(_names(value) & tainted) and not any(
            (isinstance(n, ast.Call) and _dotted(n.func) not in _CONVERSIONS and _values(n))
            or isinstance(n, ast.Subscript)
            for n in ast.walk(value)
        )

    for n in sorted((n for n in _own(fn) if isinstance(n, ast.Assign | ast.AnnAssign)), key=_pos):
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        if n.value is not None and carries(n.value):
            tainted |= {x.id for t in targets for x in ast.walk(t) if isinstance(x, ast.Name)}
    return any(
        isinstance(n, ast.Return | ast.Yield) and n.value is not None and carries(n.value)
        for n in _own(fn)
    )


def _call_name(call: ast.Call) -> str:
    return call.func.attr if isinstance(call.func, ast.Attribute) else _dotted(call.func)


def _values(call: ast.Call) -> list[ast.AST]:
    return [*call.args, *(k.value for k in call.keywords)]


def _params(fn: _Def) -> list[str]:
    a = fn.args
    return [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]


def _type_names(node: ast.AST | None) -> set[str]:
    """The names an annotation or value mentions, quoted ones included (`list["Item"]`)."""
    return set(re.findall(r"[A-Za-z_]\w*", ast.unparse(node))) if node is not None else set()


def _raises_only(body: list[ast.stmt]) -> bool:
    return len(body) == 1 and isinstance(body[0], ast.Raise)


def _is_none(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _none_test(test: ast.AST, record: str, *, present: bool) -> bool:
    """`record is None` / `not record` (or, `present`, `record is not None` / `record`)."""
    if not present and isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return isinstance(test.operand, ast.Name) and test.operand.id == record
    if present and isinstance(test, ast.Name):
        return test.id == record
    ops = (ast.IsNot, ast.NotEq) if present else (ast.Is, ast.Eq)
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ops)
        and isinstance(test.left, ast.Name)
        and test.left.id == record
        and _is_none(test.comparators[0])
    )


def _refuses_absence(stmt: ast.stmt, record: str) -> bool:
    """`if record is None: raise …` and nothing else."""
    return (
        isinstance(stmt, ast.If)
        and not stmt.orelse
        and _raises_only(stmt.body)
        and _none_test(stmt.test, record, present=False)
    )


def _parts(node: ast.AST, op: type) -> list[ast.AST]:
    return list(node.values) if isinstance(node, ast.BoolOp) and isinstance(node.op, op) else [node]


def _assigned_name(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        target = stmt.targets[0]
        return target.id if isinstance(target, ast.Name) else None
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


# ---- the checkout's code, resolved exactly


@dataclass
class _Module:
    rel: str
    funcs: dict[str, list[_Def]] = field(default_factory=dict)
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)  # `service = Service()`: its ctor
    containers: dict[str, str] = field(default_factory=dict)  # `_ITEMS: dict[int, Item]`
    stores: set[str] = field(default_factory=set)  # every module-level dict


@dataclass(frozen=True)
class Target:
    """A checkout function a call runs; `method`: its first parameter (`self`) isn't passed."""

    rel: str
    fn: _Def
    method: bool = False
    cls: ast.ClassDef | None = None


@dataclass(frozen=True)
class Opaque:
    """A dependency the reader can't follow; `params`: the names it takes, None when unknown."""

    span: CodeSpan
    params: frozenset[str] | None


class PyCode:
    """The parsed checkout: per file its module-level functions, classes, instances and typed
    containers; and the record classes with their fields (for the shared classification)."""

    def __init__(
        self, trees: dict[str, ast.Module], imports: _Imports, texts: dict[str, str]
    ) -> None:
        self.imports, self.texts = imports, texts
        self.by_rel: dict[str, _Module] = {}
        for rel, tree in trees.items():
            m = self.by_rel.setdefault(rel, _Module(rel))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    m.funcs.setdefault(node.name, []).append(node)
                elif isinstance(node, ast.ClassDef):
                    m.classes[node.name] = node
                elif isinstance(node, ast.Assign | ast.AnnAssign):
                    self._module_assign(m, node)
        self.class_rel = {id(c): m.rel for m in self.by_rel.values() for c in m.classes.values()}
        self.fields, self.records = self._record_fields()
        for m in self.by_rel.values():
            m.containers = {n: v for n, v in m.containers.items() if v in self.records}
        self.scans: dict[tuple, _Scan] = {}

    def _module_assign(self, m: _Module, node: ast.Assign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if isinstance(node.value, ast.Call) and (kind := _dotted(node.value.func)):
            m.instances.update(dict.fromkeys(names, kind))
        if isinstance(node.value, ast.Dict) or (
            isinstance(node.value, ast.Call)
            and _dotted(node.value.func).rsplit(".", 1)[-1]
            in ("dict", "defaultdict", "OrderedDict")
        ):
            m.stores.update(names)
        if isinstance(node, ast.AnnAssign) and isinstance(node.annotation, ast.Subscript):
            outer = _dotted(node.annotation.value).rsplit(".", 1)[-1]
            args = node.annotation.slice
            elts = args.elts if isinstance(args, ast.Tuple) else [args]
            if outer in ("dict", "Dict", "Mapping", "MutableMapping"):
                m.stores.update(names)
            if outer in ("dict", "Dict", "Mapping", "MutableMapping") and len(elts) == 2:
                inner = _type_names(elts[1]) - {"Optional", "None"}
                if len(inner) == 1:
                    m.containers.update(dict.fromkeys(names, next(iter(inner))))

    def _record_fields(self) -> tuple[dict[str, tuple[str, ...]], set[str]]:
        """Fields per class, inherited ones included. As on the Java side, a class that may be
        owned through another is left out unless it names an owner itself: an unknown base, a
        field holding or held by another class, subclasses, a foreign key or `<name>_id` pointing
        at it; and a class whose fields we can't read (`__table__ = Table(…)`, none at all)."""
        defs: dict[str, list[ast.ClassDef]] = {}
        for m in self.by_rel.values():
            for name, c in m.classes.items():
                defs.setdefault(name, []).append(c)
        own: dict[str, list[str]] = {}
        held: dict[str, set[str]] = {}
        bases: dict[str, list[str]] = {}
        tables: dict[str, str] = {}
        unreadable: set[str] = set()
        pointed: set[str] = set()
        for name, cs in defs.items():
            if len(cs) > 1:
                continue  # two classes of one name can't be told apart
            names: list[str] = []
            types: set[str] = set()
            for stmt in cs[0].body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    names.append(stmt.target.id)
                    types |= _type_names(stmt.annotation) | _type_names(stmt.value)
                elif isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if not isinstance(t, ast.Name):
                            continue
                        if t.id == "__table__":
                            unreadable.add(name)
                        elif t.id == "__tablename__" and isinstance(stmt.value, ast.Constant):
                            tables[name] = str(stmt.value.value)
                        elif not t.id.startswith("__"):
                            names.append(t.id)
                            types |= _type_names(stmt.value)
                elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    # attributes a method sets on the instance (`self.owner_id = …`)
                    names += [
                        t.attr
                        for n in ast.walk(stmt)
                        if isinstance(n, ast.Assign)
                        for t in n.targets
                        if isinstance(t, ast.Attribute) and _dotted(t.value) == "self"
                    ]
                if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    pointed |= {
                        m.group(1).replace("_", "").lower()
                        for n in ast.walk(stmt)
                        if isinstance(n, ast.Constant) and isinstance(n.value, str)
                        for m in [_FOREIGN_KEY.fullmatch(f'"{n.value}"')]
                        if m
                    }
            own[name], held[name] = names, types
            bases[name] = [_dotted(b).rsplit(".", 1)[-1] for b in cs[0].bases]
        records = set(own)
        pointed |= {
            re.sub(r"_?id$", "", f, flags=re.I).replace("_", "").lower()
            for names in own.values()
            for f in names
            if re.search(r"_id$|(?<=[a-z])Id$", f)
        }
        parents = {b for bs in bases.values() for b in bs}
        held_by_others = {k for n, ts in held.items() for k in ts if k != n and k in records}
        memo: dict[str, tuple[list[str], set[str]] | None] = {}

        def full(name: str, seen: frozenset[str]) -> tuple[list[str], set[str]] | None:
            if name in memo:
                return memo[name]
            if len(seen) > _MAX_DEPTH:
                return None  # too deep to read: never taken for ownerless
            names, types = list(own[name]), set(held[name])
            result: tuple[list[str], set[str]] | None = (names, types)
            for b in bases[name]:
                if b not in own and b in _FRAMEWORK_BASES:
                    continue
                inherited = full(b, seen | {name}) if b in own and b not in seen else None
                if inherited is None:
                    result = None
                    break
                names += inherited[0]
                types |= inherited[1]
            memo[name] = result
            return result

        out: dict[str, tuple[str, ...]] = {}
        for name in own:
            resolved = full(name, frozenset())
            names = resolved[0] if resolved else own[name]
            linked = (
                resolved is None
                or not names
                or name in unreadable
                or bool(resolved[1] & (records - {name}))
                or name in held_by_others
                or name in parents
                or name.lower() in pointed
                or tables.get(name, "").replace("_", "").lower() in pointed
            )
            if any(OWNER_FIELD_RX.match(f) for f in names) or not linked:
                out[name] = tuple(names)
        return out, records

    def _imported(self, rel: str, root: str) -> str | None:
        return self.imports.imported.get(rel, {}).get(root)

    def _module(self, dotted: str) -> _Module | None:
        return self.by_rel.get(self.imports.file(dotted) or "") if dotted else None

    def class_def(self, rel: str, text: str) -> ast.ClassDef | None:
        """The checkout class a dotted name refers to from `rel`, through its imports."""
        parts = text.split(".") if text else []
        m = self.by_rel.get(rel)
        if len(parts) == 1:
            if m and parts[0] in m.classes:
                return m.classes[parts[0]]
            target = self._imported(rel, parts[0])
            if target is None:
                return None
            mod, _, name = target.rpartition(".")
        elif parts and (root := self._imported(rel, parts[0])) is not None:
            mod, name = ".".join([root, *parts[1:-1]]), parts[-1]
        else:
            return None
        where = self._module(mod)
        return where.classes.get(name) if where else None

    def _instance(self, rel: str, text: str) -> tuple[str, str] | None:
        """The module and constructor of a module-level instance a name refers to."""
        parts = text.split(".")
        m = self.by_rel.get(rel)
        if len(parts) == 1:
            if m and parts[0] in m.instances:
                return rel, m.instances[parts[0]]
            target = self._imported(rel, parts[0])
            if target is None:
                return None
            mod, _, name = target.rpartition(".")
        elif (root := self._imported(rel, parts[0])) is not None:
            mod, name = ".".join([root, *parts[1:-1]]), parts[-1]
        else:
            return None
        owner = self._module(mod)
        return (owner.rel, owner.instances[name]) if owner and name in owner.instances else None

    def instance_class(self, rel: str, expr: ast.AST | None) -> ast.ClassDef | None:
        """The checkout class of the module-level instance an expression names."""
        found = self._instance(rel, _dotted(expr)) if _dotted(expr) else None
        return self.class_def(found[0], found[1]) if found else None

    def _functions(self, rel: str, text: str) -> list[Target] | None:
        """The functions a dotted name may be from `rel`: module functions, a class's or a
        module-level instance's methods. None when it names none."""
        parts = text.split(".")
        m = self.by_rel.get(rel)
        if len(parts) == 1:
            if m and parts[0] in m.funcs:
                return [Target(rel, f) for f in m.funcs[parts[0]]]
            target = self._imported(rel, parts[0])
            if target is None:
                return None
            mod, _, name = target.rpartition(".")
            where = self._module(mod)
            return (
                [Target(where.rel, f) for f in where.funcs.get(name, [])] or None if where else None
            )
        holder, name = ".".join(parts[:-1]), parts[-1]
        if (root := self._imported(rel, parts[0])) is not None and (
            where := self._module(".".join([root, *parts[1:-1]]))
        ):
            return [Target(where.rel, f) for f in where.funcs.get(name, [])] or None
        cls = self.class_def(rel, holder)
        if cls is not None:
            return self._methods(cls, name, static=True)
        inst = self._instance(rel, holder)
        if inst is not None and (cls := self.class_def(inst[0], inst[1])) is not None:
            return self._methods(cls, name)
        return None

    def _methods(
        self, cls: ast.ClassDef, name: str, *, static: bool = False
    ) -> list[Target] | None:
        """`cls.name`, in the class or its checkout bases, nearest first; `static`: called on the
        class, so only static and class methods skip a parameter."""
        c: ast.ClassDef | None = cls
        seen: set[int] = set()
        while c is not None and id(c) not in seen:
            seen.add(id(c))
            rel = self.class_rel.get(id(c), "")
            found = [
                s
                for s in c.body
                if isinstance(s, ast.FunctionDef | ast.AsyncFunctionDef) and s.name == name
            ]
            if found:
                decos = {_dotted(d) for d in found[0].decorator_list}
                bound = "classmethod" in decos or not (static or "staticmethod" in decos)
                return [Target(rel, f, bound, c) for f in found]
            c = next(
                (x for b in c.bases if (x := self.class_def(rel, _dotted(b))) is not None), None
            )
        return None

    def text(self, rel: str) -> str:
        return self.texts.get(rel, "")

    def record(self, rel: str, expr: ast.AST | None) -> str | None:
        """The record class an expression names from `rel` (`Item`, `models.Item`)."""
        c = self.class_def(rel, _dotted(expr)) if _dotted(expr) else None
        return c.name if c is not None and c.name in self.records else None

    def container(self, rel: str, expr: ast.AST | None) -> str | None:
        """The record a typed module-level container holds (`_ITEMS: dict[int, Item]`)."""
        parts = _dotted(expr).split(".") if _dotted(expr) else []
        if len(parts) == 1 and (m := self.by_rel.get(rel)) and parts[0] in m.containers:
            return m.containers[parts[0]]
        if not parts or (root := self._imported(rel, parts[0])) is None:
            return None
        mod, _, name = ".".join([root, *parts[1:]]).rpartition(".")
        m = self._module(mod)
        return m.containers.get(name) if m is not None else None

    def is_store(self, rel: str, expr: ast.AST | None) -> bool:
        """A module-level dict (`_ITEMS = {}`), from `rel` or imported."""
        parts = _dotted(expr).split(".") if _dotted(expr) else []
        if len(parts) == 1 and (m := self.by_rel.get(rel)) and parts[0] in m.stores:
            return True
        if not parts or (root := self._imported(rel, parts[0])) is None:
            return False
        mod, _, name = ".".join([root, *parts[1:]]).rpartition(".")
        m = self._module(mod)
        return m is not None and name in m.stores

    def functions(
        self, rel: str, expr: ast.AST | None, cls: ast.ClassDef | None
    ) -> list[Target] | None:
        """The checkout functions `expr` names: [] when none, None when ambiguous."""
        text = _dotted(expr)
        if not text:
            return []
        head, _, tail = text.partition(".")
        if head in ("self", "cls") and tail and "." not in tail:
            found = self._methods(cls, tail) if cls is not None else None
        else:
            found = self._functions(rel, text)
        if not found:
            return []
        real = [
            t
            for t in found
            if not any(_dotted(d).endswith("overload") for d in t.fn.decorator_list)
        ]
        return None if len(real) > 1 else real

    def dependency(self, rel: str, expr: ast.AST | None) -> list[Target] | Opaque | None:
        """What a `Depends(...)` target runs: one function; an Opaque when it is checkout code we
        don't follow (a class, an instance, an ambiguous name); None when it isn't checkout code."""
        span = CodeSpan(path=RepoPath(rel), line=getattr(expr, "lineno", 1))
        node = _unawait(expr)
        cls = None
        if isinstance(node, ast.Call):
            cls = self.class_def(rel, _dotted(node.func))
            entry = "__call__"
        elif (cls := self.class_def(rel, _dotted(node))) is not None:
            entry = "__init__"
        elif (cls := self.instance_class(rel, node)) is not None:
            entry = "__call__"
        if cls is not None:
            where = self.class_rel.get(id(cls), rel)
            if "path_params" in self.text(where):
                return Opaque(span, None)  # it may read any path id off the request
            methods = self._methods(cls, entry) or []
            names = {p for t in methods for p in _params(t.fn)} - {"self", "cls"}
            return Opaque(span, frozenset(names))
        found = self.functions(rel, node, None)
        if found is None:
            return Opaque(span, None)  # two definitions of one name
        return found or None


# ---- one function body


@dataclass
class _Scan:
    facts: HandlerFacts
    verified: set[str] = field(default_factory=set)  # parameters verified before any return
    owned_or_null: set[str] = field(default_factory=set)  # parameters returned only if owned
    covers: tuple[set[str] | None, ...] = ()
    reads: tuple[bool, ...] = ()
    handoff_cover: set[str] | None = None
    pure_read: bool = False


class _Values:
    """Which values in one function come from the caller alone. `roots`: the callers the
    function is handed (not locals derived from them)."""

    def __init__(self, callers: set[str], requests: set[str], params: set[str]) -> None:
        self.callers, self.requests, self.params = set(callers), set(requests), params
        self.roots = set(callers)

    def bind(self, fn: _Def) -> None:
        """Adds caller-only locals bound once; drops any caller or request rebound or mutated,
        directly or through a local bound from it."""
        bound: dict[str, list[ast.AST | None]] = {}
        other: set[str] = set()
        mutated: set[str] = set()

        def root(target: ast.AST) -> None:
            while isinstance(target, ast.Attribute | ast.Subscript):
                target = target.value
            if isinstance(target, ast.Call) and _dotted(target.func) == "vars" and target.args:
                target = target.args[0]
            if isinstance(target, ast.Name):
                mutated.add(target.id)

        for n in _own(fn):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        bound.setdefault(t.id, []).append(n.value)
                    else:
                        other |= {x.id for x in ast.walk(t) if isinstance(x, ast.Name)}
                        root(t)
            elif (
                isinstance(n, ast.AnnAssign)
                and isinstance(n.target, ast.Name)
                and n.value is not None
            ):
                bound.setdefault(n.target.id, []).append(n.value)
            elif isinstance(n, ast.AugAssign | ast.For | ast.AsyncFor | ast.NamedExpr):
                other |= _names(n.target)
                root(n.target)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                other |= _names(n.optional_vars)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                other.add(n.name)
            elif isinstance(n, ast.comprehension):
                other |= _names(n.target)
            elif isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                other.add(n.name)  # a nested definition rebinds its name
            elif isinstance(n, ast.Global | ast.Nonlocal):
                other |= set(n.names)
            elif isinstance(n, ast.Delete):
                for t in n.targets:
                    other |= _names(t)
            elif isinstance(n, ast.Call) and _dotted(n.func) in _SETATTR and n.args:
                root(n.args[0])
            elif (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and _MUTATORS.match(n.func.attr)
            ):
                root(n.func.value)
        # a local bound from a caller shares its object: writing it writes the caller
        for name in list(mutated & set(bound)):
            for v in bound[name]:
                mutated |= _names(v)
        self.requests -= set(bound) | other | mutated
        base = self.callers - set(bound) - other - mutated
        self.roots &= base
        found: set[str] = set()
        while True:
            self.callers = base | found
            more = {
                n
                for n, values in bound.items()
                if n not in found | other | mutated | self.params
                and len(values) == 1
                and self.derived(values[0])
            }
            if not more:
                return
            found |= more

    def is_caller(self, node: ast.AST, *, rooted: bool = False) -> bool:
        """A caller variable (`rooted`: only one handed in), or `request.user`."""
        if isinstance(node, ast.Name):
            return node.id in (self.roots if rooted else self.callers)
        # `request.user`, set by Starlette's authentication middleware
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "user"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.requests
        )

    def derived(self, node: ast.AST | None, depth: int = 0) -> bool:
        """`current_user.id`, `user["team"]`, `str(user.id)`, `f"t:{user.id}"`: built only from
        the caller and literals (never a fallback, a conditional or another input)."""
        node = _unawait(node)
        if node is None or depth > _MAX_DEPTH:
            return False  # too deep to read: not the caller
        if self.is_caller(node):
            return True
        if isinstance(node, ast.Attribute):
            return self.derived(node.value, depth + 1)
        if isinstance(node, ast.Subscript):
            return isinstance(node.slice, ast.Constant) and self.derived(node.value, depth + 1)
        if isinstance(node, ast.Call):
            values = _values(node)
            return (
                _dotted(node.func) in _CONVERSIONS
                and len(values) == 1
                and self.derived(values[0], depth + 1)
            )
        if isinstance(node, ast.JoinedStr):
            parts = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
            return bool(parts) and all(self.derived(v, depth + 1) for v in parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            sides = [node.left, node.right]
            return any(self.derived(s, depth + 1) for s in sides) and all(
                isinstance(s, ast.Constant) or self.derived(s, depth + 1) for s in sides
            )
        return False


class _Walk:
    """One function body: its lookups by id, hand-offs, and the ids each allow-listed statement
    directly in the body verifies from its end on."""

    def __init__(
        self,
        o: PyOwnership,
        target: Target,
        ids: set[str],
        callers: set[str],
        requests: set[str],
        depth: int,
        verified: set[str],
    ) -> None:
        self.o, self.code, self.rel, self.fn = o, o.code, target.rel, target.fn
        self.cls, self.depth = target.cls, depth
        self.params = set(_params(self.fn))
        self.v = _Values(callers, requests, self.params)
        self.v.bind(self.fn)
        self.parents = {id(c): n for n in ast.walk(self.fn) for c in ast.iter_child_nodes(n)}
        # each id name and the path id it holds exactly; a value merely built from one, or a
        # name bound more than once (a parameter counts as bound), holds an id of its own
        self.root = {i: i for i in ids}
        bindings: dict[str, int] = dict.fromkeys(self.params, 1)
        binders = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor, ast.NamedExpr)
        for n in sorted((n for n in _own(self.fn) if isinstance(n, binders)), key=_pos):
            if isinstance(n, ast.AnnAssign) and n.value is None:
                continue  # `user: User` binds nothing
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            value = n.iter if isinstance(n, ast.For | ast.AsyncFor) else n.value
            simple = isinstance(n, ast.Assign | ast.AnnAssign)
            for t in targets:
                for x in (x for x in ast.walk(t) if isinstance(x, ast.Name)):
                    bindings[x.id] = bindings.get(x.id, 0) + 1
                    if (
                        value is not None
                        and _names(value) & set(self.root)
                        and not self.loads(value)
                    ):
                        exact = self.exact(value) if simple and t is x else None
                        self.root[x.id] = exact or x.id
        moved = {n for n, c in bindings.items() if c > 1}
        for n in moved & set(self.root):
            self.root[n] = n
        self.ids = set(self.root)
        self.unstable = moved & self.ids
        self.lookups: list[Lookup] = []
        self.cover: list[set[str] | None] = []
        self.starts: list[_Pos] = []
        self.reads: list[bool] = []
        self.made: dict[int, list[int]] = {}  # id(node) -> the lookups it made
        self.query_lookups: set[int] = set()
        self.queries: dict[str, int] = {}  # a local holding a query -> its lookup
        self.consumed: set[int] = set()
        self.hop_verified: dict[int, set[str]] = {}
        self.hop_owned: dict[int, set[str]] = {}
        self.handoffs: list[tuple[CodeSpan, set[str] | None, _Pos]] = []
        self.hop: CodeSpan | None = None
        self.caller = next((self.span(n) for n in _own(self.fn) if self.v.is_caller(n)), None)
        # local functions and classes: their bodies run only when called (or instantiated)
        self.nested = {
            n.name: n
            for n in _own(self.fn)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        }
        self.verified: dict[str, _Pos] = dict.fromkeys(verified & self.ids, (0, 0))
        self.owned_or_null: dict[str, _Pos] = {}

    def span(self, node: ast.AST) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.rel), line=getattr(node, "lineno", 1))

    def exact(self, node: ast.AST | None) -> str | None:
        """The path id a value is exactly: the id, or a conversion of it (`int(id)`, `UUID(id)`)."""
        node = _unawait(node)
        if isinstance(node, ast.Name):
            return self.root.get(node.id)
        if isinstance(node, ast.Call) and _dotted(node.func) in _CONVERSIONS:
            values = _values(node)
            return self.exact(values[0]) if len(values) == 1 else None
        return None

    def exact_ids(self, values: list[ast.AST]) -> set[str] | None:
        roots = [self.exact(v) for v in values if _names(v) & self.ids]
        return None if not roots or None in roots else {r for r in roots if r}

    def loads(self, value: ast.AST) -> bool:
        """Whether a value is (or wraps) a call or subscript that may load something by an id."""
        ids = set(self.root)
        for n in ast.walk(value):
            if (
                isinstance(n, ast.Call)
                and _dotted(n.func) not in _CONVERSIONS
                and any(_names(a) & ids for a in _values(n))
            ):
                return True
            if isinstance(n, ast.Subscript) and _names(n.slice) & ids:
                return True
        return False

    def add(self, node: ast.AST, lookup: Lookup, *, read: bool, cover: set[str] | None) -> int:
        k = len(self.lookups)
        self.lookups.append(lookup)
        self.cover.append(cover)
        self.starts.append(_pos(node))
        self.reads.append(read)
        self.made.setdefault(id(node), []).append(k)
        return k

    def handoff(self, node: ast.AST, cover: set[str] | None) -> None:
        self.handoffs.append((self.span(node), cover, _pos(node)))

    def verify(self, roots: set[str], at: _Pos) -> None:
        for r in roots - self.unstable:
            self.verified[r] = min(at, self.verified.get(r, at))

    # ---- the walk
    def run(self) -> _Scan:
        # what the function itself runs: a nested function's body runs only when it is called
        nodes = sorted(
            (n for n in _own(self.fn) if isinstance(n, ast.Call | ast.Subscript)), key=_pos
        )
        # query roots first, so a chain (`select(M).where(…)`) is read as one query
        for n in nodes:
            if isinstance(n, ast.Call) and (record := self.query_record(n)):
                self.query(n, record)
        for n in nodes:
            if isinstance(n, ast.Call):
                self.call(n)
            else:
                self.subscript(n)
        body = [
            s
            for s in self.fn.body
            if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            and not isinstance(s, ast.Pass)
        ]
        # caller-only declarations, which can't act on a record, may sit before its check
        following: list[list[ast.stmt]] = [[] for _ in body]
        after: list[ast.stmt] = []
        for k in range(len(body) - 1, -1, -1):
            following[k] = after
            if not self.caller_declaration(body[k]):
                after = [body[k], *after[:1]]
        for stmt, nxt in zip(body, following, strict=True):
            self.statement(stmt, nxt)
        returns = [
            s
            for s in body
            if isinstance(s, ast.Return) or any(isinstance(n, ast.Return) for n in _own(s))
        ]
        return self.result(_pos(returns[0]) if returns else None, self.pure_read(body))

    def query_record(self, call: ast.Call) -> str | None:
        """`select(Item)`, `session.query(Item)`, `delete(Item)`: the record a query reads."""
        if _call_name(call) not in _QUERY_ROOTS or not call.args:
            return None
        return self.code.record(self.rel, call.args[0])

    def chain(self, call: ast.Call) -> list[ast.Call]:
        """`call` and the method calls built on it (`select(M).where(…).limit(1)`), in order."""
        out, node = [call], call
        while True:
            parent = self.parents.get(id(node))
            grand = self.parents.get(id(parent)) if isinstance(parent, ast.Attribute) else None
            if not (isinstance(grand, ast.Call) and grand.func is parent):
                return out
            out.append(grand)
            node = grand

    def predicates(self, links: list[ast.Call], record: str) -> list[tuple[str, ast.AST]] | None:
        """The (column, value) equalities a query narrows by; None when any narrowing is something
        else (`or_`, `!=`, `in_`, another table's column, raw text) or a link widens the query
        (a join, a union)."""
        found: list[tuple[str, ast.AST]] = []
        for c in links[1:]:
            name = _call_name(c)
            if name in _QUERY_WIDENING:
                return None
            if name not in _QUERY_NARROWING:
                continue
            if name == "filter_by":
                if c.args or any(k.arg is None for k in c.keywords):
                    return None
                found += [(k.arg, k.value) for k in c.keywords if k.arg]
                continue
            if c.keywords:
                return None
            for a in c.args:
                for p in a.args if isinstance(a, ast.Call) and _call_name(a) == "and_" else [a]:
                    pair = self.equality(p, record)
                    if pair is None:
                        return None
                    found.append(pair)
        return found

    def equality(self, p: ast.AST, record: str) -> tuple[str, ast.AST] | None:
        if not (isinstance(p, ast.Compare) and len(p.ops) == 1 and isinstance(p.ops[0], ast.Eq)):
            return None
        for col, value in ((p.left, p.comparators[0]), (p.comparators[0], p.left)):
            if isinstance(col, ast.Attribute) and _dotted(col.value).rsplit(".", 1)[-1] == record:
                return col.attr, value
        return None

    def query(self, root: ast.Call, record: str) -> None:
        links = self.chain(root)
        self.consumed |= {id(c) for c in links}
        if not any(_names(a) & self.ids for c in links[1:] for a in _values(c)):
            return
        predicates = self.predicates(links, record)
        gets = [a for c in links[1:] if _call_name(c) == "get" for a in c.args]
        if predicates is None:
            scoped, cover = False, None
        else:
            # shape 1: equalities only, one of them on an owner column with a caller-only value
            scoped = any(OWNER_CHECK_RX.match(c) and self.v.derived(v) for c, v in predicates)
            cover = self.exact_ids([v for _, v in predicates if _names(v) & self.ids] + gets)
        read = _call_name(root) in ("select", "query")
        k = self.add(
            root, Lookup(self.span(root), scoped, record_type=record), read=read, cover=cover
        )
        self.query_lookups.add(k)
        for c in links[1:]:
            self.made.setdefault(id(c), []).append(k)
        parent = self.parents.get(id(links[-1]))
        if isinstance(parent, ast.Assign) and (name := _assigned_name(parent)):
            self.queries[name] = k

    def subscript(self, node: ast.Subscript) -> None:
        """`_ITEMS[item_id]`: a lookup in a store by the id."""
        if not _names(node.slice) & self.ids or self.v.derived(node.value):
            return
        parent = self.parents.get(id(node))
        read = isinstance(node.ctx, ast.Load) and not isinstance(parent, ast.Attribute)
        record = self.code.container(self.rel, node.value)
        lookup = Lookup(self.span(node), record_type=record)
        self.add(node, lookup, read=read, cover=self.exact_ids([node.slice]))

    def call(self, call: ast.Call) -> None:
        if id(call) in self.consumed:
            return
        name = _call_name(call)
        # a query passed to be run (`session.exec(select(…)…)`) is already its own lookup
        values = [v for v in _values(call) if id(_unawait(v)) not in self.consumed]
        receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
        # a local function or class called, instantiated (`Loader().run()`) or handed on as a
        # callback, using the id through its arguments or its closure: not followed
        called = {n.id for n in ast.walk(call.func) if isinstance(n, ast.Name)} & self.nested.keys()
        handed = {v.id for v in values if isinstance(v, ast.Name)} & self.nested.keys()
        if called or handed:
            if any(_names(self.nested[n]) & self.ids for n in called | handed) or (
                called and any(_names(v) & self.ids for v in values)
            ):
                self.handoff(call, None)
            if called:
                return
        if not any(_names(v) & self.ids for v in values):
            # `map(lambda i: delete(i), ids)`: an id handed to a function value
            if any(isinstance(v, ast.Lambda) and _names(v) & self.ids for v in values):
                self.handoff(call, None)
            return
        cover = self.exact_ids([v for v in values if _names(v) & self.ids])
        span, dotted = self.span(call), _dotted(call.func)
        if dotted in _CONVERSIONS or _INERT.match(dotted) or _THROWN.search(name):
            return
        if receiver is not None and self.code.is_store(self.rel, receiver):
            record = self.code.container(self.rel, receiver)
            self.add(call, Lookup(span, record_type=record), read=name == "get", cover=cover)
        elif (
            name in ("get", "get_one")
            and len(call.args) >= 2
            and (record := self.code.record(self.rel, call.args[0]))
        ):
            # `session.get(Item, item_id)`
            lookup = Lookup(span, record_type=record)
            self.add(call, lookup, read=True, cover=self.exact_ids(call.args[1:]))
        elif self.code.class_def(self.rel, dotted) is not None:
            self.handoff(call, cover)  # an object built with the id (`Item(id=item_id)`)
        elif (targets := self.code.functions(self.rel, call.func, self.cls)) is None:
            if not _VALIDATOR_NAME.match(name):
                self.handoff(call, cover)  # two definitions of one name: which runs isn't told
        elif targets:
            # one hop, and a second only into an authorization-shaped helper (`check_item`)
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if not _VALIDATOR_NAME.match(name):
                    self.handoff(call, cover)
                return
            self.hop_into(call, targets)
        elif self.kept(call) and receiver is not None and not self.v.derived(receiver):
            # shape 4: a kept load we can't follow, handed a caller-only value (owner decision)
            scoped = any(self.v.derived(v) for v in values)
            self.add(call, Lookup(span, scoped), read=False, cover=cover)
        elif _LOOKUP_NAME.match(name) and (receiver is None or not self.v.derived(receiver)):
            self.add(call, Lookup(span), read=False, cover=cover)
        elif not _VALIDATOR_NAME.match(name):
            self.handoff(call, cover)

    def kept(self, call: ast.Call) -> bool:
        parent = self.parents.get(id(call))
        if isinstance(parent, ast.Await):
            parent = self.parents.get(id(parent))
        return isinstance(parent, ast.Assign | ast.AnnAssign) and parent.value is not None

    def hop_into(self, call: ast.Call, targets: list[Target]) -> None:
        self.hop = self.hop or self.span(call)
        verified: set[str] | None = None
        owned: set[str] | None = None
        for target in targets:
            scan, exact = self.o.hop(self, target, call)

            def mapped(inner: set[str] | None, exact: dict[str, str] = exact) -> set[str] | None:
                return {exact[p] for p in inner} if inner and inner <= exact.keys() else None

            for x, read, inner in zip(scan.facts.lookups, scan.reads, scan.covers, strict=True):
                lookup = Lookup(x.span, x.scoped, x.checked, x.record_type)
                self.add(call, lookup, read=read and scan.pure_read, cover=mapped(inner))
            self.caller = self.caller or scan.facts.caller
            if scan.facts.handoff:
                self.handoffs.append((scan.facts.handoff, mapped(scan.handoff_cover), _pos(call)))
            v = {exact[p] for p in scan.verified if p in exact}
            o = {exact[p] for p in scan.owned_or_null if p in exact}
            verified = v if verified is None else verified & v
            owned = o if owned is None else owned & o
        self.hop_verified[id(call)] = verified or set()
        self.hop_owned[id(call)] = owned or set()

    # ---- the allow-listed statements
    def load(self, expr: ast.AST | None) -> int | None:
        """The one read an expression is: `session.get(…)`, a typed store's `.get`, a subscript, a
        query fetched for its row (`….first()`), or a hop doing only that; never a fallback, the
        query itself or its result set."""
        expr = _unawait(expr)
        if not isinstance(expr, ast.Call | ast.Subscript):
            return None
        if any(isinstance(n, ast.BoolOp | ast.IfExp | ast.BinOp) for n in ast.walk(expr)):
            return None
        made = {k for n in ast.walk(expr) for k in self.made.get(id(n), [])}
        made |= {self.queries[n] for n in _names(expr) if n in self.queries}
        if len(made) != 1:
            return None
        k = next(iter(made))
        if k in self.query_lookups and not (
            isinstance(expr, ast.Call) and _call_name(expr) in _FETCH
        ):
            return None
        return k if self.reads[k] else None

    def statement(self, stmt: ast.stmt, following: list[ast.stmt]) -> None:
        end = _end(stmt)
        value = (
            _unawait(stmt.value)
            if isinstance(stmt, ast.Expr | ast.Assign | ast.AnnAssign | ast.Return)
            else None
        )
        if value is None:
            return
        if isinstance(value, ast.Call):
            self.verify(self.hop_verified.get(id(value), set()), end)
        k = self.load(value)
        scoped = k is not None and self.lookups[k].scoped
        if scoped and isinstance(value, ast.Call) and _call_name(value) in _FETCH_OR_RAISE:
            # shape 1, refused when absent: a scoped query fetched with `.one()`
            self.verify(self.cover[k] or set(), end)  # type: ignore[index]
        record = _assigned_name(stmt)
        if record is None or not following:
            return
        nxt = following[0]
        absent = _refuses_absence(nxt, record)
        if scoped and absent:
            # shape 1: a scoped query's row, then `if item is None: raise`
            self.verify(self.cover[k] or set(), _end(nxt))  # type: ignore[index]
        check = following[1] if absent and len(following) > 1 else nxt
        if k is not None and self.refuses_foreign(check, record):
            # shape 2: the load, then a refusal of a record the caller doesn't own
            self.checked(k)
            self.verify(self.cover[k] or set(), _end(check))
        elif k is not None and self.returns_if_owned(nxt, record):
            # shape 5: the load, then `return r if r is not None and r.owner == me else None`
            self.checked(k)
            self.owned_or_null.update(dict.fromkeys(self.cover[k] or set(), _pos(nxt)))
        elif isinstance(value, ast.Call) and absent:
            # a hop that returns its record only when owned, refused when absent
            self.verify(self.hop_owned.get(id(value), set()), _end(nxt))

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)

    def caller_declaration(self, stmt: ast.stmt) -> bool:
        return isinstance(stmt, ast.Assign) and _assigned_name(stmt) in self.v.callers

    def refuses_foreign(self, stmt: ast.stmt, record: str) -> bool:
        """`if record.<owner> != <caller-only>: raise …` and nothing else; optionally after
        `record is None or`, and behind `not <caller>.is_superuser and` (owner decision)."""
        if not (isinstance(stmt, ast.If) and not stmt.orelse and _raises_only(stmt.body)):
            return False
        test = stmt.test
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            rest = [p for p in test.values if not self.unprivileged(p)]
            if len(test.values) != 2 or len(rest) != 1:
                return False
            test = rest[0]
        compared = False
        for part in _parts(test, ast.Or):
            if _none_test(part, record, present=False):
                continue
            if not self.compares(part, record, negated=True):
                return False
            compared = True
        return compared

    def unprivileged(self, node: ast.AST) -> bool:
        """`not current_user.is_superuser`: the caller handed in lacks a privileged flag."""
        return (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and isinstance(node.operand, ast.Attribute)
            and bool(_PRIVILEGE_FLAG.match(node.operand.attr))
            and self.v.is_caller(node.operand.value, rooted=True)
        )

    def returns_if_owned(self, stmt: ast.stmt, record: str) -> bool:
        """`return record if record is not None and record.<owner> == <caller-only> else None`"""
        if not (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.IfExp)):
            return False
        expr = stmt.value
        if not (
            isinstance(expr.body, ast.Name) and expr.body.id == record and _is_none(expr.orelse)
        ):
            return False
        compared = False
        for part in _parts(expr.test, ast.And):
            if _none_test(part, record, present=True):
                continue
            if not self.compares(part, record, negated=False):
                return False
            compared = True
        return compared

    def compares(self, part: ast.AST, record: str, *, negated: bool) -> bool:
        """`record.f != c` (or `not record.f == c`) when `negated`, else `record.f == c`; `f` an
        owner member, `c` caller-only."""
        if negated and isinstance(part, ast.UnaryOp) and isinstance(part.op, ast.Not):
            return self.compares(part.operand, record, negated=False)
        op = ast.NotEq if negated else ast.Eq
        if not (
            isinstance(part, ast.Compare) and len(part.ops) == 1 and isinstance(part.ops[0], op)
        ):
            return False
        sides = (part.left, part.comparators[0])
        return any(self.owner_of(a, record) and self.v.derived(b) for a, b in (sides, sides[::-1]))

    def owner_of(self, node: ast.AST, record: str) -> bool:
        """`record.owner_id` or `record["team"]`: an owner member of the record (the narrow set)."""
        if not isinstance(node, ast.Attribute | ast.Subscript):
            return False
        if not (isinstance(node.value, ast.Name) and node.value.id == record):
            return False
        if isinstance(node, ast.Attribute):
            return bool(OWNER_CHECK_RX.match(node.attr))
        key = node.slice
        return (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and bool(OWNER_CHECK_RX.match(key.value))
        )

    def pure_read(self, body: list[ast.stmt]) -> bool:
        """`return <read>` or `r = <read>; return r`, and nothing else."""
        if not body or not isinstance(body[-1], ast.Return) or body[-1].value is None:
            return False
        if len(body) == 1:
            value = body[-1].value
        elif (
            len(body) == 2
            and (name := _assigned_name(body[0])) is not None
            and isinstance(body[-1].value, ast.Name)
            and body[-1].value.id == name
        ):
            value = body[0].value  # type: ignore[union-attr]
        else:
            return False
        return len(self.lookups) == 1 and self.load(value) == 0

    def result(self, first_return: _Pos | None, pure_read: bool) -> _Scan:
        verified = {r: at for r, at in self.verified.items() if r not in self.unstable}

        def holds(roots: set[str] | None, at: _Pos) -> bool:
            return bool(roots) and all(r in verified and verified[r] <= at for r in roots)

        unheld = [(span, roots) for span, roots, at in self.handoffs if not holds(roots, at)]
        handoff, handoff_cover = unheld[0] if unheld else (None, None)
        before = first_return or (10**9, 0)
        return _Scan(
            HandlerFacts(
                lookups=tuple(
                    Lookup(
                        x.span,
                        x.scoped,
                        x.checked or (not x.scoped and holds(self.cover[k], self.starts[k])),
                        x.record_type,
                    )
                    for k, x in enumerate(self.lookups)
                ),
                caller=self.caller,
                hop=self.hop,
                handoff=handoff,
            ),
            verified={r for r, at in verified.items() if at <= before} & self.params,
            owned_or_null={
                r
                for r, at in self.owned_or_null.items()
                if r in self.params - self.unstable and at <= before
            },
            covers=tuple(self.cover),
            reads=tuple(self.reads),
            handoff_cover=handoff_cover,
            pure_read=pure_read,
        )


Callers = Callable[[Target], tuple[set[str], set[str]]]
# a function's dependencies, each with the parameter it fills (None for `dependencies=[…]`)
Dependencies = Callable[[Target], tuple[list[tuple[str | None, Target]], list[Opaque]]]


class PyOwnership:
    """A FastAPI handler's ownership facts. `callers` names the parameters FastAPI fills with the
    authenticated caller (and the `Request` ones); `dependencies` what a function's parameters
    depend on. Both come from the route matrix's own dependency reading."""

    def __init__(self, code: PyCode, callers: Callers, dependencies: Dependencies) -> None:
        self.code, self.callers, self.dependencies = code, callers, dependencies

    def handler(
        self,
        handler: Target,
        path_ids: set[str],
        route_deps: list[tuple[str | None, Target]],
        opaque: list[Opaque],
    ) -> HandlerFacts:
        """`path_ids`: the route's path parameters; `route_deps`/`opaque`: its own, its routers'
        dependencies, followed or not."""
        ids = path_ids & set(_params(handler.fn))
        lookups: list[Lookup] = []
        caller = handoff = hop = None
        verified: set[str] = set()
        reached = bool(ids)
        # dependencies (and theirs) run first: one handed a path id is a hop whose verification
        # covers the body; one we can't follow that may take a path id leaves the route unknown
        own_deps, own_opaque = self.dependencies(handler)
        handed = {param for param, _ in own_deps}
        pending, unread, seen = [*own_deps, *route_deps], [*own_opaque, *opaque], set()
        while pending:
            param, dep = pending.pop(0)
            if id(dep.fn) in seen:
                continue
            seen.add(id(dep.fn))
            more, hidden = self.dependencies(dep)
            pending += [(None, d) for _, d in more]
            unread += hidden
            dep_ids = path_ids & set(_params(dep.fn))
            if not dep_ids:
                continue
            reached = True
            if param is not None and param in handed and returns_id(dep.fn, dep_ids):
                # `item: int = Depends(valid_item_id)` returning the id: the handler has it too
                ids.add(param)
            scan = self.scan(dep, dep_ids, 1, injected=True)
            lookups += scan.facts.lookups
            caller = caller or scan.facts.caller
            if scan.facts.lookups or scan.facts.handoff:
                # a dependency that only takes the id (`get_organization_path`) acts on nothing
                hop = hop or CodeSpan(path=RepoPath(dep.rel), line=dep.fn.lineno)
            handoff = handoff or scan.facts.handoff
            verified |= scan.verified
        blind = next((u for u in unread if u.params is None or u.params & path_ids), None)
        if not reached and blind is None:
            # the path id reaches the handler some way we don't follow: never settle it
            span = CodeSpan(path=RepoPath(handler.rel), line=handler.fn.lineno)
            return HandlerFacts(handoff=span if path_ids else None, takes_id=bool(path_ids))
        scan = self.scan(handler, ids, 0, verified, injected=True) if ids else _Scan(HandlerFacts())
        if blind is not None:
            # the path id goes first to code we can't read: neither settled nor judged
            return HandlerFacts(
                caller=caller or scan.facts.caller, handoff=blind.span, takes_id=True
            )
        return HandlerFacts(
            lookups=(*lookups, *scan.facts.lookups),
            caller=caller or scan.facts.caller,
            hop=hop or scan.facts.hop,
            handoff=handoff or scan.facts.handoff,
            takes_id=True,
            # the handler gets no path id, and the dependencies that do use it for nothing
            ignores_id=not ids and hop is None,
        )

    def scan(
        self,
        target: Target,
        ids: set[str],
        depth: int,
        verified: set[str] | None = None,
        *,
        injected: bool,
        handed: set[str] | None = None,
        handed_requests: set[str] | None = None,
    ) -> _Scan:
        """`injected`: FastAPI calls it, filling its dependencies (the handler, a dependency);
        otherwise a call only hands it the caller values in `handed`/`handed_requests`."""
        own, requests = self.callers(target) if injected else (set(), set())
        callers = own | (handed or set())
        requests = requests | (handed_requests or set())
        key = (target.rel, target.fn.lineno, frozenset(ids), frozenset(callers), depth)
        key += (frozenset(requests), frozenset(verified or ()))
        if key not in self.code.scans:
            walk = _Walk(self, target, ids, callers, requests, depth, set(verified or ()))
            self.code.scans[key] = walk.run()
        return self.code.scans[key]

    def hop(self, walk: _Walk, target: Target, call: ast.Call) -> tuple[_Scan, dict[str, str]]:
        """The callee's facts with its parameters mapped from the call's arguments (by position,
        then keyword), and the outer path id each parameter is exactly."""
        a = target.fn.args
        names = [x.arg for x in (*a.posonlyargs, *a.args)][1 if target.method else 0 :]
        mapping: dict[str, ast.AST] = dict(zip(names, call.args, strict=False))
        mapping.update({k.arg: k.value for k in call.keywords if k.arg is not None})
        unmapped = (
            len(call.args) > len(names)
            or any(isinstance(x, ast.Starred) for x in call.args)
            or any(k.arg is None for k in call.keywords)
        )
        if unmapped:
            # `*args` / `**kwargs`: which parameter gets the id can't be told
            return _Scan(HandlerFacts(handoff=walk.span(call))), {}
        inner_ids = {p for p, v in mapping.items() if _names(v) & walk.ids}
        handed = {p for p, v in mapping.items() if p not in inner_ids and walk.v.derived(v)}
        requests = {
            p for p, v in mapping.items() if isinstance(v, ast.Name) and v.id in walk.v.requests
        }
        scan = self.scan(
            target,
            inner_ids,
            walk.depth + 1,
            injected=False,
            handed=handed,
            handed_requests=requests,
        )
        return scan, {p: r for p, v in mapping.items() if (r := walk.exact(v))}
