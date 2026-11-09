"""Ownership of the object an axum or actix-web id route acts on, read from its handler and the
same-crate functions it hands the id. Protection counts only from allow-listed shapes (D8,
D25-D28)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    HandlerFacts,
    Lookup,
    record_ownerless,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk
from traust_core.v1.providers.tree import TreeFile

# function-like macros whose arguments are expressions: `!` becomes `_` (same length, so lines
# and offsets hold) and they parse as calls
_EXPRESSION_MACROS = re.compile(
    r"\b(query|query_as|query_scalar|query_unchecked|query_as_unchecked|query_scalar_unchecked|"
    r"ensure|bail|format|anyhow|println|eprintln|print|eprint|panic)!(?=\s*\()"
)
_SQLX_MACROS = {
    "query_": 0,
    "query_unchecked_": 0,
    "query_scalar_": 0,
    "query_scalar_unchecked_": 0,
    "query_as_": 1,
    "query_as_unchecked_": 1,
}  # the argument index of the SQL
_SQLX_FUNCTIONS = {"query", "query_as", "query_scalar", "query_with", "query_as_with"}
_SQL_FETCH = {"fetch_one", "fetch_optional", "fetch_all", "fetch", "execute", "fetch_many"}
_SQL_READ = {"fetch_one", "fetch_optional"}
_DIESEL_FETCH = {"first", "get_result", "get_results", "load", "execute", "optional"}
_DIESEL_READ = {"first", "get_result"}
_SEA_FETCH = {"one", "all", "exec", "count"}
_EXTRACTOR_TRAITS = {
    "FromRequestParts",
    "FromRequest",
    "OptionalFromRequestParts",
    "OptionalFromRequest",
}
# library extractors that carry a verified caller (D26)
_LIBRARY_CALLERS = {"Identity", "AuthSession"}
# what an `Extension<T>`/`ReqData<T>` or `extensions().get::<T>()` of the caller holds
_CALLER_TYPE = re.compile(
    r"(?i)^(current_?|auth(enticated)?_?|logged_?in_?|session_?|verified_?)?"
    r"(user|account|member|principal|identity|claims|subject|actor|caller)$"
)
_PATH_TYPES = {"Path", "RawPathParams"}
_REQUEST_TYPES = {"HttpRequest", "Request", "Parts", "Uri", "OriginalUri"}
_WRAPPERS = {
    "Arc",
    "Rc",
    "Box",
    "LazyLock",
    "Lazy",
    "OnceLock",
    "OnceCell",
    "Mutex",
    "RwLock",
    "RefCell",
    "Cell",
    "Data",
    "State",
    "Extension",
    "ReqData",
    "MutexGuard",
    "RwLockReadGuard",
    "RwLockWriteGuard",
    "Pin",
    "Option",
}
_CONTAINERS = {"HashMap", "BTreeMap", "DashMap", "IndexMap", "Vec", "VecDeque", "Slab"}
# methods that pass a value through: a guard, a borrow, a clone
_TRANSPARENT = {
    "lock",
    "read",
    "write",
    "borrow",
    "borrow_mut",
    "unwrap",
    "expect",
    "clone",
    "as_ref",
    "as_mut",
    "deref",
    "get_ref",
    "into_inner",
}
_STORE_READS = {"get", "get_key_value"}
_STORE_CALLS = {"get", "get_mut", "remove", "entry", "insert", "get_key_value", "swap_remove"}
_SEARCHES = {"find", "filter", "position", "find_map", "retain", "iter_mut"}
# conversions of one value into another form of itself
_CONVERSIONS = {
    "clone",
    "to_string",
    "to_owned",
    "as_str",
    "as_ref",
    "as_deref",
    "into",
    "into_inner",
    "parse",
    "to_lowercase",
    "to_uppercase",
    "trim",
    "unwrap",
    "expect",
    "borrow",
    "as_uuid",
    "to_vec",
}
_CONVERTERS = {"from", "try_from", "parse_str", "from_str", "new"}
_CALLER_METHODS = _CONVERSIONS | {"id", "user_id", "get_id"}
_INERT_CALLS = re.compile(
    r"^(format_|println_|eprintln_|print_|eprint_|anyhow_|panic_|Some|Ok|Err|Box::new|Json|"
    r"Html|Redirect::\w+|web::Json|HttpResponse::\w+|StatusCode::\w+)$"
)
_COMBINATORS = {
    "map",
    "map_err",
    "and_then",
    "or_else",
    "ok_or",
    "ok_or_else",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "context",
    "with_context",
    "map_or",
    "map_or_else",
    "then",
    "then_some",
    "is_some",
    "is_none",
    "inspect",
    "eq",
    "ne",
    "cmp",
    "partial_cmp",
    "push",
    "push_str",
    "extend",
    "join",
    "len",
    "is_empty",
}
# error and absence adapters a value passes through unchanged
_ADAPTERS = {"map_err", "context", "with_context", "ok_or", "ok_or_else"}
# values built from others: a path joined to the id is still the id's path
_BUILDERS = {"join", "push", "push_str", "extend", "format_", "concat", "with_extension", "add"}
_ID_TYPES = {
    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
    "String", "str", "Uuid", "Ulid", "ObjectId",
}  # fmt: skip
_RESPONSE_PARTS = {"json", "body", "finish", "insert_header", "content_type", "append_header"}
_LOOKUP_NAME = re.compile(
    r"^(get|find|fetch|load|read|lookup|select|query|search|retrieve|delete|remove|take|update|"
    r"by_id|one)(_|$)"
)
_AUTHORIZE_NAME = re.compile(
    r"^(check|verify|authori[sz]e|assert|ensure|require|validate|enforce|can|has|is|owns)(_|$)"
)
_VALIDATOR_NAME = re.compile(
    r"^(validate|check|verify|assert|ensure|require)(_(id|ids|uuid|param|params|arg|args|format"
    r"|length|size|range|positive|input|not_none|not_null|not_empty))?$"
)
_LOG_MACROS = re.compile(r"^(\w+::)*(trace|debug|info|warn|error|event|span|log|dbg|tracing)$")
# a session or transaction bound to the caller (D28)
_SESSION = re.compile(
    r"^(begin|begin_transaction|transaction|acquire|conn|connection|get_conn|session|"
    r"with_user|for_user|as_user)$"
)
_PROCESSING = re.compile(
    r"(?i)(decode|verify|valid|authent|introspect|lookup|load_user|find_user|get_user|user_from|"
    r"from_token|from_authori[sz]ation|parse_jwt|jwt|claims|session_user|by_token|by_api_key|"
    r"check_token|check_key|resolve_\w*auth)"
)
# decoders of an encoding, which constrain nothing
_ENCODING = re.compile(
    r"(?i)(percent|url|base64|b64|hex|utf_?8|form|html|uri)_?decode|decode_(utf|percent|base|hex|url)|from_utf8"
)
_REFUSALS = {"FORBIDDEN", "NOT_FOUND", "UNAUTHORIZED"}
_REFUSAL_RESPONSES = re.compile(
    r"^(HttpResponse|HttpResponseBuilder)::(Forbidden|NotFound|Unauthorized)$"
)
_REFUSAL_ERRORS = re.compile(r"^(\w+::)*Error(Forbidden|NotFound|Unauthorized)$")
_MAX_DEPTH = 48
_END = 1 << 62


def rewrite(text: str, own: frozenset[str] = frozenset()) -> str:
    """`own`: macros the checkout defines itself, which keep their tokens (an `ensure!` that only
    logs is no refusal)."""
    return _EXPRESSION_MACROS.sub(
        lambda m: m.group(0) if m.group(1) in own else f"{m.group(1)}_", text
    )


def _unwrap(node: Node | None) -> Node | None:
    """The expression inside `x?`, `x.await`, `(x)`, `&x`, `*x`."""
    while node is not None:
        if node.type in (
            "try_expression",
            "await_expression",
            "parenthesized_expression",
            "reference_expression",
        ):
            node = next((c for c in node.named_children if c.type != "mutable_specifier"), None)
        elif node.type == "unary_expression" and node.children and node.children[0].type == "*":
            node = node.named_children[0] if node.named_children else None
        else:
            return node
    return None


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [a for a in args.named_children if "comment" not in a.type] if args else []


def _op(node: Node) -> str:
    op = node.child_by_field_name("operator")
    return op.type if op is not None else ""


def _segments(path: str) -> list[str]:
    """`a::b::<T>::c` is [a, b, c]; `<T as Trait<S>>::f` is [T, f]."""
    path = re.sub(r"\s+", " ", path).strip()
    if m := re.match(r"^<\s*([\w:]+)(?:\s+as\s+.*)?>\s*::(.*)$", path):
        path = f"{m.group(1)}::{m.group(2)}"
    out, depth, cur = [], 0, ""
    for i, ch in enumerate(path):
        depth += (ch == "<") - (ch == ">")
        if depth == 0 and ch == ":" and path[i + 1 : i + 2] == ":":
            out.append(cur)
            cur = ""
        elif depth == 0 and ch not in "<>: ":
            cur += ch
    out.append(cur)
    return [s for s in out if s]


def _last(path: str) -> str:
    segs = _segments(path)
    return segs[-1] if segs else ""


def _generic(text: str) -> tuple[str, list[str]]:
    """`HashMap<u64, Note>` is (`HashMap`, [`u64`, `Note`])."""
    text = re.sub(r"^&\s*('\w+\s+)?(mut\s+)?|^dyn\s+|^impl\s+", "", text.strip())
    if "<" not in text or not text.endswith(">"):
        return _last(text), []
    name, inner = text.split("<", 1)
    args, depth, cur = [], 0, ""
    for ch in inner[:-1]:
        if ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
            continue
        depth += (ch in "<([" and 1) or 0
        depth -= (ch in ">)]" and 1) or 0
        cur += ch
    if cur.strip():
        args.append(cur.strip())
    return _last(name), [a for a in args if not a.startswith("'")]


def _strip(text: str) -> str:
    """The type a wrapper (`Arc<Mutex<T>>`, `&T`, `web::Data<T>`) holds."""
    for _ in range(12):
        name, args = _generic(text)
        if name in _WRAPPERS and len(args) == 1:
            text = args[0]
        elif not args:
            return name
        else:
            return text
    return text


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()


@dataclass
class _Src(Parsed):
    crate: str = ""
    module: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Fn:
    src: _Src
    node: Node  # function_item, or a closure handler
    module: tuple[str, ...]
    owner: str | None = None  # the type an impl method belongs to


@dataclass(frozen=True)
class _Sql:
    kind: str
    table: str | None
    # (column, placeholder index) of a WHERE of AND-ed equalities only; None when it's anything else
    equalities: tuple[tuple[str, int], ...] | None
    aggregate: bool = False
    select_all: bool = False  # `select * from <one table>`


def _sql(text: str) -> _Sql:
    s = re.sub(r"'(?:[^']|'')*'", "''", text)  # literals first: `'/*'` opens no comment
    s = re.sub(r"--[^\n]*|/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"\s+", " ", s).strip().rstrip(";").strip().lower()
    kind = s.split(" ", 1)[0] if s else ""
    table = None
    if m := re.search(
        r"^(?:select .*? from|delete from|update|insert into) (?:only )?\"?([\w.]+)\"?", s
    ):
        table = m.group(1).rsplit(".", 1)[-1]
    source = re.search(r" from (.*?)(?: where |$)", s)
    plain = (
        kind in ("select", "update", "delete")
        and ";" not in s
        # a comma join, or `update … from`, brings another table into the WHERE
        and not (source and "," in source.group(1))
        and not (kind == "update" and " from " in s)
        and not re.search(
            r"\b(with|or|join|union|intersect|except|exists|in|not|like|ilike|between|any|all|"
            r"using|having)\b|\(\s*select|<>|!=|<|>",
            s,
        )
    )
    equalities: tuple[tuple[str, int], ...] | None = None
    if plain and (
        m := re.search(
            r" where (.*?)"
            r"(?: returning | order by | group by | limit | offset | for update| for share|$)",
            s,
        )
    ):
        found: list[tuple[str, int]] = []
        marks = [m2.start() for m2 in re.finditer(r"\?", s)]
        for part in m.group(1).split(" and "):
            part = part.strip().strip("()").strip()
            col = r"(?:\"?\w+\"?\.)?\"?(\w+)\"?"
            mark = r"(\$\d+|\?)"
            literal = r"(?:''|\d+|true|false)"
            if (e := re.fullmatch(rf"{col}\s*=\s*{mark}", part)) or (
                e := re.fullmatch(rf"{mark}\s*=\s*{col}", part)
            ):
                c, p = (
                    (e.group(1), e.group(2))
                    if not e.group(1).startswith(("$", "?"))
                    else (
                        e.group(2),
                        e.group(1),
                    )
                )
                if p == "?":
                    at = m.start(1) + m.group(1).find(part)
                    index = sum(1 for x in marks if x < at + part.find("?"))
                else:
                    index = int(p[1:]) - 1
                found.append((c, index))
            elif not re.fullmatch(rf"{col}\s*=\s*{literal}|{col} is (?:not )?null", part):
                found = []
                break
        equalities = tuple(found) if found else None
    # an aggregate always returns its row: a match is not a read of the record
    aggregate = bool(
        re.match(r"select (distinct )?(count|sum|min|max|avg|exists|bool_\w+)\s*\(", s)
    )
    select_all = bool(re.match(r"select \* from [\w.\"]+( where | order | limit |$)", s + " "))
    return _Sql(kind, table, equalities, aggregate, select_all and plain)


class RustCode:
    """A checkout's Rust crates: their modules, functions, impls, records and extractors."""

    def __init__(self, files: list[TreeFile], parser: object) -> None:
        crates = self._crates(files)
        own = frozenset(
            m
            for f in files
            if f.path.suffix == ".rs"
            for m in re.findall(r"macro_rules!\s*(\w+)", f.text)
        )
        self.sources: list[_Src] = []
        self.fns: dict[tuple[str, tuple[str, ...], str], list[_Fn]] = {}
        self.methods: dict[tuple[str, str], list[_Fn]] = {}
        self.by_name: dict[str, list[_Fn]] = {}
        self.modules: set[tuple[str, tuple[str, ...]]] = set()
        self.crate_names = set(crates.values())
        self.crates = {self._place(f.rel, crates)[0] for f in files if f.path.suffix == ".rs"}
        self.crates |= self.crate_names
        self.uses: dict[tuple[str, tuple[str, ...]], dict[str, list[str]]] = {}
        self.globs: dict[tuple[str, tuple[str, ...]], list[list[str]]] = {}
        # what a module re-exports (`pub use other::*`), to follow a path through it
        self.module_uses: dict[tuple[str, tuple[str, ...]], dict[str, list[str]]] = {}
        self.module_globs: dict[tuple[str, tuple[str, ...]], list[list[str]]] = {}
        self.types: dict[str, int] = {}
        self.aliases: dict[str, str] = {}
        self.renamed: dict[str, str] = {}
        self.traits: set[str] = set()
        self.implements: dict[str, set[str]] = {}
        self.structs: dict[str, dict[str, str]] = {}
        self.statics: dict[str, str] = {}
        self.extractors: dict[str, list[_Fn]] = {}
        self.fields: dict[str, tuple[str, ...]] = {}
        self.scans: dict[tuple, _Scan] = {}
        self._kinds: dict[str, str] = {}
        for f in files:
            if f.path.suffix != ".rs":
                continue
            data = rewrite(f.text, own).encode("utf-8")
            crate, module = self._place(f.rel, crates)
            src = _Src(f, parser.parse(data).root_node, data, crate, module)  # type: ignore[attr-defined]
            self.sources.append(src)
            self.modules.add((crate, module))
            self._items(src, src.root, module, None)
        # a record holding another checkout struct may carry its owner there (`doc.meta.owner`)
        for name in list(self.fields):
            types = self.structs.get(name, {}).values()
            if any(t in self.structs for typ in types for t in re.findall(r"[A-Za-z_]\w*", typ)):
                del self.fields[name]

    @staticmethod
    def _crates(files: list[TreeFile]) -> dict[str, str]:
        found = {}
        for f in files:
            if f.path.name == "Cargo.toml":
                m = re.search(r'(?ms)^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', f.text)
                folder = str(PurePosixPath(f.rel).parent)
                found[folder] = (
                    m.group(1) if m else PurePosixPath(folder).name or "crate"
                ).replace("-", "_")
        return found

    @staticmethod
    def _place(rel: str, crates: dict[str, str]) -> tuple[str, tuple[str, ...]]:
        folder = max(
            (d for d in crates if d == "." or rel.startswith(d + "/")), key=len, default=None
        )
        if folder is None:
            return f"#{rel}", ()
        rest = rel if folder == "." else rel[len(folder) + 1 :]
        name = crates[folder]
        if not rest.startswith("src/"):
            return f"{name}#{rest}", ()
        parts = rest[4:].split("/")
        if parts[0] == "bin":
            return f"{name}#{rest}", ()
        stem = parts[-1].removesuffix(".rs")
        if len(parts) == 1 and stem in ("lib", "main"):
            return name, ()
        return name, tuple(parts[:-1]) + (() if stem == "mod" else (stem,))

    def _items(self, src: _Src, node: Node, module: tuple[str, ...], owner: str | None) -> None:
        scope = (src.file.rel, module)
        for c in node.named_children:
            kind = c.type
            if kind == "function_item" and (name := c.child_by_field_name("name")):
                fn = _Fn(src, c, module, owner)
                key = src.text(name)
                if owner is None:
                    self.fns.setdefault((src.crate, module, key), []).append(fn)
                else:
                    self.methods.setdefault((owner, key), []).append(fn)
                self.by_name.setdefault(key, []).append(fn)
            elif kind == "mod_item" and (body := c.child_by_field_name("body")):
                inner = (*module, src.text(c.child_by_field_name("name")))
                self.modules.add((src.crate, inner))
                self._items(src, body, inner, None)
            elif kind in ("impl_item", "trait_item") and (body := c.child_by_field_name("body")):
                field_name = "type" if kind == "impl_item" else "name"
                typ = _strip(src.text(c.child_by_field_name(field_name)))
                if kind == "trait_item":
                    self.traits.add(typ)
                self._items(src, body, module, typ)
                trait = c.child_by_field_name("trait") if kind == "impl_item" else None
                if trait is not None:
                    self.implements.setdefault(typ, set()).add(_generic(src.text(trait))[0])
                if trait is not None and _generic(src.text(trait))[0] in _EXTRACTOR_TRAITS:
                    for fn in body.named_children:
                        if fn.type == "function_item" and src.text(
                            fn.child_by_field_name("name")
                        ).startswith("from_request"):
                            self.extractors.setdefault(typ, []).append(_Fn(src, fn, module, typ))
            elif kind in ("struct_item", "enum_item", "type_item", "union_item"):
                name = src.text(c.child_by_field_name("name"))
                self.types[name] = self.types.get(name, 0) + 1
                if kind == "struct_item":
                    self._struct(src, c, module)
                elif kind == "type_item" and (t := c.child_by_field_name("type")) is not None:
                    self.aliases[name] = src.text(t)
            elif kind in ("static_item", "const_item") and (t := c.child_by_field_name("type")):
                self.statics[src.text(c.child_by_field_name("name"))] = src.text(t)
            elif kind == "use_declaration" and (arg := c.child_by_field_name("argument")):
                for alias, path in self._use(src, module, arg, []):
                    if alias == "*":
                        self.globs.setdefault(scope, []).append(path)
                        self.module_globs.setdefault((src.crate, module), []).append(path)
                        continue
                    self.uses.setdefault(scope, {})[alias] = path
                    self.module_uses.setdefault((src.crate, module), {})[alias] = path
                    if path and path[-1] != alias:
                        self.renamed[alias] = path[-1]
            elif (
                kind == "macro_invocation"
                and _last(src.text(c.child_by_field_name("macro"))) == "table"
            ):
                self._table(src.text(c))

    def _struct(self, src: _Src, node: Node, module: tuple[str, ...]) -> None:
        name = src.text(node.child_by_field_name("name"))
        body = node.child_by_field_name("body")
        fields: dict[str, str] = {}
        if body is not None and body.type == "field_declaration_list":
            for d in body.named_children:
                if d.type == "field_declaration":
                    fields[src.text(d.child_by_field_name("name"))] = src.text(
                        d.child_by_field_name("type")
                    )
            # a sea-orm entity's `Model` is its module's record (`note::Entity` reads `note`)
            for key in (name, module[-1]) if name == "Model" and module else (name,):
                self.fields[key] = tuple(dict.fromkeys([*self.fields.get(key, ()), *fields]))
        elif body is not None:
            types = [t for t in body.named_children if t.type not in ("visibility_modifier",)]
            fields = {str(i): src.text(t) for i, t in enumerate(types)}
        self.structs.setdefault(name, {}).update(fields)

    def _table(self, text: str) -> None:
        """diesel's `table! { notes (id) { id -> Int4, user_id -> Int4 } }`"""
        for m in re.finditer(r"(\w+)\s*(?:\([^)]*\))?\s*\{([^{}]*)\}", text):
            columns = tuple(re.findall(r"(\w+)\s*->", m.group(2)))
            if columns:
                self.fields[m.group(1)] = columns

    def _use(
        self, src: _Src, module: tuple[str, ...], node: Node, prefix: list[str]
    ) -> Iterator[tuple[str, list[str]]]:
        kind = node.type
        if kind in ("identifier", "scoped_identifier", "crate", "self", "super"):
            path = [*prefix, *_segments(src.text(node))]
            if path and path[-1] == "self":
                path = path[:-1]
            if path:
                yield path[-1], self._absolute(src.crate, module, path)
        elif kind == "use_as_clause":
            path = [*prefix, *_segments(src.text(node.child_by_field_name("path")))]
            alias = src.text(node.child_by_field_name("alias"))
            yield alias, self._absolute(src.crate, module, path)
        elif kind == "scoped_use_list":
            base = node.child_by_field_name("path")
            inner = [*prefix, *(_segments(src.text(base)) if base is not None else [])]
            if (items := node.child_by_field_name("list")) is not None:
                for item in items.named_children:
                    yield from self._use(src, module, item, inner)
        elif kind == "use_list":
            for item in node.named_children:
                yield from self._use(src, module, item, prefix)
        elif kind == "use_wildcard":
            base = [*prefix, *_segments(src.text(node).removesuffix("*").rstrip(":"))]
            yield "*", self._absolute(src.crate, module, base)

    def _absolute(self, crate: str, module: tuple[str, ...], path: list[str]) -> list[str]:
        """A path from a crate root: `crate::a::b` is [<crate>, a, b]; a library's path is kept
        as written (its head is no crate of the checkout)."""
        if not path:
            return [crate, *module]
        head, rest = path[0], path[1:]
        if head == "crate":
            return [crate, *rest]
        if head == "self":
            return [crate, *module, *rest]
        if head == "super":
            up = list(module[:-1])
            while rest and rest[0] == "super":
                up, rest = up[:-1], rest[1:]
            return [crate, *up, *rest]
        if (crate, (*module, head)) in self.modules or (crate, module, head) in self.fns:
            return [crate, *module, *path]
        return path

    def module_at(self, src: _Src, node: Node | None) -> tuple[str, ...]:
        """The module a node sits in: its file's, then each enclosing `mod x { }`."""
        names = []
        while node is not None:
            if node.type == "mod_item" and node.child_by_field_name("body") is not None:
                names.append(src.text(node.child_by_field_name("name")))
            node = node.parent
        return (*src.module, *reversed(names))

    def resolve(self, src: _Src, path: str, at: Node | None = None) -> list[_Fn] | None:
        """The crate functions a call path names: [] when none (a library's), None when it can't
        be told which runs. `at` places the path (its module, its enclosing functions)."""
        segs = _segments(path)
        if not segs:
            return None
        module = self.module_at(src, at)
        uses = self.uses.get((src.file.rel, module), {})
        if segs[0] == "Self" and len(segs) == 2:
            owner = _impl_owner(src, at)
            return self.method(owner, segs[1]) if owner else None
        if len(segs) == 1:
            name = segs[0]
            if (local := _local_fn(src, at, name, module)) is not None:
                return [local]
            if name in uses:
                return self._target(uses[name])
            if found := self.fns.get((src.crate, module, name)):
                return found if len(found) == 1 else None
            globs = self.globs.get((src.file.rel, module), [])
            hits = [found for g in globs if (found := self._target([*g, name]))]
            if len(hits) == 1:
                return hits[0]
            if hits or any(g[:1] and g[0] not in self.crates for g in globs):
                return None  # more than one glob, or a library's, may provide it
            return self._unique(name)
        head = segs[0]
        full = [*uses[head], *segs[1:]] if head in uses else self._absolute(src.crate, module, segs)
        return self._target(full)

    def _target(self, full: list[str], depth: int = 0) -> list[_Fn] | None:
        if not full or full[0] not in self.crates:
            return []  # a library's
        if len(full) >= 3 and full[-2][:1].isupper():
            return self.method(full[-2], full[-1])
        if found := self._at(full):
            return found
        module, name = (full[0], tuple(full[1:-1])), full[-1]
        if depth < 6:
            # re-exported by the module: `pub use x::f;`, `pub use x::*;`
            if (path := self.module_uses.get(module, {}).get(name)) is not None:
                return self._target(path, depth + 1)
            hits = [
                found
                for g in self.module_globs.get(module, [])
                if (found := self._target([*g, name], depth + 1))
            ]
            if len(hits) == 1:
                return hits[0]
            if hits:
                return None
        # in a crate of the checkout but not indexed (a macro-made module): the only one so named
        return self._unique(name)

    def _at(self, full: list[str]) -> list[_Fn]:
        if len(full) < 2:
            return []
        found = self.fns.get((full[0], tuple(full[1:-1]), full[-1]), [])
        return found if len(found) == 1 else []

    def _unique(self, name: str) -> list[_Fn] | None:
        found = self.by_name.get(name, [])
        if not found:
            return []
        return found if len(found) == 1 else None

    def method(self, owner: str, name: str) -> list[_Fn] | None:
        """`owner`'s method `name`: None when another type shares the name, or a trait default
        may run instead."""
        if self.types.get(owner, 0) > 1 or owner in self.traits:
            return None
        found = self.methods.get((owner, name))
        if found is None:
            defined = owner in self.types or self.implements.get(owner)
            return None if defined and self.implements.get(owner) else []
        return found if len(found) == 1 else None

    def caller_kind(self, typ: str, depth: int = 0) -> str:
        """`trusted`, `forged` or `unread` (D26)."""
        typ = self.renamed.get(typ, typ)
        if typ in self.aliases and depth < 4:
            return self.caller_kind(_strip(self.aliases[typ]), depth + 1)
        if typ in self._kinds:
            return self._kinds[typ]
        self._kinds[typ] = "unread"  # a cycle reads as unread
        impls = self.extractors.get(typ, [])
        if not impls:
            library = typ in _LIBRARY_CALLERS and typ not in self.types
            kind = "trusted" if library else "unread"
        else:
            kinds = {self._extractor(f, depth) for f in impls} - {"self"}
            kind = next((k for k in ("forged", "unread") if k in kinds or not kinds), "trusted")
        self._kinds[typ] = kind
        return kind

    def _extractor(self, fn: _Fn, depth: int) -> str:
        """Trusted when its caller comes from the request's extensions (server code put it
        there), a trusted auth extractor, or a decode, verify or lookup call handed the raw
        request data, and no raw value reaches it any other way; else forged (D26)."""
        from traust_core.v1.providers.rust_routes import _is_guard

        src, node = fn.src, fn.node
        body = node.child_by_field_name("body")
        if body is None:
            return "unread"
        sources: set[str] = set()
        for n in walk(body):
            if n.type != "call_expression":
                continue
            name, text = _call_name(src, n), src.text(n.child_by_field_name("function"))
            turbofish = re.search(r"::<\s*(.+?)\s*>\s*$", text)
            typ = None
            if name == "get" and turbofish and _extensions(src, _receiver(n)):
                read = _strip(turbofish.group(1))
                if read in ("Self", fn.owner) or _CALLER_TYPE.match(read) or _is_guard(read):
                    sources.add("trusted")
                continue
            if name.startswith("from_request") and _receiver(n) is None:
                segs = _segments(text)
                typ = _strip(segs[-2]) if len(segs) >= 2 else None
            elif name in ("extract", "extract_parts") and turbofish:
                typ = _strip(turbofish.group(1))
            if typ in ("Self", fn.owner):
                sources.add("self")
            elif typ and (_is_guard(typ) or _CALLER_TYPE.match(typ)) and depth < 3:
                sources.add(self.caller_kind(typ, depth + 1))
        params = node.child_by_field_name("parameters")
        request = {
            src.text(p.child_by_field_name("pattern"))
            for p in (params.named_children if params is not None else [])
            if p.type == "parameter" and not re.search(r"(?i)state", src.text(p))
        }
        handed = request | _bound_from(src, body, request)
        if any(
            n.type == "call_expression"
            and _PROCESSING.search(name := _call_name(src, n))
            and not _ENCODING.search(name)
            and _idents(src, n) & handed
            for n in walk(body)
        ):
            sources.add("trusted")  # the request handed whole to an auth resolver
        if raw := _raw_reads(src, body):
            processed = [
                n
                for n in walk(body)
                if n.type == "call_expression"
                and _PROCESSING.search(name := _call_name(src, n))
                and not _ENCODING.search(name)
            ]

            def reaches(r: Node, c: Node) -> bool:
                """The raw value `r` reaches the decode call `c`: as its argument, through a
                local, or through a closure chained on it (`headers().and_then(|h| decode(h))`)."""
                return (
                    _inside(r, c)
                    or bool(_idents(src, c) & _tainted(src, body, [r]))
                    or any(_inside(c, closure) for closure in _chained_closures(r))
                )

            if not all(any(reaches(r, c) for c in processed) for r in raw):
                return "forged"
            sources.add("trusted")
        if not sources:
            return "forged"
        if sources == {"self"}:
            return "self"
        return next((k for k in ("forged", "unread") if k in sources), "trusted")

    def record(self, typ: str | None) -> str | None:
        if not typ:
            return None
        name = _strip(typ)
        return name if name in self.fields else None

    def value_type(self, typ: str) -> str | None:
        """The value a container type holds: `Mutex<HashMap<u64, Note>>` holds `Note`."""
        for _ in range(12):
            name, args = _generic(typ)
            if name in _WRAPPERS and len(args) == 1:
                typ = args[0]
            elif name in _CONTAINERS and args:
                return _strip(args[-1])
            elif name in self.structs and set(self.structs[name]) == {"0"}:
                typ = self.structs[name]["0"]
            else:
                return None
        return None


_RAW_FIELDS = {"headers", "uri", "method"}
_RAW_CALLS = {
    "headers", "header", "uri", "query", "query_string", "cookie", "cookies", "get_cookie",
    "match_info", "connection_info", "peer_addr", "path",
}  # fmt: skip
_RAW_EXTRACTORS = {
    "Query",
    "Path",
    "TypedHeader",
    "CookieJar",
    "Form",
    "Json",
    "HeaderMap",
    "RawQuery",
}


def _raw_reads(src: Parsed, body: Node) -> list[Node]:
    """What the client sent, read directly: a header, the URI, the query, a plain cookie."""
    out = []
    for n in walk(body):
        if n.type == "field_expression" and src.text(n.child_by_field_name("field")) in _RAW_FIELDS:
            out.append(n)
        elif n.type == "call_expression":
            name = _call_name(src, n)
            text = src.text(n.child_by_field_name("function"))
            extractor = re.search(r"\b(" + "|".join(_RAW_EXTRACTORS) + r")\b", text)
            if (_receiver(n) is not None and name in _RAW_CALLS) or (
                extractor
                and (name.startswith("from_request") or name in ("extract", "extract_parts"))
            ):
                out.append(n)
    return out


def _tainted(src: Parsed, body: Node, reads: list[Node]) -> set[str]:
    """The locals bound from a raw read, and from those."""
    names: set[str] = set()
    for _ in range(8):
        more = {
            x
            for d in walk(body)
            if d.type == "let_declaration"
            and (v := d.child_by_field_name("value")) is not None
            and (any(_inside(r, v) for r in reads) or _idents(src, v) & names)
            for x in _pattern_names(src, d.child_by_field_name("pattern"))
        }
        if more <= names:
            return names
        names |= more
    return names


def _bound_from(src: Parsed, body: Node, names: set[str]) -> set[str]:
    found: set[str] = set()
    for _ in range(8):
        more = {
            x
            for d in walk(body)
            if d.type == "let_declaration"
            and _idents(src, d.child_by_field_name("value")) & (names | found)
            for x in _pattern_names(src, d.child_by_field_name("pattern"))
        }
        if more <= found:
            return found
        found |= more
    return found


def _chained_closures(node: Node) -> list[Node]:
    """The closures handed to the method calls chained on `node` (`x.and_then(|v| ..)`)."""
    out = []
    while node.parent is not None and node.parent.type in (
        "field_expression",
        "call_expression",
        "try_expression",
        "await_expression",
        "arguments",
    ):
        node = node.parent
        if node.type == "call_expression":
            out += [a for a in _args(node) if a.type == "closure_expression"]
    return out


def _inside(node: Node, outer: Node) -> bool:
    return outer.start_byte <= node.start_byte and node.end_byte <= outer.end_byte


def _extensions(src: Parsed, node: Node | None) -> bool:
    """`parts.extensions`, `req.extensions()`: what server code put on the request."""
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "field_expression":
        return src.text(node.child_by_field_name("field")) == "extensions"
    return node.type == "call_expression" and _call_name(src, node) == "extensions"


_MUTATORS = re.compile(
    r"^(clone_from|push\w*|insert\w*|extend\w*|clear|truncate|replace\w*|set_\w+|retain|"
    r"append|remove\w*|take|swap\w*|get_mut|as_mut\w*|iter_mut|drain|make_ascii_\w+|sort\w*|"
    r"dedup\w*|fill|reverse)$"
)


def _response(src: Parsed, node: Node | None) -> bool:
    """A response under construction: `HttpResponse::Ok()…`, `Response::builder()…`."""
    node = _unwrap(node)
    while node is not None and node.type == "call_expression":
        if (path := _path_of(src, node)) and re.match(r"^(\w+::)*(HttpResponse|Response)\b", path):
            return True
        node = _unwrap(_receiver(node))
    return False


def _assigned(src: Parsed, fn: Node) -> set[str]:
    """Names a function assigns to (`x = …`, `x += …`) or binds outside a `let` (`for x in`,
    `if let Some(x)`, a closure or match arm parameter)."""
    out: set[str] = set()
    for n in _own(fn):
        if n.type in ("assignment_expression", "compound_assignment_expr"):
            if (root := _root(n.child_by_field_name("left"))) is not None:
                out.add(src.text(root))
        elif n.type in ("for_expression", "let_condition", "closure_expression", "match_arm"):
            pattern = n.child_by_field_name("pattern") or n.child_by_field_name("parameters")
            if pattern is not None and pattern.type == "match_pattern":
                pattern = pattern.named_children[0] if pattern.named_children else None
            out |= set(_pattern_names(src, pattern))
    return out


_IDENTITY = re.compile(
    r"(?i)^(id|uuid|uid|sub|subject|email|username|login|name|key|(user|account|tenant|org|"
    r"organi[sz]ation|team|workspace|owner|member|customer|client|company|project|group)_?(id|uuid|key)?)$"
)
_FORMAT_MACROS = {
    "json", "vec", "write", "writeln", "matches", "assert", "assert_eq", "assert_ne",
    "debug_assert", "todo", "unimplemented", "unreachable", "concat", "stringify",
}  # fmt: skip


def _calls_in(tokens: Node) -> bool:
    """Whether a macro's tokens hold a call: a name followed by a `(…)` group."""
    for n in walk(tokens):
        kids = n.children
        for left, right in itertools.pairwise(kids):
            if (
                left.type == "identifier"
                and right.type == "token_tree"
                and right.children[:1]
                and right.children[0].type == "("
            ):
                return True
    return False


def _collection(typ: str) -> bool:
    for _ in range(12):
        name, args = _generic(typ)
        if name in _CONTAINERS:
            return True
        if name not in _WRAPPERS or len(args) != 1:
            return False
        typ = args[0]
    return False


def _root(node: Node | None) -> Node | None:
    """The variable at the base of `a.b.c`, `a[0]`, `(*a)`."""
    node = _unwrap(node)
    while node is not None and node.type in ("field_expression", "index_expression"):
        node = _unwrap(node.named_children[0]) if node.named_children else None
    return node if node is not None and node.type in ("identifier", "self") else None


def _impl_owner(src: Parsed, node: Node | None) -> str | None:
    while node is not None:
        if node.type == "impl_item":
            return _strip(src.text(node.child_by_field_name("type")))
        node = node.parent
    return None


def _local_fn(src: _Src, at: Node | None, name: str, module: tuple[str, ...]) -> _Fn | None:
    """A function declared inside one of the functions enclosing `at`."""
    node = at
    while node is not None:
        if node.type == "function_item" and (body := node.child_by_field_name("body")):
            for n in walk(body):
                if n.type == "function_item" and src.text(n.child_by_field_name("name")) == name:
                    return _Fn(src, n, module)
        node = node.parent
    return None


def _idents(src: Parsed, node: Node | None) -> set[str]:
    """The variable names an expression mentions (not path segments, not field names)."""
    if node is None:
        return set()
    out = set()
    for n in walk(node):
        if n.type == "identifier" and (
            n.parent is None or n.parent.type not in ("scoped_identifier", "scoped_type_identifier")
        ):
            out.add(src.text(n))
        elif n.type == "self":
            out.add("self")
    return out


def _call_name(src: Parsed, call: Node) -> str:
    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "generic_function":
        fn = fn.child_by_field_name("function")
    if fn is None:
        return ""
    if fn.type == "field_expression":
        return src.text(fn.child_by_field_name("field"))
    return _last(src.text(fn))


def _receiver(call: Node) -> Node | None:
    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "generic_function":
        fn = fn.child_by_field_name("function")
    return (
        fn.child_by_field_name("value")
        if fn is not None and fn.type == "field_expression"
        else None
    )


def _path_of(src: Parsed, call: Node) -> str:
    fn = call.child_by_field_name("function")
    if fn is not None and fn.type == "generic_function":
        fn = fn.child_by_field_name("function")
    return src.text(fn) if fn is not None and fn.type != "field_expression" else ""


def _pattern_names(src: Parsed, node: Node | None) -> list[str]:
    if node is None:
        return []
    return [
        src.text(n)
        for n in walk(node)
        if n.type in ("identifier", "shorthand_field_identifier")
        and (n.parent is None or n.parent.type != "scoped_identifier")
        and not (
            n.parent is not None
            and n.parent.type in ("tuple_struct_pattern", "struct_pattern")
            and n.parent.child_by_field_name("type") == n
        )
    ]


def _statements(block: Node | None) -> list[Node]:
    """A block's statements, without those a `#[cfg(..)]` may compile out."""
    if block is None or block.type != "block":
        return [block] if block is not None else []
    out, gated = [], False
    for c in block.named_children:
        if c.type == "attribute_item":
            gated = gated or bool(re.match(rb"#\s*\[\s*cfg", c.text or b""))
            continue
        if "comment" in c.type or c.type in (
            "use_declaration",
            "function_item",
            "struct_item",
            "empty_statement",
        ):
            continue
        if not gated:
            out.append(c)
        gated = False
    return out


def _is_tail(stmt: Node) -> bool:
    """A block's last statement that is its value: no `let`, no closing `;`."""
    if stmt.type == "let_declaration":
        return False
    return stmt.type != "expression_statement" or stmt.children[-1].type != ";"


def _expr(stmt: Node) -> Node | None:
    """The expression a statement evaluates."""
    if stmt.type == "expression_statement":
        return stmt.named_children[0] if stmt.named_children else None
    if stmt.type == "let_declaration":
        return stmt.child_by_field_name("value")
    return stmt


def _bound(src: Parsed, stmt: Node) -> str | None:
    """`let r = ...` / `let Some(r) = ... else {..}`: the one name bound."""
    if stmt.type != "let_declaration":
        return None
    pattern = stmt.child_by_field_name("pattern")
    if pattern is None:
        return None
    if pattern.type == "identifier":
        return src.text(pattern)
    if pattern.type == "mut_pattern" and pattern.named_children:
        inner = pattern.named_children[-1]
        return src.text(inner) if inner.type == "identifier" else None
    if pattern.type == "tuple_struct_pattern":
        names = [c for c in pattern.named_children if c != pattern.child_by_field_name("type")]
        kind = src.text(pattern.child_by_field_name("type"))
        if kind in ("Some", "Ok") and len(names) == 1 and names[0].type == "identifier":
            return src.text(names[0])
    return None


@dataclass
class _Scan:
    facts: HandlerFacts
    # (parameter, the store or table it was verified for)
    verified: set[tuple[str, str]] = field(default_factory=set)
    owned_or_null: set[tuple[str, str]] = field(default_factory=set)
    targets: tuple[str | None, ...] = ()
    covers: tuple[set[str] | None, ...] = ()
    reads: tuple[bool, ...] = ()
    handoff_cover: set[str] | None = None
    pure_read: bool = False
    returns_caller: bool = False


class _Values:
    """Which values in one function come from the caller alone (D26)."""

    def __init__(
        self, src: Parsed, fn: Node, callers: set[str], requests: set[str], code: RustCode
    ) -> None:
        self.src, self.code = src, code
        self.requests = set(requests)
        self.callers = set(callers)
        self.roots = set(callers)
        bound: dict[str, list[Node | None]] = {}
        assigned: set[str] = set()
        for n in _own(fn):
            if n.type == "let_declaration":
                pattern = n.child_by_field_name("pattern")
                value = n.child_by_field_name("value")
                name = _bound(src, n) if pattern is not None else None
                if name is not None and (
                    pattern.type != "tuple_struct_pattern" or value is not None
                ):
                    bound.setdefault(name, []).append(value)
                else:
                    for x in _pattern_names(src, pattern):
                        bound.setdefault(x, []).append(None)
            elif n.type in ("assignment_expression", "compound_assignment_expr"):
                left = n.child_by_field_name("left")
                while left is not None and left.type in ("field_expression", "index_expression"):
                    left = left.named_children[0]
                if left is not None and left.type == "identifier":
                    assigned.add(src.text(left))
            elif (
                n.type == "call_expression"
                and _MUTATORS.match(_call_name(src, n))
                and (root := _root(_receiver(n))) is not None
            ) or (
                n.type == "reference_expression"
                and any(c.type == "mutable_specifier" for c in n.children)
                and (root := _root(n.child_by_field_name("value"))) is not None
            ):
                assigned.add(src.text(root))  # `user.id.clone_from(..)`, `&mut user`
            elif n.type in ("for_expression", "closure_expression", "match_arm", "let_condition"):
                pattern = n.child_by_field_name("pattern") or n.child_by_field_name("parameters")
                if pattern is not None and pattern.type == "match_pattern":
                    pattern = pattern.named_children[0] if pattern.named_children else None
                for x in _pattern_names(src, pattern):
                    bound.setdefault(x, []).append(None)
        self.callers -= set(bound) | assigned
        self.requests -= set(bound) | assigned
        self.roots &= self.callers
        base = set(self.callers)
        found: set[str] = set()
        while True:
            self.callers = base | found
            more = {
                n
                for n, values in bound.items()
                if n not in found
                and n not in assigned
                and values
                and all(v is not None and self.derived(v) for v in values)
            }
            if not more:
                return
            found |= more

    def derived(self, node: Node | None, depth: int = 0) -> bool:
        """`user.id`, `&claims.sub`, `user.id.to_string()`, `Uuid::parse_str(&claims.sub)?`: built
        only from the caller (never a fallback or another input)."""
        src = self.src
        node = _unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return False
        if node.type in ("identifier", "self"):
            return src.text(node) in self.callers
        if node.type == "field_expression":
            return self.derived(node.child_by_field_name("value"), depth + 1)
        if node.type == "type_cast_expression":
            return self.derived(node.child_by_field_name("value"), depth + 1)
        if node.type == "call_expression":
            args = _args(node)
            receiver = _receiver(node)
            name = _call_name(src, node)
            if self.request_caller(node):
                return True
            if receiver is not None:
                return (
                    name in _CALLER_METHODS
                    and all(a.type == "string_literal" for a in args)
                    and self.derived(receiver, depth + 1)
                )
            if name == "format_":
                literal = args[0] if args else None
                if literal is None or literal.type != "string_literal":
                    return False
                captured = re.findall(r"(?<!\{)\{([A-Za-z_]\w*)", src.text(literal))
                return (
                    len(args) + len(captured) > 1
                    and all(c in self.callers for c in captured)
                    and all(self.derived(a, depth + 1) for a in args[1:])
                )
            return name in _CONVERTERS and len(args) == 1 and self.derived(args[0], depth + 1)
        return False

    def identity(self, node: Node | None) -> bool:
        """A caller value naming who the caller is (`user.id`, `claims.sub`), not an attribute of
        theirs (`user.is_admin`)."""
        if not self.derived(node):
            return False
        node = _unwrap(node)
        while node is not None and node.type == "call_expression" and _receiver(node) is not None:
            node = _unwrap(_receiver(node))
        if node is None or node.type != "field_expression":
            return True
        return bool(_IDENTITY.match(self.src.text(node.child_by_field_name("field"))))

    def request_caller(self, node: Node) -> bool:
        """`req.extensions().get::<User>()` (server code put it there), or a crate function
        handed only the request that returns one (`auth::get_current_user(&req)`)."""
        src = self.src
        if not self.requests:
            return False
        if _extension_read(src, node, self.requests):
            return True
        if _receiver(node) is not None or not (path := _path_of(src, node)):
            return False
        args = _args(node)
        if len(args) != 1 or _idents(src, args[0]) - self.requests or not _idents(src, args[0]):
            return False
        found = self.code.resolve(src, path, node)  # type: ignore[arg-type]
        if not found or len(found) != 1:
            return False
        target = found[0]
        params = target.node.child_by_field_name("parameters")
        names = [
            x
            for p in (params.named_children if params is not None else [])
            if p.type == "parameter"
            for x in _pattern_names(target.src, p.child_by_field_name("pattern"))
        ]
        body = _statements(target.node.child_by_field_name("body"))
        return (
            len(names) == 1
            and len(body) == 1
            and _is_tail(body[0])
            and _extension_read(target.src, _expr(body[0]), set(names))
        )


def _extension_read(src: Parsed, node: Node | None, requests: set[str]) -> bool:
    """`req.extensions().get::<User>()`, through `.cloned()`, `.ok_or(..)` and the like."""
    node = _unwrap(node)
    while node is not None and node.type == "call_expression":
        name = _call_name(src, node)
        if name == "get":
            fn = node.child_by_field_name("function")
            m = re.search(r"::<\s*([\w:]+)\s*>\s*$", src.text(fn)) if fn is not None else None
            inner = _unwrap(_receiver(node))
            return (
                m is not None
                and bool(_CALLER_TYPE.match(_last(m.group(1))))
                and inner is not None
                and inner.type == "call_expression"
                and _call_name(src, inner) == "extensions"
                and src.text(_unwrap(_receiver(inner))) in requests
            )
        if name not in (*_CALLER_METHODS, "cloned", "map", "ok_or", "ok_or_else", "to_owned"):
            return False
        if name == "map" and not all(
            a.type == "closure_expression"
            and re.fullmatch(r"\|\s*(\w+)\s*\|\s*\1\s*\.\s*(clone|to_owned)\s*\(\s*\)", src.text(a))
            for a in _args(node)
        ):
            return False
        node = _unwrap(_receiver(node))
    return False


def _own(fn: Node) -> Iterator[Node]:
    """A function's own nodes: closures and blocks run inline; nested items don't."""
    stack = [fn.child_by_field_name("body") or fn]
    if (params := fn.child_by_field_name("parameters")) is not None:
        stack.append(params)
    while stack:
        n = stack.pop()
        yield n
        stack.extend(
            reversed(
                [c for c in n.children if c.type not in ("function_item", "impl_item", "mod_item")]
            )
        )


class _Walk:
    """One function body: its lookups by id, hand-offs, and the ids each allow-listed statement
    directly in the body verifies from its end on."""

    def __init__(
        self,
        o: RustOwnership,
        target: _Fn,
        ids: dict[str, str],
        callers: set[str],
        types: dict[str, str],
        depth: int,
        verified: set[str],
        requests: set[str] = frozenset(),  # type: ignore[assignment]
    ) -> None:
        self.o, self.code, self.target, self.depth = o, o.code, target, depth
        self.src, self.fn = target.src, target.node
        self.types = dict(types)
        self.params: list[str] = []
        params = self.fn.child_by_field_name("parameters")
        for p in params.named_children if params is not None else []:
            if p.type == "self_parameter":
                self.params.append("self")
                if target.owner:
                    self.types["self"] = target.owner
            elif p.type == "parameter":
                names = _pattern_names(self.src, p.child_by_field_name("pattern"))
                self.params += names
                if len(names) == 1 and (t := p.child_by_field_name("type")) is not None:
                    self.types.setdefault(names[0], self.src.text(t))
            elif p.type == "identifier":  # a closure's untyped parameter
                self.params.append(self.src.text(p))
        self.v = _Values(self.src, self.fn, callers, set(requests), self.code)
        self.root: dict[str, str] = dict(ids)
        # each id name and the path id it holds exactly; a name bound again to anything else
        # still carries an id (never verified), whichever binding a use sees
        bindings: dict[str, list[str]] = {i: [r] for i, r in ids.items()}
        for n in sorted(
            (n for n in _own(self.fn) if n.type == "let_declaration"), key=lambda n: n.start_byte
        ):
            value = n.child_by_field_name("value")
            pattern = n.child_by_field_name("pattern")
            if (
                (t := n.child_by_field_name("type")) is not None
                and pattern is not None
                and pattern.type == "identifier"
            ):
                self.types[self.src.text(pattern)] = self.src.text(t)
            names = _pattern_names(self.src, pattern)
            carries = (
                value is not None
                and bool(_idents(self.src, value) & set(self.root))
                and not self.loads(value)
                and not self.v.derived(value)
            )
            for x in names:
                single = len(names) == 1 and pattern.type in ("identifier", "mut_pattern")
                exact = self.exact(value) if carries and single else None
                if carries:
                    self.root[x] = exact or x
                bindings.setdefault(x, []).append(self.root[x] if carries else "")
        self.unstable = {
            n for n, roots in bindings.items() if n in self.root and len(set(roots)) > 1
        } | (_assigned(self.src, self.fn) & self.root.keys())
        for n in self.unstable:
            self.root[n] = n
        self.ids = set(self.root)
        self.lookups: list[Lookup] = []
        self.cover: list[set[str] | None] = []
        self.starts: list[int] = []
        self.reads: list[bool] = []
        self.sessions: list[bool] = []
        self.made: dict[int, list[int]] = {}
        self.query_lookups: set[int] = set()
        self.queries: dict[str, int] = {}
        self.consumed: set[int] = set()
        self.targets: list[str | None] = []
        self.hop_verified: dict[int, set[tuple[str, str]]] = {}
        self.hop_owned: dict[int, set[tuple[str, str]]] = {}
        self.handoffs: list[tuple[CodeSpan, set[str] | None, int]] = []
        self.hop: CodeSpan | None = None
        self.caller = next(
            (
                self.span(n)
                for n in _own(self.fn)
                if (n.type in ("identifier", "self") and self.src.text(n) in self.v.roots)
                or (n.type == "call_expression" and self.v.request_caller(n))
            ),
            None,
        )
        self.session_names = {
            _bound(self.src, n)
            for n in _own(self.fn)
            if n.type == "let_declaration" and self.session(n.child_by_field_name("value"))
        } - {None}
        # (id, store or table, from, to): where an allow-listed statement verified an id
        self.verified: list[tuple[str, str, int, int]] = []
        self.owned_or_null: list[tuple[str, str, int]] = []

    def span(self, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.src.file.rel), line=self.src.line(node))

    def text(self, node: Node | None) -> str:
        return self.src.text(node)

    def session(self, value: Node | None) -> bool:
        """`user_db.begin(&authed)`: a session or transaction opened for the caller (D28)."""
        value = _unwrap(value)
        while (
            value is not None
            and value.type == "call_expression"
            and _call_name(self.src, value) in ("unwrap", "expect", "context", "map_err")
        ):
            value = _unwrap(_receiver(value))
        return (
            value is not None
            and value.type == "call_expression"
            and bool(_SESSION.match(_call_name(self.src, value)))
            and any(self.v.derived(a) for a in _args(value))
        )

    def exact(self, node: Node | None) -> str | None:
        """The path id a value is exactly: the id, or a conversion of it."""
        node = _unwrap(node)
        if node is None:
            return None
        if node.type == "identifier":
            return self.root.get(self.text(node))
        if node.type == "field_expression":
            value = _unwrap(node.child_by_field_name("value"))
            key = f"{self.text(value)}.{self.text(node.child_by_field_name('field'))}"
            if key in self.root:
                return self.root[key]
            return None
        if node.type == "type_cast_expression":
            return self.exact(node.child_by_field_name("value"))
        if node.type == "call_expression":
            args, receiver, name = _args(node), _receiver(node), _call_name(self.src, node)
            if receiver is not None and (
                (name in _CONVERSIONS and all(a.type == "string_literal" for a in args))
                or (name in _ADAPTERS and not any(self.has_id(a) for a in args))
            ):
                return self.exact(receiver)
            if receiver is None and name in _CONVERTERS and len(args) == 1:
                return self.exact(args[0])
            segs = _segments(_path_of(self.src, node))
            if (
                receiver is None
                and len(segs) == 2
                and segs[0] in _ID_TYPES
                and args
                and all(a.type in ("integer_literal", "string_literal") for a in args[1:])
            ):
                return self.exact(args[0])  # `i64::from_str_radix(&id, 36)`
        return None

    def exact_ids(self, values: list[Node]) -> set[str] | None:
        roots = [self.exact(v) for v in values if _idents(self.src, v) & self.ids]
        return None if not roots or None in roots else {r for r in roots if r}

    def has_id(self, node: Node | None) -> bool:
        return bool(_idents(self.src, node) & self.root.keys())

    def loads(self, value: Node) -> bool:
        """Whether a value is (or wraps) a call or index that may load something by an id."""
        ids = set(self.root)
        for n in walk(value):
            if n.type == "call_expression":
                if self.exact(n) is not None or _call_name(self.src, n) in _BUILDERS:
                    continue
                if any(_idents(self.src, a) & ids for a in _args(n)):
                    return True
            elif n.type == "index_expression" and len(n.named_children) == 2:
                if _idents(self.src, n.named_children[1]) & ids:
                    return True
        return False

    def add(
        self,
        node: Node,
        lookup: Lookup,
        *,
        read: bool,
        cover: set[str] | None,
        session: bool = False,
        target: str | None = None,
    ) -> int:
        k = len(self.lookups)
        self.lookups.append(lookup)
        self.cover.append(cover)
        self.targets.append(target)
        self.starts.append(node.start_byte)
        self.reads.append(read)
        self.sessions.append(session)
        self.made.setdefault(node.id, []).append(k)
        return k

    def handoff(self, node: Node, cover: set[str] | None) -> None:
        self.handoffs.append((self.span(node), cover, node.start_byte))

    def verify(self, pairs: set[tuple[str, str]], at: int, end: int = _END) -> None:
        self.verified += [(r, t, at, end) for r, t in pairs if r not in self.unstable]

    def pairs(self, k: int) -> set[tuple[str, str]]:
        """What lookup `k` verifies once refused: its exact ids, for its own store or table."""
        target = self.targets[k]
        return {(r, target) for r in self.cover[k] or set()} if target else set()

    # ---- the walk
    def run(self) -> _Scan:
        nodes = [
            n
            for n in _own(self.fn)
            if n.type in ("call_expression", "index_expression", "macro_invocation")
        ]
        nodes.sort(key=lambda n: n.start_byte)
        for n in nodes:
            if n.type == "call_expression":
                self.query(n)
        for n in nodes:
            if n.type == "call_expression":
                self.call(n)
            elif n.type == "index_expression":
                self.index(n)
            else:
                self.macro(n)
        body = _statements(self.fn.child_by_field_name("body"))
        following: list[list[Node]] = [[] for _ in body]
        after: list[Node] = []
        for k in range(len(body) - 1, -1, -1):
            following[k] = after
            if not self.caller_declaration(body[k]):
                after = [body[k], *after[:1]]
        for k, (stmt, nxt) in enumerate(zip(body, following, strict=True)):
            self.statement(stmt, nxt, tail=k == len(body) - 1 and _is_tail(stmt))
        return self.result(self.first_return(body), self.pure_read(body))

    def first_return(self, body: list[Node]) -> int | None:
        for stmt in body:
            if any(
                n.type in ("return_expression", "try_expression")
                or (
                    n.type == "token_tree"
                    and any(self.text(c) in ("return", "?") for c in n.children)
                )
                # a macro we don't know may expand to a `return` (`allow_if!(..)`)
                or (
                    n.type == "macro_invocation"
                    and not _LOG_MACROS.match(
                        name := _last(self.text(n.child_by_field_name("macro")))
                    )
                    and name not in _FORMAT_MACROS
                )
                for n in walk(stmt)
            ):
                return stmt.start_byte
        return None

    # ---- queries: sqlx, diesel, sea-orm
    def chain(self, call: Node) -> list[Node]:
        """`call` and the method calls built on it, in order."""
        out, node = [call], call
        while True:
            parent = node.parent
            while parent is not None and parent.type in ("try_expression", "await_expression"):
                node, parent = parent, parent.parent
            if not (
                parent is not None
                and parent.type == "field_expression"
                and parent.child_by_field_name("value") == node
            ):
                return out
            above = parent.parent
            if above is not None and above.type == "generic_function":
                above = above.parent
            if above is None or above.type != "call_expression":
                return out
            node = above
            out.append(node)

    def query(self, root: Node) -> None:
        if root.id in self.consumed:
            return
        name = _call_name(self.src, root)
        path = _path_of(self.src, root)
        if name in _SQLX_MACROS:
            self.sqlx(root, name)
        elif (
            name in _SQLX_FUNCTIONS
            and _receiver(root) is None
            and (path.startswith("sqlx::") or path in _SQLX_FUNCTIONS)
        ) or (name == "sql_query" and _receiver(root) is None):
            self.sqlx(root, "query")
        elif _receiver(root) is None and (
            name in ("find_by_id", "delete_by_id")
            or (name in ("find", "delete_many", "update_many") and "Entity" in _segments(path))
        ):
            self.sea(root)
        elif name in ("find", "filter") and self.diesel_root(_receiver(root)):
            self.diesel(root)

    def sqlx(self, root: Node, name: str) -> None:
        links = self.chain(root)
        args = _args(root)
        if name in _SQLX_MACROS:
            at = _SQLX_MACROS[name]
            sql_node = args[at] if len(args) > at else None
            values = args[at + 1 :]
            record = self.text(args[0]) if at == 1 and args else None
        else:
            sql_node = args[0] if args else None
            values = [a for c in links[1:] if _call_name(self.src, c) == "bind" for a in _args(c)]
            fn = root.child_by_field_name("function")
            m = (
                re.search(r"::<\s*_?\s*,?\s*([\w:]+)\s*>", self.text(fn))
                if fn is not None
                else None
            )
            record = m.group(1) if m and name == "query_as" else None
        self.consumed |= {c.id for c in links}
        if not any(self.has_id(v) for v in values):
            return
        sql = self.sql_text(sql_node)
        fetch = next(
            (_call_name(self.src, c) for c in links[1:] if _call_name(self.src, c) in _SQL_FETCH),
            None,
        )
        parsed = _sql(sql) if sql is not None else None
        scoped, cover = False, None
        if parsed is not None and parsed.equalities is not None:
            pairs = [(c, values[i]) for c, i in parsed.equalities if i < len(values)]
            if len(pairs) == len(parsed.equalities):
                scoped = any(OWNER_CHECK_RX.match(c) and self.v.derived(v) for c, v in pairs)
                cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
        record_type = self.sql_record(record, parsed, macro=name in _SQLX_MACROS)
        read = (
            parsed is not None
            and parsed.kind == "select"
            and not parsed.aggregate
            and fetch in _SQL_READ
        )
        session = any(
            _idents(self.src, a) & self.session_names
            for c in links[1:]
            if _call_name(self.src, c) in _SQL_FETCH
            for a in _args(c)
        )
        k = self.add(
            root,
            Lookup(self.span(root), scoped, record_type=record_type),
            read=read,
            cover=cover,
            session=session,
            target=f"table:{parsed.table}" if parsed is not None and parsed.table else None,
        )
        self.query_lookups.add(k)
        for c in links[1:]:
            self.made.setdefault(c.id, []).append(k)
        self.keep(links[-1], k)

    def sql_record(self, record: str | None, parsed: _Sql | None, *, macro: bool) -> str | None:
        """The record a query reads. A row type without an owner field is only a projection
        unless the macro checked it against the whole row (`query_as!(T, "select * …")`)."""
        typ = self.code.record(_last(record)) if record else None
        table = parsed.table if parsed is not None and parsed.table in self.code.fields else None
        if typ is not None and not record_ownerless(typ, self.code.fields):
            return typ
        if typ is not None and macro and parsed is not None and parsed.select_all:
            return typ
        return table

    def keep(self, last: Node, k: int) -> None:
        parent = last.parent
        while parent is not None and parent.type in ("try_expression", "await_expression"):
            parent = parent.parent
        if (
            parent is not None
            and parent.type == "let_declaration"
            and (name := _bound(self.src, parent))
        ):
            self.queries[name] = k
            pattern = parent.child_by_field_name("pattern")
            if (pattern is not None and pattern.type == "mut_pattern") or name in _assigned(
                self.src, self.fn
            ):
                x = self.lookups[k]
                self.lookups[k] = Lookup(x.span, False, x.checked, x.record_type)
                self.cover[k] = None

    def sql_text(self, node: Node | None) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type in ("string_literal", "raw_string_literal"):
            return "".join(self.text(c) for c in node.named_children if c.type == "string_content")
        if node.type == "identifier":
            # the one binding of the name, never reassigned or shadowed
            name = self.text(node)
            lets = [
                n
                for n in _own(self.fn)
                if n.type == "let_declaration"
                and name in _pattern_names(self.src, n.child_by_field_name("pattern"))
            ]
            if len(lets) == 1 and name not in _assigned(self.src, self.fn):
                return self.sql_text(lets[0].child_by_field_name("value"))
        return None

    def diesel_root(self, node: Node | None) -> bool:
        node = _unwrap(node)
        while (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node)
            in ("filter", "find", "select", "into_boxed", "order", "order_by", "limit")
        ):
            node = _unwrap(_receiver(node))
        if node is None:
            return False
        text = self.text(node)
        return node.type in ("scoped_identifier", "identifier") and (
            text.endswith("::table") or text.rsplit("::", 1)[-1] in self.code.fields
        )

    def diesel(self, root: Node) -> None:
        below = []
        node = _unwrap(_receiver(root))
        while node is not None and node.type == "call_expression":
            below.append(node)
            node = _unwrap(_receiver(node))
        table = self.text(node).removesuffix("::table").rsplit("::", 1)[-1] if node else None
        chain = [*reversed(below), *self.chain(root)]
        self.consumed |= {c.id for c in chain}
        values = [a for c in chain for a in _args(c)]
        if not any(self.has_id(v) for v in values):
            return
        pairs: list[tuple[str, Node]] | None = []
        for c in chain:
            name = _call_name(self.src, c)
            if name == "find" and len(_args(c)) == 1:
                pairs.append(("id", _args(c)[0]))
            elif name == "filter" and len(_args(c)) == 1:
                for p in self.diesel_eqs(_args(c)[0]):
                    if p is None:
                        pairs = None
                        break
                    pairs.append(p)
                if pairs is None:
                    break
            elif name in ("or_filter", "inner_join", "left_join", "left_outer_join", "union", "or"):
                pairs = None
                break
        scoped, cover = False, None
        if pairs is not None:
            scoped = any(OWNER_CHECK_RX.match(c) and self.v.derived(v) for c, v in pairs)
            cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
        fetch = [_call_name(self.src, c) for c in chain if _call_name(self.src, c) in _DIESEL_FETCH]
        typed = next(
            (
                m.group(1)
                for c in chain
                if (
                    m := re.search(
                        r"::<\s*([\w:]+)\s*>", self.text(c.child_by_field_name("function"))
                    )
                )
            ),
            None,
        )
        typed_record = self.code.record(typed) if typed else None
        if table in self.code.fields:
            record = table
        elif typed_record is not None and not record_ownerless(typed_record, self.code.fields):
            record = typed_record
        else:
            record = None
        read = bool(fetch) and fetch[0] in _DIESEL_READ and "optional" not in fetch[1:]
        session = any(
            _idents(self.src, a) & self.session_names
            for c in chain
            if _call_name(self.src, c) in _DIESEL_FETCH
            for a in _args(c)
        )
        k = self.add(
            root,
            Lookup(self.span(root), scoped, record_type=record),
            read=read or (bool(fetch) and fetch[0] == "first"),
            cover=cover,
            session=session,
            target=f"table:{table}" if table else None,
        )
        self.query_lookups.add(k)
        for c in chain:
            self.made.setdefault(c.id, []).append(k)
        self.keep(chain[-1], k)

    def diesel_eqs(self, node: Node) -> list[tuple[str, Node] | None]:
        node = _unwrap(node)
        if node is None or node.type != "call_expression":
            return [None]
        name = _call_name(self.src, node)
        receiver = _unwrap(_receiver(node))
        if name == "and" and receiver is not None and len(_args(node)) == 1:
            return [*self.diesel_eqs(receiver), *self.diesel_eqs(_args(node)[0])]
        if (
            name == "eq"
            and receiver is not None
            and len(_args(node)) == 1
            and receiver.type in ("identifier", "scoped_identifier")
        ):
            return [(_last(self.text(receiver)), _args(node)[0])]
        return [None]

    def sea(self, root: Node) -> None:
        links = self.chain(root)
        self.consumed |= {c.id for c in links}
        path = _path_of(self.src, root)
        values = [a for c in links for a in _args(c)]
        if not any(self.has_id(v) for v in values):
            return
        pairs: list[tuple[str, Node]] | None = []
        if _call_name(self.src, root) in ("find_by_id", "delete_by_id") and _args(root):
            pairs.append(("id", _args(root)[0]))
        for c in links[1:]:
            name = _call_name(self.src, c)
            if name == "filter" and len(_args(c)) == 1:
                arg = _unwrap(_args(c)[0])
                rec = (
                    _unwrap(_receiver(arg))
                    if arg is not None and arg.type == "call_expression"
                    else None
                )
                if (
                    arg is not None
                    and _call_name(self.src, arg) == "eq"
                    and rec is not None
                    and "Column::" in self.text(rec)
                    and len(_args(arg)) == 1
                ):
                    pairs.append((_snake(_last(self.text(rec))), _args(arg)[0]))
                else:
                    pairs = None
                    break
            elif re.search(r"join|related|linked|having|union", name):
                pairs = None
                break
        scoped, cover = False, None
        if pairs is not None:
            scoped = any(OWNER_CHECK_RX.match(c) and self.v.derived(v) for c, v in pairs)
            cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
        segs = _segments(path)
        module = (
            segs[-3]
            if len(segs) >= 3 and segs[-2] == "Entity"
            else (segs[-2] if len(segs) >= 2 else None)
        )
        record = module if module in self.code.fields else None
        fetch = [
            _call_name(self.src, c) for c in links[1:] if _call_name(self.src, c) in _SEA_FETCH
        ]
        session = any(
            _idents(self.src, a) & self.session_names
            for c in links[1:]
            if _call_name(self.src, c) in _SEA_FETCH
            for a in _args(c)
        )
        k = self.add(
            root,
            Lookup(self.span(root), scoped, record_type=record),
            read=fetch[:1] == ["one"],
            cover=cover,
            session=session,
            target=f"table:{module}" if module else None,
        )
        self.query_lookups.add(k)
        for c in links[1:]:
            self.made.setdefault(c.id, []).append(k)
        self.keep(links[-1], k)

    # ---- other reads by id
    def index(self, node: Node) -> None:
        """`notes[&id]`: a lookup in a store by the id."""
        if len(node.named_children) != 2 or not self.has_id(node.named_children[1]):
            return
        store = node.named_children[0]
        if self.v.derived(store):
            return
        record = self.store_record(store)
        self.add(
            node,
            Lookup(self.span(node), record_type=record),
            read=True,
            cover=self.exact_ids([node.named_children[1]]),
            target=self.store(store),
        )

    def macro(self, node: Node) -> None:
        """A macro whose tokens carry an id: a hand-off, unless it only formats or logs plain
        values (no call inside, which could act on the id: `json!({"n": NOTES.find(id)})`)."""
        tokens = next((c for c in node.named_children if c.type == "token_tree"), None)
        if tokens is None or not _idents(self.src, tokens) & self.ids:
            return
        name = _last(self.text(node.child_by_field_name("macro")))
        if (_LOG_MACROS.match(name) or name in _FORMAT_MACROS) and not _calls_in(tokens):
            return
        self.handoff(node, None)

    def store(self, store: Node | None) -> str:
        """The store a lookup reads, by its declared type, else as written."""
        return f"store:{self.type_of(store) or self.text(_unwrap(store))}"

    def store_record(self, store: Node | None) -> str | None:
        typ = self.type_of(store)
        return self.code.value_type(typ) if typ else None

    def type_of(self, node: Node | None, depth: int = 0) -> str | None:
        """The declared type of a receiver, through fields, statics and pass-through methods."""
        node = _unwrap(node)
        if node is None or depth > 16:
            return None
        if node.type in ("identifier", "self"):
            name = self.text(node)
            return self.types.get(name) or self.code.statics.get(name)
        if node.type == "field_expression":
            owner = self.type_of(node.child_by_field_name("value"), depth + 1)
            if owner is None:
                return None
            if self.code.types.get(_strip(owner), 0) > 1:
                return None  # two structs so named: which one isn't told
            fields = self.code.structs.get(_strip(owner), {})
            return fields.get(self.text(node.child_by_field_name("field")))
        if node.type == "call_expression" and _call_name(self.src, node) in _TRANSPARENT:
            inner = self.type_of(_receiver(node), depth + 1)
            if inner is None:
                return None
            name, args = _generic(inner)
            return args[0] if name in _WRAPPERS and len(args) == 1 else inner
        return None

    def call(self, call: Node) -> None:
        if call.id in self.consumed:
            return
        src = self.src
        name = _call_name(src, call)
        receiver = _receiver(call)
        values = [
            a for a in _args(call) if _unwrap(a) is None or _unwrap(a).id not in self.consumed
        ]
        closures = [a for a in values if a.type == "closure_expression"]
        if not any(self.has_id(v) for v in values):
            if (
                receiver is not None
                and self.has_id(receiver)
                and self.exact(receiver) is None
                and _LOOKUP_NAME.match(name)
                and not self.v.derived(receiver)
            ):
                # an object built from the id, written or read (`model.update(&db)`)
                self.add(
                    call,
                    Lookup(self.span(call)),
                    read=False,
                    cover=None,
                    session=self.on_session(call),
                )
            return
        cover = self.exact_ids([v for v in values if self.has_id(v)])
        path = _path_of(src, call)
        span = self.span(call)
        if self.exact(call) is not None or _INERT_CALLS.match(path or name):
            return
        if name in _COMBINATORS and not (closures and name in _SEARCHES):
            return
        if name in _BUILDERS or (name in _RESPONSE_PARTS and _response(self.src, receiver)):
            return
        if (
            receiver is not None
            and not self.v.derived(receiver)
            and (name in _STORE_CALLS or (name in _SEARCHES and closures))
        ):
            typ = self.type_of(receiver)
            # a std collection's method, or one we can't place: not a checkout method of the type
            if (typ is not None and _collection(typ)) or (typ is None and name in _STORE_CALLS):
                record = self.store_record(receiver)
                self.add(
                    call,
                    Lookup(span, record_type=record),
                    read=name in _STORE_READS or name == "find",
                    cover=cover if name not in _SEARCHES else None,
                    target=self.store(receiver),
                )
                return
        if path and path[:1].isupper() and not re.search(r"::[a-z_]\w*$", path):
            # a tuple struct or variant built with the id (`NoteId(id)`): a value, not an action
            return
        targets = self.callees(call, receiver, path, name)
        if targets is None:
            if not _VALIDATOR_NAME.match(name):
                self.handoff(call, cover)
        elif targets:
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if self.accessor(call, targets) is not None:
                    return
                if not _VALIDATOR_NAME.match(name):
                    self.handoff(call, cover)
                return
            self.hop_into(call, targets)
        elif self.on_session(call):
            self.add(call, Lookup(span), read=False, cover=cover, session=True)
        elif (
            self.kept(call)
            and (receiver is None or not self.v.derived(receiver))
            and any(self.v.identity(v) for v in values)
        ):
            # shape 4: a kept load we can't follow, handed a caller-only value (D7)
            self.add(call, Lookup(span, True), read=False, cover=cover)
        elif _LOOKUP_NAME.match(name) and (receiver is None or not self.v.derived(receiver)):
            self.add(call, Lookup(span), read=False, cover=cover, session=self.on_session(call))
        elif not _VALIDATOR_NAME.match(name):
            self.handoff(call, cover)

    def on_session(self, call: Node) -> bool:
        return bool(
            self.session_names
            & (
                _idents(self.src, _receiver(call))
                | {n for a in _args(call) for n in _idents(self.src, a)}
            )
        )

    def callees(self, call: Node, receiver: Node | None, path: str, name: str) -> list[_Fn] | None:
        if receiver is None:
            return self.code.resolve(self.src, path, call) if path else []
        typ = self.type_of(receiver)
        if typ is None:
            return []
        return self.code.method(_strip(typ), name)

    def accessor(self, call: Node, targets: list[_Fn]) -> int | None:
        """At the hop limit, a function that only reads a container by its id parameter is the
        store itself: `fn find(&self, id) { self.0.lock().unwrap().get(&id).cloned() }`."""
        if len(targets) != 1:
            return None
        target = targets[0]
        body = _statements(target.node.child_by_field_name("body"))
        if len(body) != 1 or body[0].type not in ("call_expression", "index_expression"):
            return None
        params = [
            _pattern_names(target.src, p.child_by_field_name("pattern"))
            for p in target.node.child_by_field_name("parameters").named_children
            if p.type == "parameter"
        ]
        if any(len(p) != 1 for p in params):
            return None
        expr = body[0]
        while expr.type == "call_expression" and _call_name(target.src, expr) in (
            "cloned",
            "clone",
            "copied",
            "is_some",
            "map",
            "unwrap_or_default",
        ):
            expr = _unwrap(_receiver(expr))
            if expr is None:
                return None
        if expr.type != "call_expression" or _call_name(target.src, expr) not in _STORE_CALLS:
            return None
        receiver = _unwrap(_receiver(expr))
        if receiver is None or _idents(target.src, receiver) - {"self"}:
            return None
        inner = _Walk(self.o, target, {}, set(), {}, self.depth + 1, set())
        record = inner.store_record(receiver)
        name = _call_name(target.src, expr)
        args = _args(call)
        mapping = dict(zip([p[0] for p in params], args, strict=False))
        used = [mapping[n] for n in _idents(target.src, expr) & set(mapping)]
        cover = self.exact_ids([v for v in used if self.has_id(v)])
        lookup = Lookup(
            CodeSpan(path=RepoPath(target.src.file.rel), line=target.src.line(expr)),
            record_type=record,
        )
        target_store = inner.store(receiver)
        return self.add(call, lookup, read=name in _STORE_READS, cover=cover, target=target_store)

    def kept(self, call: Node) -> bool:
        """`let r = call(..).await.map_err(..)?`: the value bound to a local (`_` drops it)."""
        node, parent = call, call.parent
        while parent is not None:
            if parent.type in ("try_expression", "await_expression"):
                node, parent = parent, parent.parent
            elif (
                parent.type == "field_expression"
                and parent.child_by_field_name("value") == node
                and parent.parent is not None
                and parent.parent.type == "call_expression"
                and _call_name(self.src, parent.parent) in _ADAPTERS
            ):
                node, parent = parent.parent, parent.parent.parent
            else:
                break
        return (
            parent is not None
            and parent.type == "let_declaration"
            and _bound(self.src, parent) not in (None, "_")
        )

    def hop_into(self, call: Node, targets: list[_Fn]) -> None:
        self.hop = self.hop or self.span(call)
        verified: set[str] | None = None
        owned: set[str] | None = None
        for target in targets:
            scan, exact = self.o.hop(self, target, call)

            def mapped(inner: set[str] | None, exact: dict[str, str] = exact) -> set[str] | None:
                return {exact[p] for p in inner} if inner and inner <= exact.keys() else None

            for x, read, inner, where in zip(
                scan.facts.lookups, scan.reads, scan.covers, scan.targets, strict=True
            ):
                self.add(
                    call,
                    Lookup(x.span, x.scoped, x.checked, x.record_type),
                    read=read and scan.pure_read,
                    cover=mapped(inner),
                    target=where,
                )
            self.caller = self.caller or scan.facts.caller
            if scan.facts.handoff:
                self.handoffs.append(
                    (scan.facts.handoff, mapped(scan.handoff_cover), call.start_byte)
                )
            v = {(exact[p], t) for p, t in scan.verified if p in exact}
            o = {(exact[p], t) for p, t in scan.owned_or_null if p in exact}
            verified = v if verified is None else verified & v
            owned = o if owned is None else owned & o
        self.hop_verified[call.id] = verified or set()
        self.hop_owned[call.id] = owned or set()

    # ---- the allow-listed statements (D8, D25)
    def load(self, expr: Node | None) -> int | None:
        """The one read an expression is, unwrapped of `?`, `.await` and absence refusals; never a
        fallback, the query itself or a list."""
        expr = self.strip_absence(expr)[0]
        if expr is None or expr.type not in ("call_expression", "index_expression", "identifier"):
            return None
        if expr.type == "identifier":
            k = self.queries.get(self.text(expr))
            return k if k is not None and self.reads[k] else None
        if any(
            n.type in ("if_expression", "match_expression", "binary_expression") for n in walk(expr)
        ):
            return None
        made = {k for n in walk(expr) for k in self.made.get(n.id, [])}
        if len(made) != 1:
            return None
        k = next(iter(made))
        return k if self.reads[k] else None

    def strip_absence(self, expr: Node | None) -> tuple[Node | None, bool]:
        """(the load inside `x.await?.ok_or(E)?`, whether absence is refused there)."""
        refused = False
        node = expr
        while True:
            node2 = node
            if node2 is not None and node2.type == "try_expression":
                inner = node2.named_children[0] if node2.named_children else None
                if (
                    inner is not None
                    and inner.type == "call_expression"
                    and (
                        _call_name(self.src, inner) in ("ok_or", "ok_or_else")
                        # anyhow's `.context(..)?` refuses a `None` only once the fetch's own
                        # error is handed on: `fetch_optional(..).await?.context(..)?`
                        or (
                            _call_name(self.src, inner) in ("context", "with_context")
                            and (r := _receiver(inner)) is not None
                            and r.type == "try_expression"
                        )
                    )
                ):
                    refused = True
                    node = _receiver(inner)
                    continue
                node = inner
                continue
            if node2 is not None and node2.type in (
                "await_expression",
                "parenthesized_expression",
                "reference_expression",
            ):
                node = node2.named_children[0] if node2.named_children else None
                continue
            return node, refused

    def raises_on_absence(self, expr: Node | None, k: int) -> bool:
        """A fetch that errors when nothing matched, its error handed on with `?` (through
        `.await` and error adapters): sqlx `fetch_one`, diesel `first`."""
        node, tried = expr, False
        while node is not None:
            if node.type == "try_expression":
                tried, node = True, (node.named_children[0] if node.named_children else None)
            elif node.type in ("await_expression", "parenthesized_expression"):
                node = node.named_children[0] if node.named_children else None
            elif node.type == "call_expression":
                name = _call_name(self.src, node)
                if name in ("fetch_one", "first", "get_result"):
                    return tried
                if name not in ("map_err", "context", "with_context"):
                    return False
                node = _receiver(node)
            else:
                return False
        return False

    def try_after(self, node: Node) -> bool:
        parent = node.parent
        while parent is not None and parent.type == "await_expression":
            parent = parent.parent
        return parent is not None and parent.type == "try_expression"

    def statement(self, stmt: Node, following: list[Node], *, tail: bool) -> None:
        value = _expr(stmt)
        if value is None:
            return
        end = stmt.end_byte
        if (call := self.propagated(value)) is not None:
            # a hop whose refusal (an `Err`) the handler hands on with `?`
            self.verify(self.hop_verified.get(call.id, set()), end)
        if self.match_check(value, tail) or self.if_let_check(value, tail):
            return
        _, absent_inline = self.strip_absence(value)
        if stmt.type == "let_declaration" and stmt.child_by_field_name("alternative") is not None:
            absent_inline = absent_inline or self.refusal(
                stmt.child_by_field_name("alternative"), tail=False
            )
        k = self.load(value)
        scoped = k is not None and self.lookups[k].scoped
        if scoped and self.reads[k] and (absent_inline or self.raises_on_absence(value, k)):
            # shape 1, refused when absent
            self.verify(self.pairs(k), end)
        if (
            tail
            and k is None
            and (hop := self.hop_call(value)) is not None
            and self.absence_refused_tail(value)
        ):
            self.verify(self.hop_owned.get(hop.id, set()), end)
        if tail and k is not None and self.filters_owned(value):
            self.checked(k)
        record = _bound(self.src, stmt)
        if record is None or not following:
            if record is not None and k is not None and self.filters_owned(value):
                self.checked(k)
            return
        nxt = following[0]
        absent = (
            absent_inline
            or self.raises_on_absence(value, k if k is not None else -1)
            or self.refuses_absence(nxt, record)
        )
        if scoped and absent and self.reads[k]:  # type: ignore[index]
            self.verify(self.pairs(k), nxt.end_byte)  # type: ignore[arg-type]
        check = following[1] if self.refuses_absence(nxt, record) and len(following) > 1 else nxt
        if k is not None and absent and self.refuses_foreign(check, record):
            # shape 2: the load, then a refusal of a record the caller doesn't own
            self.checked(k)
            self.verify(self.pairs(k), check.end_byte)
        elif k is not None and self.filters_owned(value):
            # shape 5 inline: `load.filter(|r| r.owner == me)`
            self.checked(k)
            self.owned_or_null += [(r, t, stmt.start_byte) for r, t in self.pairs(k)]
        elif (hop := self.hop_call(value)) is not None and absent:
            # a hop that returns its record only when owned, refused when absent
            self.verify(self.hop_owned.get(hop.id, set()), nxt.end_byte)

    def propagated(self, value: Node | None) -> Node | None:
        """`hop(..)?` / `hop(..).await?`: the hop call whose `Err` the caller returns."""
        if value is None or value.type != "try_expression" or not value.named_children:
            return None
        node = value.named_children[0]
        while node.type == "await_expression" and node.named_children:
            node = node.named_children[0]
        return node if node.type == "call_expression" else None

    def hop_call(self, value: Node | None) -> Node | None:
        node, _ = self.strip_absence(value)
        while (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node) in ("map", "ok_or", "ok_or_else")
        ):
            node = _unwrap(_receiver(node))
        return (
            node
            if node is not None and node.type == "call_expression" and node.id in self.hop_owned
            else None
        )

    def absence_refused_tail(self, value: Node | None) -> bool:
        """`hop(..).map(Json).ok_or(StatusCode::NOT_FOUND)` returned: a missing record is the
        refusal (D25)."""
        node = _unwrap(value)
        return (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node) in ("ok_or", "ok_or_else")
            and self.refusal_value(_args(node)[0] if _args(node) else None, err=True)
        )

    def filters_owned(self, value: Node | None) -> bool:
        """`load.filter(|r| r.<owner> == <caller>)`: shape 5, the record returned only if owned."""
        node = _unwrap(value)
        while node is not None and node.type == "call_expression":
            if _call_name(self.src, node) == "filter" and len(_args(node)) == 1:
                closure = _args(node)[0]
                if closure.type == "closure_expression":
                    params = _pattern_names(self.src, closure.child_by_field_name("parameters"))
                    body = closure.child_by_field_name("body")
                    if (
                        len(params) == 1
                        and body is not None
                        and self.compares_all(body, params[0], negated=False)
                    ):
                        return (
                            self.load(_receiver(node)) is not None
                            or self.hop_call(_receiver(node)) is not None
                        )
                return False
            node = _unwrap(_receiver(node))
        return False

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)

    def caller_declaration(self, stmt: Node) -> bool:
        return stmt.type == "let_declaration" and _bound(self.src, stmt) in self.v.callers

    def refuses_absence(self, stmt: Node, record: str) -> bool:
        """`let Some(r) = r else { return Err(..) };`, `let r = r.ok_or(E)?;`"""
        if stmt.type != "let_declaration" or _bound(self.src, stmt) != record:
            return False
        value = stmt.child_by_field_name("value")
        if stmt.child_by_field_name("alternative") is not None:
            return self.text(_unwrap(value)) == record and self.refusal(
                stmt.child_by_field_name("alternative"), tail=False
            )
        inner, refused = self.strip_absence(value)
        return refused and inner is not None and self.text(inner) == record

    def refuses_foreign(self, stmt: Node, record: str) -> bool:
        """`if r.<owner> != <caller> { return Err(..) }` or `ensure!(r.owner == me, ..)`, and
        nothing else."""
        expr = _expr(stmt)
        if expr is None:
            return False
        if (
            expr.type == "call_expression"
            and _call_name(self.src, expr) == "ensure_"
            and _receiver(expr) is None
        ):
            args = _args(expr)
            return bool(args) and self.compares_all(args[0], record, negated=False)
        if expr.type != "if_expression" or expr.child_by_field_name("alternative") is not None:
            return False
        condition = expr.child_by_field_name("condition")
        if condition is None or condition.type in ("let_condition", "let_chain"):
            return False
        consequence = expr.child_by_field_name("consequence")
        return (
            self.refusal(consequence, tail=False)
            and record not in _idents(self.src, consequence)  # a 403 carrying the record leaks it
            and self.compares_any(condition, record)
        )

    def compares_any(self, cond: Node, record: str) -> bool:
        """A disjunction with a part refusing a foreign record: `r.owner != me || ..`."""
        cond = _unwrap(cond) if cond.type == "parenthesized_expression" else cond
        if cond is None:
            return False
        if cond.type == "binary_expression" and _op(cond) == "||":
            return any(
                self.compares_any(s, record)
                for s in (cond.child_by_field_name("left"), cond.child_by_field_name("right"))
                if s is not None
            )
        return self.compares(cond, record, negated=True)

    def compares_all(self, cond: Node, record: str, *, negated: bool) -> bool:
        """A conjunction with a part requiring an owned record: `r.owner == me && ..`."""
        if cond.type == "parenthesized_expression" and cond.named_children:
            cond = cond.named_children[0]
        if cond.type == "binary_expression" and _op(cond) == "&&":
            return any(
                self.compares_all(s, record, negated=negated)
                for s in (cond.child_by_field_name("left"), cond.child_by_field_name("right"))
                if s is not None
            )
        return self.compares(cond, record, negated=negated)

    def compares(self, part: Node, record: str, *, negated: bool) -> bool:
        if part.type == "parenthesized_expression" and part.named_children:
            return self.compares(part.named_children[0], record, negated=negated)
        if (
            negated
            and part.type == "unary_expression"
            and part.children
            and part.children[0].type == "!"
        ):
            return bool(part.named_children) and self.compares(
                part.named_children[0], record, negated=False
            )
        if part.type != "binary_expression" or _op(part) != ("!=" if negated else "=="):
            return False
        sides = (part.child_by_field_name("left"), part.child_by_field_name("right"))
        return any(self.owner_of(a, record) and self.v.derived(b) for a, b in (sides, sides[::-1]))

    def owner_of(self, node: Node | None, record: str) -> bool:
        node = _unwrap(node)
        while (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node) in _CONVERSIONS
            and not _args(node)
        ):
            node = _unwrap(_receiver(node))
        if node is None or node.type != "field_expression":
            return False
        value = _unwrap(node.child_by_field_name("value"))
        return (
            value is not None
            and value.type == "identifier"
            and self.text(value) == record
            and bool(OWNER_CHECK_RX.match(self.text(node.child_by_field_name("field"))))
        )

    def refusal(self, node: Node | None, *, tail: bool) -> bool:
        """D25: `return Err(..)`, `Err(..)?`, `bail!`, or a 401/403/404 response returned; in a
        tail position the value itself."""
        if node is None:
            return False
        if node.type == "block":
            stmts = _statements(node)
            # a block's value refuses only where the block is the value; a statement must exit
            return len(stmts) == 1 and self.refusal(
                _expr(stmts[0]), tail=tail and _is_tail(stmts[0])
            )
        if node.type == "expression_statement":
            return self.refusal(_expr(node), tail=False)
        if node.type == "return_expression":
            value = node.named_children[0] if node.named_children else None
            return self.refusal_value(value, err=True)
        if node.type == "try_expression":
            inner = node.named_children[0] if node.named_children else None
            return (
                inner is not None
                and inner.type == "call_expression"
                and _path_of(self.src, inner) == "Err"
            )
        if (
            node.type == "call_expression"
            and _call_name(self.src, node) == "bail_"
            and _receiver(node) is None
        ):
            return True
        return tail and self.refusal_value(node, err=True)

    def refusal_value(self, node: Node | None, *, err: bool) -> bool:
        """`Err(..)`, a 401/403/404 `StatusCode`, `HttpResponse::Forbidden()…`, `Ok(<that>)`."""
        node = _unwrap(node)
        if node is None:
            return False
        if node.type == "call_expression":
            path = _path_of(self.src, node)
            if path == "Err" and err:
                return True
            if path == "Ok" and len(_args(node)) == 1:
                return self.refusal_value(_args(node)[0], err=False)
            if _REFUSAL_RESPONSES.match(path) or _REFUSAL_ERRORS.match(path):
                return True
            if _receiver(node) is not None and _call_name(self.src, node) in (
                "finish",
                "json",
                "body",
                "into_response",
                "into",
                "build",
                "content_type",
                "insert_header",
            ):
                return self.refusal_value(_receiver(node), err=err)
            return False
        if node.type == "scoped_identifier":
            return self.text(node).rsplit("::", 1)[-1] in _REFUSALS and "StatusCode" in self.text(
                node
            )
        if node.type == "tuple_expression" and node.named_children:
            return self.refusal_value(node.named_children[0], err=False)
        return False

    def match_check(self, value: Node | None, tail: bool) -> bool:
        """`match <load> { Some(r) if r.owner == me => .., _ => <refusal> }`: shape 2 in one
        expression; what the owned arm runs is covered."""
        node = _unwrap(value)
        if node is None or node.type != "match_expression":
            return False
        k = self.load(node.child_by_field_name("value"))
        body = node.child_by_field_name("body")
        if k is None or body is None:
            return False
        arms = [a for a in body.named_children if a.type == "match_arm"]
        owned = None
        for arm in arms:
            pattern = arm.child_by_field_name("pattern")
            inner = (
                pattern.named_children[0]
                if pattern is not None and pattern.named_children
                else None
            )
            condition = pattern.child_by_field_name("condition") if pattern is not None else None
            names = (
                _pattern_names(self.src, inner)
                if inner is not None
                and inner.type == "tuple_struct_pattern"
                and self.text(inner.child_by_field_name("type")) in ("Some", "Ok")
                else []
            )
            if (
                owned is None
                and len(names) == 1
                and condition is not None
                and self.compares_all(condition, names[0], negated=False)
            ):
                owned = arm
            elif not self.refusal(arm.child_by_field_name("value"), tail=tail) or (
                _idents(self.src, arm.child_by_field_name("value"))
                & set(_pattern_names(self.src, inner))
            ):
                return False
        if owned is None:
            return False
        self.checked(k)
        start = owned.child_by_field_name("value")
        self.verify(self.pairs(k), start.start_byte if start is not None else node.end_byte)
        return True

    def if_let_check(self, value: Node | None, tail: bool) -> bool:
        """`if let Some(r) = <load> { if r.owner != me { return Err(..) } .. } else { refusal }`"""
        node = _unwrap(value)
        if node is None or node.type != "if_expression":
            return False
        condition = node.child_by_field_name("condition")
        if condition is None or condition.type != "let_condition":
            return False
        pattern = condition.child_by_field_name("pattern")
        names = (
            _pattern_names(self.src, pattern)
            if pattern is not None
            and pattern.type == "tuple_struct_pattern"
            and self.text(pattern.child_by_field_name("type")) in ("Some", "Ok")
            else []
        )
        k = self.load(condition.child_by_field_name("value"))
        alternative = node.child_by_field_name("alternative")
        if k is None or len(names) != 1:
            return False
        refused = False
        if alternative is not None:
            block = next((c for c in alternative.named_children if c.type == "block"), None)
            if not self.refusal(block, tail=tail):
                return False
            refused = True
        consequence = _statements(node.child_by_field_name("consequence"))
        if not consequence or not self.refuses_foreign(consequence[0], names[0]):
            return False
        self.checked(k)
        # without an `else` refusal, only the block the owned record reaches is covered
        block = node.child_by_field_name("consequence")
        self.verify(self.pairs(k), consequence[0].end_byte, _END if refused else block.end_byte)
        return True

    def pure_read(self, body: list[Node]) -> bool:
        """`<read>` returned, or `let r = <read>; r`, and nothing else."""
        if len(body) == 1:
            value = _expr(body[0]) if body[0].type != "expression_statement" else None
            if value is not None and value.type == "return_expression":
                value = value.named_children[0] if value.named_children else None
        elif (
            len(body) == 2
            and (name := _bound(self.src, body[0])) is not None
            and self.text(body[1]) in (name, f"Ok({name})", f"return {name}")
        ):
            value = _expr(body[0])
        else:
            return False
        node, _ = self.strip_absence(value)
        while (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node) in ("cloned", "clone", "copied", "map")
        ):
            node = _unwrap(_receiver(node))
        return len(self.lookups) == 1 and self.load(node) == 0

    def result(self, first_return: int | None, pure_read: bool) -> _Scan:
        verified = [v for v in self.verified if v[0] not in self.unstable]

        def holds(roots: set[str] | None, at: int, target: str | None) -> bool:
            """Every id verified at `at`, for `target` (any store, for a hand-off)."""
            return bool(roots) and all(
                any(
                    r == v
                    and (target == "*" or (target is not None and target == t))
                    and start <= at < end
                    for v, t, start, end in verified
                )
                for r in roots
            )

        unheld = [(span, roots) for span, roots, at in self.handoffs if not holds(roots, at, "*")]
        tail_owned = self.tail_owned()
        lookups = []
        for k, x in enumerate(self.lookups):
            covered = holds(self.cover[k], self.starts[k], self.targets[k])
            checked = x.checked or (not x.scoped and covered)
            if self.sessions[k] and not (x.scoped or checked):
                # D28: through a session bound to the caller: listed, neither judged nor credited
                unheld.append((x.span, self.cover[k]))
                continue
            lookups.append((k, Lookup(x.span, x.scoped, checked, x.record_type)))
        handoff, handoff_cover = unheld[0] if unheld else (None, None)
        before = first_return if first_return is not None else _END
        params = set(self.params) - self.unstable
        return _Scan(
            HandlerFacts(
                lookups=tuple(x for _, x in lookups),
                caller=self.caller,
                hop=self.hop,
                handoff=handoff,
            ),
            verified={
                (r, t) for r, t, at, end in verified if at <= before and end == _END and r in params
            },
            owned_or_null={
                (r, t) for r, t, at in self.owned_or_null if r in params and at <= before
            }
            | tail_owned,
            covers=tuple(self.cover[k] for k, _ in lookups),
            reads=tuple(self.reads[k] for k, _ in lookups),
            targets=tuple(self.targets[k] for k, _ in lookups),
            handoff_cover=handoff_cover,
            pure_read=pure_read,
        )

    def tail_owned(self) -> set[tuple[str, str]]:
        """Shape 5 as the function's value: `self.find(id).filter(|n| n.owner == owner)`."""
        body = _statements(self.fn.child_by_field_name("body"))
        if not body or not _is_tail(body[-1]):
            return set()
        tail = _expr(body[-1])
        if tail.type == "return_expression":
            tail = tail.named_children[0] if tail.named_children else tail
        k = self.load(self.filter_receiver(tail))
        if k is None or not self.filters_owned(tail):
            return set()
        self.checked(k)
        return {(r, t) for r, t in self.pairs(k) if r in set(self.params) - self.unstable}

    def filter_receiver(self, node: Node | None) -> Node | None:
        node = _unwrap(node)
        while node is not None and node.type == "call_expression":
            if _call_name(self.src, node) == "filter":
                return _receiver(node)
            node = _unwrap(_receiver(node))
        return None


class RustOwnership:
    """An axum or actix-web handler's ownership facts."""

    def __init__(self, code: RustCode) -> None:
        self.code = code

    def handler(self, rel: str, at: Node, handler: str, path_ids: set[str]) -> HandlerFacts:
        """`rel`/`at`: where the route names `handler` (or the handler itself, for a macro
        route); `path_ids`: its path parameters."""
        src = next((s for s in self.code.sources if s.file.rel == rel), None)
        span = CodeSpan(path=RepoPath(rel), line=at.start_point[0] + 1)
        if src is None:
            return HandlerFacts(handoff=span, takes_id=True)
        node = src.root.descendant_for_byte_range(at.start_byte, at.end_byte)
        while node is not None and (node.start_byte, node.end_byte) != (at.start_byte, at.end_byte):
            node = node.parent
        module = self.code.module_at(src, node)
        if node is not None and node.type in ("closure_expression", "function_item"):
            target = _Fn(src, node, module, _impl_owner(src, node))
        elif re.fullmatch(r"[\w:]+", handler):
            found = self.code.resolve(src, handler, node)
            if not found or len(found) != 1:
                return HandlerFacts(handoff=span, takes_id=True)
            target = found[0]
        else:
            return HandlerFacts(handoff=span, takes_id=True)
        ids, callers, types, unread, requests = self.parameters(target)
        if unread is not None:
            return HandlerFacts(handoff=unread, takes_id=True)
        if not ids:
            # the id may come from the request itself (`req.match_info()`, `req.uri()`)
            ids = {r: r for r in requests}
        scan = self.scan(target, ids, callers, types, 0, requests=requests)
        return HandlerFacts(
            lookups=scan.facts.lookups,
            caller=scan.facts.caller,
            hop=scan.facts.hop,
            handoff=scan.facts.handoff,
            takes_id=True,
            ignores_id=not ids,
        )

    def parameters(
        self, target: _Fn
    ) -> tuple[dict[str, str], set[str], dict[str, str], CodeSpan | None, set[str]]:
        """(the path ids, the caller names, declared types, an unreadable caller, request names)."""
        src = target.src
        ids: dict[str, str] = {}
        callers: set[str] = set()
        types: dict[str, str] = {}
        requests: set[str] = set()
        unread = None
        params = target.node.child_by_field_name("parameters")
        for p in params.named_children if params is not None else []:
            if p.type != "parameter":
                continue
            pattern, typ = p.child_by_field_name("pattern"), p.child_by_field_name("type")
            if typ is None:
                continue
            type_text = src.text(typ)
            outer, inner_args = _generic(type_text)
            outer = self.code.renamed.get(outer, outer)
            names = [n for n in _pattern_names(src, pattern) if n != "_"]
            if self.carries_path(type_text):
                for n in names:
                    ids[n] = n
                if pattern is not None and pattern.type == "identifier" and inner_args:
                    for f in self.code.structs.get(_strip(inner_args[0]), {}):
                        ids[f"{src.text(pattern)}.{f}"] = f"{src.text(pattern)}.{f}"
                continue
            if outer in _REQUEST_TYPES:
                requests |= set(names)
                continue
            if outer in ("Json", "Form", "Query", "Multipart", "Bytes", "State", "Data"):
                if pattern is not None and pattern.type == "identifier":
                    types[src.text(pattern)] = type_text
                elif len(names) == 1 and inner_args:
                    types[names[0]] = inner_args[0]
                continue
            if (
                outer in ("Extension", "ReqData")
                and inner_args
                and _CALLER_TYPE.match(_strip(inner_args[0]))
            ):
                callers |= set(names)  # server code put it there (D26)
                continue
            caller = self.caller_type(type_text)
            if caller is None:
                if len(names) == 1:
                    types[names[0]] = type_text
                continue
            kind = self.code.caller_kind(caller)
            if kind == "trusted":
                callers |= set(names)
            elif kind == "unread" and unread is None:
                unread = CodeSpan(path=RepoPath(src.file.rel), line=src.line(p))
        return ids, callers, types, unread, requests

    def carries_path(self, type_text: str, seen: frozenset[str] = frozenset()) -> bool:
        """`Path<i64>`, `web::Path<(u64,)>`, `WithRejection<Path<_>, _>`, `Result<Path<_>, _>`, an
        alias of `Path`, or a checkout extractor that reads the path itself."""
        for name in re.findall(r"[A-Za-z_]\w*", type_text):
            name = self.code.renamed.get(name, name)
            if name in _PATH_TYPES:
                return True
            if (
                name in self.code.aliases
                and name not in seen
                and self.carries_path(
                    self.code.aliases[name],
                    seen | {name},  # `type Result<T> = Result<T, E>` names itself
                )
            ):
                return True  # `type NotePath = Path<i64>;`
            impls = self.code.extractors.get(name, [])
            if any(
                re.search(r"\b(Path|RawPathParams|match_info|uri)\b", f.src.text(f.node))
                for f in impls
            ) and not _CALLER_TYPE.match(name):
                return True
        return False

    def caller_type(self, type_text: str) -> str | None:
        """The auth type a parameter carries: `AuthUser`, `Extension<User>`,
        `web::ReqData<Claims>`; None for anything else (an `Option` of one admits anyone)."""
        from traust_core.v1.providers.rust_routes import _is_guard

        for name in re.findall(r"[A-Za-z_]\w*", type_text):
            if (
                name not in _WRAPPERS
                and name not in ("web", "axum", "extract", "actix_web")
                and _is_guard(name)
            ):
                return name
        return None

    def scan(
        self,
        target: _Fn,
        ids: dict[str, str],
        callers: set[str],
        types: dict[str, str],
        depth: int,
        verified: set[str] | None = None,
        requests: set[str] | None = None,
    ) -> _Scan:
        key = (
            target.src.file.rel,
            target.node.start_byte,
            frozenset(ids.items()),
            frozenset(callers),
            depth,
            frozenset(verified or ()),
            frozenset(types.items()),
            frozenset(requests or ()),
        )
        if key not in self.code.scans:
            walk = _Walk(
                self, target, ids, callers, types, depth, set(verified or ()), set(requests or ())
            )
            self.code.scans[key] = walk.run()
        return self.code.scans[key]

    def hop(self, walk: _Walk, target: _Fn, call: Node) -> tuple[_Scan, dict[str, str]]:
        """The callee's facts with its parameters mapped from the call's arguments (by position),
        and the outer path id each parameter is exactly."""
        src = target.src
        params = target.node.child_by_field_name("parameters")
        names: list[list[str]] = []
        ptypes: dict[str, str] = {}
        for p in params.named_children if params is not None else []:
            if p.type == "parameter":
                found = _pattern_names(src, p.child_by_field_name("pattern"))
                names.append(found)
                if len(found) == 1 and (t := p.child_by_field_name("type")) is not None:
                    ptypes[found[0]] = src.text(t)
        args = _args(call)
        if len(args) != len(names) or any(len(n) != 1 for n in names):
            return _Scan(HandlerFacts(handoff=walk.span(call))), {}
        mapping = {n[0]: a for n, a in zip(names, args, strict=True)}
        inner_ids = {p: p for p, v in mapping.items() if walk.has_id(v)}
        handed = {p for p, v in mapping.items() if p not in inner_ids and walk.v.derived(v)}
        receiver = _receiver(call)
        if receiver is not None and walk.v.derived(receiver):
            handed.add("self")
        scan = self.scan(target, inner_ids, handed, ptypes, walk.depth + 1)
        return scan, {p: r for p, v in mapping.items() if (r := walk.exact(v))}
