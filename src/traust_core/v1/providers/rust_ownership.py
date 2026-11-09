"""Ownership of the object an axum or actix-web id route acts on, read from its handler and the
same-crate functions it hands the id. Protection counts only from allow-listed shapes (D8,
D25-D28)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterator
from dataclasses import dataclass
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
_DIESEL_LINKS = {
    "find", "filter", "select", "first", "get_result", "get_results", "load", "execute",
    "optional", "limit", "order", "order_by", "then_order_by", "for_update", "into_boxed",
    "delete", "update", "set", "map_err", "await", "ok", "unwrap", "expect", "context",
    "with_context",
}  # fmt: skip
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
_PATH_TYPES = {"Path", "RawPathParams", "OptionalPath"}
_PAYLOAD_TYPES = {
    "Json",
    "Form",
    "Query",
    "Multipart",
    "Bytes",
    "State",
    "Data",
    "Payload",
    "RawForm",
}
_LIBRARY_CRATES = {"actix_identity", "axum_login"}
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
    "unwrap",
    "expect",
    "borrow",
    "as_uuid",
    "to_vec",
}
_CONVERTERS = {"from", "try_from", "parse_str", "from_str", "new"}
_CALLER_METHODS = _CONVERSIONS | {"id", "user_id", "get_id"}
_INERT_CALLS = re.compile(
    r"^(format_|println_|eprintln_|print_|eprint_|anyhow_|panic_|(\w+::)*ensure_|(\w+::)*bail_|(\w+::)*anyhow_|Some|Ok|Err|Box::new|Json|"
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
    "len",
    "is_empty",
}
# error and absence adapters a value passes through unchanged
_ADAPTERS = {"map_err", "context", "with_context", "ok_or", "ok_or_else"}
# values built from others: a path joined to the id is still the id's path
# std functions of values: what they return is still the id (or another of the caller's)
_VALUE_FUNCTIONS = {
    "unwrap_or", "unwrap_or_else", "unwrap_or_default", "or", "or_else", "max", "min",
    "clamp", "into", "to_vec", "to_owned",
}  # fmt: skip
# what a plain id value offers: asking it about itself acts on nothing
_ID_METHODS = {
    "iter", "into_iter", "len", "is_empty", "chars", "bytes", "split", "contains", "starts_with",
    "ends_with", "as_bytes", "to_be_bytes", "to_le_bytes", "hash", "fmt", "eq", "ne", "cmp",
    "partial_cmp", "checked_add", "checked_sub", "is_nil", "hyphenated", "simple", "as_u128",
}  # fmt: skip
# methods that make a value another one: whatever it held before is gone
_REPOINTS = {"clone_from", "replace", "swap", "take", "set"}
_ID_FIELD = re.compile(r"(?i)^(id|uuid|key|slug|\w+_id)$")
# what a sqlx, diesel or sea-orm query is built and run with, and what its result passes through
_QUERY_CHAIN = {
    "bind", "push_bind", "fetch", "fetch_one", "fetch_optional", "fetch_all", "fetch_many",
    "execute", "persistent", "rows_affected", "filter", "find", "select", "first", "load",
    "get_result", "get_results", "optional", "limit", "offset", "order", "order_by",
    "then_order_by", "into_boxed", "set", "returning", "values", "on_conflict", "do_nothing",
    "do_update", "for_update", "count", "one", "all", "exec", "into_model", "into_json",
    "order_by_asc", "order_by_desc", "columns", "map_err", "context", "with_context", "ok_or",
    "ok_or_else", "ok", "flatten", "unwrap", "expect", "or_filter", "inner_join", "left_join",
    "left_outer_join", "group_by", "having", "distinct", "find_also_related", "find_with_related",
    "join", "reverse_join",
}  # fmt: skip
_LOAD_ADAPTERS = {
    "ok_or",
    "ok_or_else",
    "map_err",
    "context",
    "with_context",
    "cloned",
    "clone",
    "copied",
}
_HOLDERS = {"push", "push_str", "insert", "add", "extend", "append", "bind", "arg", "push_bind"}
_BUILDERS = {"join", "push", "push_str", "extend", "format_", "concat", "with_extension", "add"}
_PARSERS = {"from_str", "from_str_radix", "parse_str", "try_from", "from", "new", "parse"}
_ID_TYPES = {
    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
    "String", "str", "Uuid", "Ulid", "ObjectId",
}  # fmt: skip
_RESPONSE_PARTS = {"json", "body", "finish", "insert_header", "content_type", "append_header"}
_WRITE_NAME = re.compile(
    r"^(save|insert|upsert|exec|execute|persist|store|put|write|patch|apply)(_|$)"
)
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
_PROCESSING = re.compile(
    r"(?i)(decode|verify|authent|introspect|lookup|load_user|find_user|get_user|user_from|"
    r"from_token|from_authori[sz]ation|parse_jwt|jwt|claims|session_user|by_token|by_api_key|"
    r"check_token|check_key|resolve_\w*auth|(get|fetch|load)_\w*auth\w*|^validate(_(token|jwt|session|credentials|"
    r"signature|api_key|key|claims))?$)"
)
_UNVERIFIED = re.compile(
    r"(?i)dangerous|insecure|unverified|unchecked|without_verif|no_verif|skip_verif"
)
# an encoding's namespace: `STANDARD.decode(..)`, `hex::decode(..)`
_ENCODINGS = re.compile(
    r"(?i)\b(base64|b64|hex|percent_encoding|urlencoding|form_urlencoded|serde_urlencoded|"
    r"STANDARD\w*|URL_SAFE\w*|BASE64\w*|general_purpose|engine|bs58|base32|zstd|flate2|gzip)\b"
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


def _top_from(s: str) -> int | None:
    """Where a select's own FROM starts: the first ` from ` outside parentheses
    (`trim(both from x)`, `extract(epoch from x)` are not it)."""
    depth = 0
    for m in re.finditer(r"[()]| from ", s):
        if m.group(0) == " from " and depth == 0:
            return m.start()
        depth += {"(": 1, ")": -1}.get(m.group(0), 0)
    return None


def _sql(text: str) -> _Sql:
    # literals first (`'/*'` opens no comment); MySQL also escapes with a backslash
    s = re.sub(r"'(?:[^'\\]|\\.|'')*'", "''", text)
    s = re.sub(r"--[^\n]*|/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"\s+", " ", s).strip().rstrip(";").strip()
    original, s = s, s.lower()
    kind = s.split(" ", 1)[0] if s else ""
    table = None
    start = _top_from(s) if kind == "select" else None
    head = (re.match(r" from (?:only )?", s[start:]) if start is not None else None) or re.match(
        r"(?:delete from|update|insert into) (?:only )?", s
    )
    if head is not None:
        at = (start or 0) + head.end()
        if m := re.match(r'"[^"]+"(?:\."[^"]+")?|[\w.]+', original[at:]):
            # a quoted name keeps its case: `"Note"` is not `note`
            table = m.group(0) if m.group(0).startswith('"') else m.group(0).lower()
    source = re.search(r" from (.*?)(?: where |$)", s[start:] if start is not None else s)
    plain = (
        kind in ("select", "update", "delete")
        # comments, escapes and MySQL's `/*! … */` read differently per dialect (D31)
        and not re.search(r"--|/\*|\*/|#|\\", text)
        and ";" not in s
        and "/*" not in s
        and "*/" not in s  # Postgres nests comments: what's left of one can't be trusted
        and not re.search(r'"[^"]*[\s(][^"]*"', s)  # a quoted name hiding SQL
        and not re.match(r"update [\w.\"]+(?: (?:as )?\w+)?\s*,", s)  # `update a x, b y`
        # a comma join, or `update … from`, brings another table into the WHERE
        and not (source and ("," in source.group(1) or "(" in source.group(1)))
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
        before = s[: m.start(1)].count("?")  # `?` marks number in order
        seen = 0
        for raw in m.group(1).split(" and "):
            part = raw.strip().strip("()").strip()
            col = r"(?:\"?\w+\"?\.)?\"?(\w+)\"?"
            mark = r"(\$\d{1,5}|\?)"  # Postgres binds at most 65535: a longer one is no bind
            literal = r"(?:''|\d+|true|false)"
            if (e := re.fullmatch(rf"{col}\s*=\s*{mark}", part)) or (
                e := re.fullmatch(rf"{mark}\s*=\s*{col}", part)
            ):
                c, p = (
                    (e.group(1), e.group(2))
                    if not e.group(1).startswith(("$", "?"))
                    else (e.group(2), e.group(1))
                )
                index = before + seen if p == "?" else int(p[1:]) - 1
                found.append((c, index))
            elif not re.fullmatch(rf"{col}\s*=\s*{literal}|{col} is (?:not )?null", part):
                found = []
                break
            seen += raw.count("?")
        equalities = tuple(found) if found else None
    # a read of the record selects plain columns; anything computed (an aggregate, a function)
    # may return a row whether or not one matched
    columns = s[len("select ") : start] if kind == "select" and start is not None else None
    plain_columns = columns is not None and bool(
        re.fullmatch(r'\s*(\*|[\w."]+(\s+as\s+\w+)?)(\s*,\s*[\w."]+(\s+as\s+\w+)?)*\s*', columns)
    )
    aggregate = kind == "select" and not plain_columns
    select_all = bool(re.match(r"select \* from [\w.\"]+( where | order | limit |$)", s + " "))
    return _Sql(kind, table, equalities, aggregate, select_all and plain)


class RustCode:
    """A checkout's Rust crates: their modules, functions, impls, records and extractors."""

    def __init__(self, files: list[TreeFile], parser: object) -> None:
        crates = self._crates(files)
        # `notes = { package = "legacy-notes" }`: in that crate `notes::` is legacy-notes
        self.renames: dict[tuple[str, str], str] = {}
        workspace: dict[str, str] = {}
        for f in files:
            if f.path.name == "Cargo.toml":
                for alias, package in _renames(f.text, "workspace.dependencies"):
                    workspace[alias] = package
        for f in files:
            if f.path.name == "Cargo.toml":
                folder = str(PurePosixPath(f.rel).parent)
                if folder not in crates:
                    continue
                for alias, package in _renames(f.text, "dependencies"):
                    self.renames[(crates[folder], alias)] = package
                # `notes = { workspace = true }`: the workspace's rename
                for alias in re.findall(
                    r"(?m)^\s*([\w-]+)\s*=\s*\{[^}\n]*\bworkspace\s*=\s*true", f.text
                ):
                    if alias.replace("-", "_") in workspace:
                        self.renames[(crates[folder], alias.replace("-", "_"))] = workspace[
                            alias.replace("-", "_")
                        ]
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
        self.module_aliases: dict[tuple[str, tuple[str, ...], str], str] = {}
        self.macros = set(own)
        # checkout macros that bind a name they are handed (`($u:ident) => { let $u = .. }`)
        self.rebinding_macros = {
            name
            for f in files
            if f.path.suffix == ".rs"
            for name, body in _macro_bodies(f.text)
            if re.search(r"\blet\s+(?:mut\s+)?\$", body)
        }
        self.mut_methods: set[str] = set()
        self.typed_paths: set[str] = set()
        # a JWT validation turned off anywhere, or keys taken from the token itself
        self.insecure_jwt = any(
            f.path.suffix == ".rs" and _INSECURE_JWT.search(f.text) for f in files
        )
        self.static_homes: dict[str, list[str]] = {}
        self.primary_keys: dict[str, str] = {}
        self.derived_extractors: set[str] = set()  # methods some checkout type takes `&mut self` in
        self.renamed: dict[str, str] = {}
        self.traits: set[str] = set()
        self.implements: dict[str, set[str]] = {}
        self.structs: dict[str, dict[str, str]] = {}
        self.statics: dict[str, str] = {}
        self.extractors: dict[str, list[_Fn]] = {}
        self.fields: dict[str, tuple[str, ...]] = {}
        self.scans: dict[tuple, _Scan] = {}
        self._use_aliases: set[str] | None = None
        self._inserted: dict[str, bool] = {}
        self._targets: dict[tuple[tuple[str, ...], bool], list[_Fn] | None] = {}
        self._kinds: dict[str, str] = {}
        placed: dict[str, tuple[str, ...]] = {}
        for f in files:
            if f.path.suffix != ".rs":
                continue
            for m in re.finditer(
                r'#\[path\s*=\s*"([^"]+)"\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)', f.text
            ):
                target = str(PurePosixPath(f.rel).parent / m.group(1))
                _, module = self._place(f.rel, crates)
                placed[target] = (*module, m.group(2))
        for f in files:
            if f.path.suffix != ".rs":
                continue
            data = rewrite(f.text, own).encode("utf-8")
            crate, module = self._place(f.rel, crates)
            if f.rel in placed:
                module = placed[f.rel]
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
                    params = c.child_by_field_name("parameters")
                    first = (
                        params.named_children[0]
                        if params is not None and params.named_children
                        else None
                    )
                    if (
                        first is not None
                        and first.type == "self_parameter"
                        and "mut" in src.text(first)
                    ):
                        self.mut_methods.add(key)
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
                    attrs, prev = [], c.prev_named_sibling
                    while prev is not None and prev.type == "attribute_item":
                        attrs.append(src.text(prev))
                        prev = prev.prev_named_sibling
                    if any("TypedPath" in a for a in attrs):
                        self.typed_paths.add(name)  # axum-extra `#[derive(TypedPath)]`
                    if any(re.search(r"\bFromRequest(Parts)?\b", a) for a in attrs):
                        self.derived_extractors.add(name)  # `#[derive(FromRequestParts)]`
                elif kind == "type_item" and (t := c.child_by_field_name("type")) is not None:
                    self.aliases[name] = src.text(t)
                    self.module_aliases[(src.crate, module, name)] = src.text(t)
            elif kind in ("static_item", "const_item") and (t := c.child_by_field_name("type")):
                name = src.text(c.child_by_field_name("name"))
                # two statics of one name (in different modules): which a use names isn't kept
                self.statics[name] = (
                    "" if self.statics.get(name, src.text(t)) != src.text(t) else src.text(t)
                )
                self.static_homes.setdefault(name, []).append("::".join((src.crate, *module)))
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
        for m in re.finditer(r"(\w+)\s*(?:\(([^)]*)\))?\s*\{([^{}]*)\}", text):
            columns = tuple(re.findall(r"(\w+)\s*->", m.group(3)))
            if columns:
                # one table name in two schemas (`export.notes`, a test schema): every column
                self.fields[m.group(1)] = tuple(
                    dict.fromkeys([*self.fields.get(m.group(1), ()), *columns])
                )
                if m.group(2):
                    self.primary_keys[m.group(1)] = m.group(2).split(",")[0].strip()

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
        if (package := self.renames.get((crate.split("#")[0], head))) is not None:
            return [package, *rest]
        return path

    def type_path(
        self, src: _Src, module: tuple[str, ...], name: str, depth: int = 0
    ) -> tuple[list[str], bool]:
        """Where a type name used in a module comes from: (its path, whether it is the
        checkout's), through that module's `use x as Name` and `type Name = X;` and the
        checkout modules they point into; never another module's."""
        return self._type_at(src.crate, module, name, depth)

    def alias_text(self, src: _Src, module: tuple[str, ...], name: str) -> str | None:
        """What a `type Name = ..;` the name reaches (here or through a `use`) stands for."""
        crate, depth = src.crate, 0
        while depth < 6:
            if (alias := self.module_aliases.get((crate, module, name))) is not None:
                return alias
            path = self.module_uses.get((crate, module), {}).get(name)
            if not path or path[0] not in self.crates:
                return None
            crate, module, name, depth = path[0], tuple(path[1:-1]), path[-1], depth + 1
        return None

    def _type_at(
        self, crate: str, module: tuple[str, ...], name: str, depth: int
    ) -> tuple[list[str], bool]:
        if depth > 6:
            return [name], False
        alias = self.module_aliases.get((crate, module, name))
        if alias is not None:
            target = _generic(alias)[0]
            if target != name:
                return self._type_at(crate, module, target, depth + 1)
        path = self.module_uses.get((crate, module), {}).get(name)
        if path is not None:
            if not path or path[0] not in self.crates:
                return path or [name], False
            return self._type_at(path[0], tuple(path[1:-1]), path[-1], depth + 1)
        globs = self.module_globs.get((crate, module), [])
        for g in globs:
            # `use crate::auth::*;` brings in what that module names or aliases
            if (
                g[:1]
                and g[0] in self.crates
                and (
                    (g[0], tuple(g[1:]), name) in self.module_aliases
                    or name in self.module_uses.get((g[0], tuple(g[1:])), {})
                )
            ):
                return self._type_at(g[0], tuple(g[1:]), name, depth + 1)
        external = [g for g in globs if g[:1] and g[0] not in self.crates]
        if name not in self.types and external:
            return [*external[0], name], False  # from a library's glob
        return [name], name in self.types or name in self.extractors

    def module_at(self, src: _Src, node: Node | None) -> tuple[str, ...]:
        """The module a node sits in: its file's, then each enclosing `mod x { }`."""
        names = []
        while node is not None:
            if node.type == "mod_item" and node.child_by_field_name("body") is not None:
                names.append(src.text(node.child_by_field_name("name")))
            node = node.parent
        return (*src.module, *reversed(names))

    def resolve(
        self, src: _Src, path: str, at: Node | None = None, *, fallback: bool = True
    ) -> list[_Fn] | None:
        """The crate functions a call path names: [] when none (a library's), None when it can't
        be told which runs. `at` places the path (its module, its enclosing functions)."""
        segs = _segments(path)
        if not segs:
            return None
        module = self.module_at(src, at)
        uses = {**self.uses.get((src.file.rel, module), {}), **self._block_uses(src, at, module)}
        if segs[0] == "Self" and len(segs) == 2:
            owner = _impl_owner(src, at)
            return self.method(owner, segs[1]) if owner else None
        if len(segs) == 1:
            name = segs[0]
            if (local := _local_fn(src, at, name, module)) is not None:
                return [local]
            if name in uses:
                return self._target(uses[name], fallback=fallback)
            if found := self.fns.get((src.crate, module, name)):
                return found if len(found) == 1 else None
            globs = self.globs.get((src.file.rel, module), [])
            hits = [found for g in globs if (found := self._target([*g, name], fallback=fallback))]
            if len(hits) == 1:
                return hits[0]
            if hits or any(g[:1] and g[0] not in self.crates for g in globs):
                return None  # more than one glob, or a library's, may provide it
            return self._unique(name) if fallback else None
        head = segs[0]
        full = [*uses[head], *segs[1:]] if head in uses else self._absolute(src.crate, module, segs)
        return self._target(full, fallback=fallback)

    def _block_uses(
        self, src: _Src, at: Node | None, module: tuple[str, ...]
    ) -> dict[str, list[str]]:
        """The `use` declarations of the blocks enclosing `at` (a function-local `use`)."""
        found: dict[str, list[str]] = {}
        node = at
        while node is not None:
            if node.type == "block":
                for c in node.named_children:
                    if c.type == "use_declaration" and (arg := c.child_by_field_name("argument")):
                        for alias, path in self._use(src, module, arg, []):
                            if alias != "*":
                                found.setdefault(alias, path)
            node = node.parent
        return found

    def _target(
        self, full: list[str], depth: int = 0, *, fallback: bool = True
    ) -> list[_Fn] | None:
        key = (tuple(full), fallback)
        if key not in self._targets:
            self._targets[key] = None  # a glob cycle back to this path provides nothing more
            self._targets[key] = self._find_target(full, depth, fallback=fallback)
        return self._targets[key]

    def _find_target(self, full: list[str], depth: int, *, fallback: bool) -> list[_Fn] | None:
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
                return self._target(path, depth + 1, fallback=fallback)
            # one function reached through two globs is still one
            hits = {
                tuple((f.src.file.rel, f.node.start_byte) for f in found): found
                for g in self.module_globs.get(module, [])
                if (found := self._target([*g, name], depth + 1, fallback=fallback))
            }
            if len(hits) == 1:
                return next(iter(hits.values()))
            if hits:
                return None
        # in a crate of the checkout but not indexed (a macro-made module): the only one so named
        return self._unique(name) if fallback else None

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

    def inserted_unverified(self, name: str) -> bool:
        """Whether checkout code puts a `name` into request extensions without verifying
        anything first (`req.extensions_mut().insert(AuthUser { id: header })`)."""
        if name not in self._inserted:
            word = re.compile(rf"\b{re.escape(name)}\b")
            self._inserted[name] = any(
                n.type == "function_item"
                and word.search(src.text(n))
                and _inserts_unverified(src, n)
                for src in self.sources
                for n in walk(src.root)
            )
        return self._inserted[name]

    def use_alias(self, name: str) -> bool:
        """A name a `use .. as` gives a type: which record it stands for isn't kept."""
        if self._use_aliases is None:
            self._use_aliases = {
                a
                for src in self.sources
                for u in re.findall(r"\buse\b[^;]*;", src.file.text)
                for a in re.findall(r"\bas\s+([A-Z]\w*)", u)
            }
        return name in self._use_aliases

    def hidden_link(self, record: str) -> bool:
        """A field holding another object's id under a name no owner word matches:
        `belongs_to: Uuid`."""
        return any(
            f != "id" and re.search(r"\b(Uuid|Ulid|ObjectId|Thing|RecordId)\b", t)
            for f, t in self.structs.get(_strip(record), {}).items()
        )

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
        if typ in self._kinds:
            return self._kinds[typ]
        self._kinds[typ] = "unread"  # a cycle reads as unread
        impls = self.extractors.get(typ, [])
        aliased = sum(1 for (_, _, n) in self.module_aliases if n == typ)
        if self.types.get(typ, 0) - aliased > 1:
            kind = "unread"  # two types so named: which impl runs can't be told
        elif not impls:
            library = typ in _LIBRARY_CALLERS and typ not in self.types
            kind = "trusted" if library else "unread"
        else:
            kinds = {self._extractor(f, depth) for f in impls} - {"self"}
            kind = next((k for k in ("forged", "unread") if k in kinds or not kinds), "trusted")
        self._kinds[typ] = kind
        return kind

    def _extractor(self, fn: _Fn, depth: int) -> str:
        """Trusted only when its own body takes the caller from the request's extensions (a
        caller type server code put there), a trusted auth extractor or library session, or a
        known verifying library call (a JWT decode, under `?`) that the one raw credential is
        handed to directly, and no other raw value reaches it; forged when a raw value reaches
        it otherwise; unread when it hands the request to code we don't read, a helper included
        (D26, credited only from what the extractor itself shows)."""
        from traust_core.v1.providers.rust_routes import _is_guard

        src, node = fn.src, fn.node
        body = node.child_by_field_name("body")
        if body is None:
            return "unread"
        params = node.child_by_field_name("parameters")
        request = {
            src.text(p.child_by_field_name("pattern"))
            for p in (params.named_children if params is not None else [])
            if p.type == "parameter" and not re.search(r"(?i)state", src.text(p))
        }
        helpers, opaque = self._helpers(src, body, request)
        unread = opaque or bool(helpers)
        module = self.module_at(src, node)
        insecure = self.insecure_jwt or _INSECURE.search(src.text(body))
        sources: set[str] = set()
        raw = list(_raw_reads(src, body, request, self))
        verifying: list[Node] = []
        unknown: list[Node] = []
        for n in walk(body):
            if n.type != "call_expression":
                continue
            name = _call_name(src, n)
            text = src.text(n.child_by_field_name("function"))
            turbofish = re.search(r"::<\s*(.+?)\s*>\s*$", text)
            if name == "get" and turbofish and _extensions(src, _receiver(n)):
                read = _strip(turbofish.group(1))
                if read in ("Self", fn.owner) or _CALLER_TYPE.match(read):
                    sources.add("trusted")
                elif not _INFRASTRUCTURE.search(read):
                    raw.append(n)  # what a middleware put there, maybe from the client
                continue
            typ = None
            if name.startswith("from_request") and _receiver(n) is None:
                segs = _segments(text)
                typ = _strip(segs[-2]) if len(segs) >= 2 else None
            elif name in ("extract", "extract_parts") and turbofish:
                typ = _strip(turbofish.group(1))
            if typ in ("Self", fn.owner):
                sources.add("self")
            elif typ in _SERVER_STATE:
                path, ours = self.type_path(src, module, typ)
                sources.add("trusted" if not ours and path[0] in _SESSION_CRATES else "unread")
            elif typ and (_is_guard(typ) or _CALLER_TYPE.match(typ)) and depth < 3:
                sources.add(self.caller_kind(typ, depth + 1))
            if not insecure and self._library_verifier(src, n) and _tried(n):
                verifying.append(n)
            elif _PROCESSING.search(name) and _consumed(n) and not _ENCODINGS.search(text):
                unknown.append(n)  # a call that may verify: we can't tell
        for r in raw:
            if any(_handed(src, body, r, c) for c in verifying):
                continue
            if any(_handed(src, body, r, c) for c in unknown) or any(
                # `headers().and_then(|h| AuthUser::from_authorization(h))`: handed to code we
                # don't read
                n.type == "call_expression"
                and (
                    _PROCESSING.search(_call_name(src, n))
                    or (_path_of(src, n) and self.resolve(src, _path_of(src, n), n))
                )
                for closure in _chained_closures(r)
                for n in walk(closure)
            ):
                unread = True
                continue
            return "forged"
        if raw and verifying and len(raw) == 1:
            sources.add("trusted")  # one credential, verified
        elif raw and verifying:
            unread = True  # several raw values: which is the caller's isn't told
        if unread:
            return "unread"
        if not sources:
            return "forged"
        if sources == {"self"}:
            return "self"
        return next((k for k in ("forged", "unread") if k in sources), "trusted")

    def _helpers(
        self, src: _Src, body: Node, request: set[str]
    ) -> tuple[list[tuple[_Src, Node, set[str]]], bool]:
        """(the checkout functions and methods an extractor hands the request to, with the
        parameters that receive it, whether it hands it to code we can't read: a checkout
        macro, a method we can't place)."""
        handed = request | _bound_from(src, body, request)
        out = []
        opaque = False
        for n in walk(body):
            if (
                n.type == "macro_invocation"
                and _idents(src, n) & handed
                and _last(src.text(n.child_by_field_name("macro"))) in self.macros
            ):
                opaque = True
            if n.type != "call_expression":
                continue
            receiver = _receiver(n)
            args = _args(n)
            if (
                receiver is not None
                and _idents(src, receiver) & handed
                and _call_name(src, n) not in _REQUEST_METHODS
            ):
                # `parts.act_as()`: a checkout extension-trait method, or one we can't place
                found = self.by_name.get(_call_name(src, n), [])
                if len(found) == 1 and found[0].owner is not None:
                    out.append((found[0].src, found[0].node.child_by_field_name("body"), {"self"}))
                elif found:
                    opaque = True
                continue
            if receiver is not None or not any(_idents(src, a) & handed for a in args):
                continue
            found = self.resolve(src, _path_of(src, n), n)
            if not found or len(found) != 1 or found[0].node.child_by_field_name("body") is None:
                continue
            if _PROCESSING.search(_call_name(src, n)) and not self._verifies(src, n, 0):
                opaque = True  # a checkout auth resolver we can't read through: maybe it verifies
                continue
            target = found[0]
            params = target.node.child_by_field_name("parameters")
            names = [
                _pattern_names(target.src, p.child_by_field_name("pattern"))
                for p in (params.named_children if params is not None else [])
                if p.type == "parameter"
            ]
            receiving = {
                x
                for ns, a in zip(names, args, strict=False)
                if _idents(src, a) & handed
                for x in ns
            }
            out.append((target.src, target.node.child_by_field_name("body"), receiving))
        return [o for o in out if o[1] is not None], opaque

    def _verifies(self, src: _Src, call: Node, depth: int) -> bool:
        """A call that verifies what it is handed, whose result is used: a known verifying
        library call (a JWT decode, a signature or password check), a lookup query, or a
        checkout function that itself runs one."""
        if not _consumed(call):
            return False
        name = _call_name(src, call)
        text = src.text(call.child_by_field_name("function"))
        if _is_query(src, call):
            return True
        if _ENCODINGS.search(text) or _ENCODING.search(name) or _UNVERIFIED.search(name):
            return False
        path = _path_of(src, call)
        found = self.resolve(src, path, call) if path else None
        if found:
            if depth > 3 or len(found) != 1:
                return False
            target_body = found[0].node.child_by_field_name("body")
            return target_body is not None and any(
                n.type == "call_expression"
                and n != call
                and (_is_query(found[0].src, n) or self._library_verifier(found[0].src, n))
                for n in walk(target_body)
            )
        return self._library_verifier(src, call)

    def _library_verifier(self, src: _Src, call: Node) -> bool:
        """jsonwebtoken's `decode`, the jwt crate's `verify_with_key`, josekit's
        `decode_with_verifier`: named through their own crate, never an encoding's `decode`."""
        name = _call_name(src, call)
        if name not in ("decode", "decode_with_verifier", "verify_with_key"):
            return False
        module = self.module_at(src, call)
        path = _path_of(src, call)
        if path:
            segs = _segments(path)
            uses = self.uses.get((src.file.rel, module), {})
            full = [*uses.get(segs[0], [segs[0]]), *segs[1:]] if segs else []
            return bool(full) and full[0] in _VERIFIER_CRATES
        # a method: `token.verify_with_key(&key)` with the jwt crate's trait in scope
        return name == "verify_with_key" and any(
            p[:1] == ["jwt"] for p in self.uses.get((src.file.rel, module), {}).values()
        )

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


_RAW_FIELDS = {"headers", "uri"}
_RAW_CALLS = {
    "headers", "headers_mut", "header", "uri", "uri_mut", "query", "query_string", "cookie",
    "cookies", "get_cookie", "match_info", "connection_info", "peer_addr", "path", "full_url",
    "into_body", "body", "to_bytes",
}  # fmt: skip
_INSECURE_JWT = re.compile(
    r"insecure_disable_signature_validation|validate_signature\s*=\s*false|"
    r"dangerous_insecure|decode_header[\s\S]{0,600}jwk|jwk[\s\S]{0,600}decode_header"
)
# turns a verifier off: `validation.insecure_disable_signature_validation()`
_INSECURE = re.compile(
    r"(?i)insecure|dangerous|unverified|unsecured|validate_exp\s*=\s*false|"
    r"validate_signature\s*=\s*false|without_verif|no_verif|skip_verif"
)
# server state an extension may hold, which is no caller's input
_INFRASTRUCTURE = re.compile(
    r"(?i)(pool|db|database|state|config|settings|client|cache|jwks|keys?|metrics)$"
)
_VERIFIER_CRATES = {"jsonwebtoken", "jwt", "josekit", "jwt_simple", "biscuit"}
_SESSION_CRATES = {
    "tower_sessions",
    "actix_session",
    "axum_extra",
    "axum_sessions",
    "async_session",
    "actix_identity",
    "axum_login",
}
_SERVER_STATE = {"Session", "SignedCookieJar", "PrivateCookieJar", "Identity", "AuthSession"}
_REQUEST_METHODS = {
    "headers", "headers_mut", "header", "uri", "query", "query_string", "cookie", "cookies",
    "get_cookie", "match_info", "connection_info", "peer_addr", "path", "extensions",
    "extensions_mut", "method", "version", "body", "into_body", "full_url", "extract",
    "extract_parts", "get", "clone", "app_data", "head",
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
    "String",
    "Bytes",
    "OriginalUri",
    "Uri",
}


def _raw_reads(src: _Src, body: Node, request: set[str], code: RustCode) -> list[Node]:
    """What the client sent, read directly: a header, the URI, the query, a plain cookie, the
    body (also through `let Parts { headers, .. } = parts;` and renamed extractors)."""
    out = []
    destructured: set[str] = set()
    for n in walk(body):
        if n.type == "let_declaration" and _idents(src, n.child_by_field_name("value")) & request:
            pattern = n.child_by_field_name("pattern")
            destructured |= (
                {x for x in _pattern_names(src, pattern) if x in _RAW_FIELDS}
                if pattern is not None and pattern.type == "struct_pattern"
                else set()
            )
    for n in walk(body):
        field = n.child_by_field_name("field") if n.type == "field_expression" else None
        if (field is not None and src.text(field) in _RAW_FIELDS) or (
            n.type == "identifier"
            and src.text(n) in destructured
            and n.parent is not None
            and n.parent.type
            not in ("struct_pattern", "field_pattern", "shorthand_field_identifier")
        ):
            out.append(n)
        elif n.type == "call_expression":
            name = _call_name(src, n)
            text = src.text(n.child_by_field_name("function"))
            module = code.module_at(src, n)
            names = {
                code.uses.get((src.file.rel, module), {}).get(x, [x])[-1]
                for x in re.findall(r"[A-Za-z_]\w*", text)
            }
            names |= {
                x
                for y in list(names)
                for x in re.findall(r"[A-Za-z_]\w*", code.alias_text(src, module, y) or "")
            }
            if re.search(r"\benv::var(_os)?$|\bdotenv\b", text):
                out.append(n)  # one fixed identity for every caller: none of theirs
            elif (_receiver(n) is not None and name in _RAW_CALLS) or (
                names & _RAW_EXTRACTORS
                and (name.startswith("from_request") or name in ("extract", "extract_parts"))
            ):
                out.append(n)
    return out


def _inserts_unverified(src: Parsed, fn: Node) -> bool:
    """`fn` puts into request extensions a value no verifier returned (nor a caller another
    middleware already put there)."""
    calls = [c for c in walk(fn) if c.type == "call_expression"]
    verified = [
        c
        for c in calls
        if _extensions(src, c)
        or (_PROCESSING.search(_call_name(src, c)) and not _UNVERIFIED.search(src.text(c)))
    ]
    names = _tainted(src, fn, verified)
    return any(
        (
            _call_name(src, c) == "Extension"
            or (
                _call_name(src, c) == "insert"
                and src.text(_receiver(c)).endswith("extensions_mut()")
            )
        )
        and not any(
            any(_inside(v, a) for v in verified) or _idents(src, a) & names for a in _args(c)
        )
        for c in calls
    )


def _tried(call: Node) -> bool:
    """`decode(..).map_err(..)?`: the call's error is handed on with `?`."""
    parent = call.parent
    while parent is not None:
        if parent.type == "try_expression":
            # in a closure, the `?` refuses only the closure: its caller may fall back
            fn = _enclosing_fn(call)
            return fn is not None and fn.id == getattr(_enclosing_fn(parent), "id", None)
        if parent.type == "await_expression":
            parent = parent.parent
        elif (
            parent.type == "field_expression"
            and parent.parent is not None
            and parent.parent.type == "call_expression"
            and _call_name_text(parent.parent) in ("map_err", "context", "with_context")
        ):
            parent = parent.parent.parent
        else:
            return False
    return False


def _balanced(text: str, at: int) -> str:
    """The `<…>` group opening at `at`."""
    depth = 0
    for i in range(at, len(text)):
        depth += {"<": 1, ">": -1}.get(text[i], 0)
        if depth == 0:
            return text[at + 1 : i]
    return text[at + 1 :]


def _enclosing_fn(node: Node) -> Node | None:
    while node.parent is not None and node.type not in ("function_item", "closure_expression"):
        node = node.parent
    return node if node.type == "function_item" else None


def _call_name_text(call: Node) -> str:
    fn = call.child_by_field_name("function")
    field = (
        fn.child_by_field_name("field")
        if fn is not None and fn.type == "field_expression"
        else None
    )
    return (field.text or b"").decode() if field is not None else ""


def _handed(src: Parsed, body: Node, r: Node, c: Node) -> bool:
    """The raw value `r` is handed to `c` as an argument, directly or through a local."""
    return _inside(r, c) or bool(_idents(src, c) & _tainted(src, body, [r]))


def _consumed(call: Node) -> bool:
    """Whether a call's result decides anything: handed on with `?`, bound to a local that is
    read, returned, or matched with a refusing arm; never `let _ = ..`, a bare statement, `.ok()`
    or `.is_ok()` thrown away, or an error only logged."""
    node, parent = call, call.parent
    while parent is not None and (
        parent.type in ("await_expression", "parenthesized_expression")
        or (
            parent.type == "field_expression"
            and parent.parent is not None
            and parent.parent.type == "call_expression"
        )
    ):
        node = parent if parent.type != "field_expression" else parent.parent
        parent = node.parent
    if parent is None:
        return False
    if parent.type == "try_expression" or parent.type == "return_expression":
        return True
    if parent.type == "let_declaration":
        pattern = parent.child_by_field_name("pattern")
        return pattern is not None and not (pattern.text or b"_").startswith(b"_")
    if parent.type in ("match_expression", "let_condition"):
        whole = parent if parent.type == "match_expression" else parent.parent
        return whole is not None and bool(
            re.search(rb"\breturn\s+Err\b|\bErr\(", whole.text or b"")
        )
    # `Ok(Self { id: decode(..)?.sub })`, a tail value
    return parent.type in ("arguments", "field_initializer", "block")


def _is_query(src: Parsed, call: Node) -> bool:
    """A lookup query: sqlx's macros and functions, a diesel or sea-orm fetch."""
    name = _call_name(src, call)
    text = src.text(call)
    if name in ("query_", "query_as_", "query_scalar_") or _path_of(src, call).startswith(
        "sqlx::query"
    ):
        return bool(re.search(r"(?i)\bselect\b", text))
    return name in ("first", "get_result", "load", "one", "fetch_one", "fetch_optional") and bool(
        re.search(r"::table\b|Entity::|sqlx::", text)
    )


def _ignored(call: Node) -> bool:
    """A call whose value is only refused on or thrown away: `validate(&id)?;`, `check(id);`."""
    node = call
    while node.parent is not None and node.parent.type in ("await_expression", "try_expression"):
        node = node.parent
    return (
        node is not call and node.parent is not None and node.parent.type == "expression_statement"
    ) or _discarded(call)


def _discarded(call: Node) -> bool:
    """A call whose value nobody reads: `let _ = verify(..);`, `verify(..);`."""
    parent = call.parent
    while parent is not None and parent.type == "await_expression":
        parent = parent.parent
    if parent is None:
        return False
    if parent.type == "expression_statement":
        return True
    if parent.type == "let_declaration":
        pattern = parent.child_by_field_name("pattern")
        return (
            pattern is not None
            and pattern.type in ("identifier", "_")
            and (pattern.text or b"").startswith(b"_")
        )
    return False


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


def _macro_bodies(text: str) -> Iterator[tuple[str, str]]:
    """Each `macro_rules! name { .. }` and its body."""
    for m in re.finditer(r"macro_rules!\s*(\w+)\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.group(1), text[m.end() : i]


def _held_by(src: Parsed, pattern: Node | None) -> dict[str, str]:
    """What each name a caller pattern binds holds: "" the whole caller (`user`,
    `Extension(user)`), a field's name (`AuthUser { id, is_admin: admin }` binds `id` -> `id`,
    `admin` -> `is_admin`), "#n" a positional field (`CurrentAuth(_, admin)`)."""
    if pattern is None:
        return {}
    if pattern.type in ("identifier", "mut_pattern"):
        return {n: "" for n in _pattern_names(src, pattern)}
    if pattern.type == "tuple_struct_pattern":
        items = [c for c in pattern.named_children if c != pattern.child_by_field_name("type")]
        if len(items) == 1:
            return _held_by(src, items[0])  # `Extension(user)`, `Extension(User { .. })`
        return {n: f"#{i}" for i, c in enumerate(items) for n in _pattern_names(src, c) if n != "_"}
    if pattern.type == "struct_pattern":
        out: dict[str, str] = {}
        for c in pattern.named_children:
            if c.type == "field_pattern":
                field = c.child_by_field_name("name")
                bound = c.child_by_field_name("pattern")
                name = src.text(field) if field is not None else ""
                for n in _pattern_names(src, bound) if bound is not None else [name]:
                    out[n] = name
            elif c.type == "shorthand_field_identifier":
                out[src.text(c)] = src.text(c)
        return out
    return {n: "#" for n in _pattern_names(src, pattern)}


def _assigned(src: Parsed, fn: Node, *, mutators: bool = True, refs: bool = True) -> set[str]:
    """Names (and `p.id` field paths) a function writes: `x = …`, `(x, _) = …`, `x += …`,
    `x.push_str(..)`, `&mut x`, or binds outside a `let` (`for x in`, `if let Some(x)`, a
    closure or match arm parameter)."""
    out: set[str] = set()

    def written(node: Node | None) -> None:
        if node is None:
            return
        for x in walk(node):
            if x.type == "field_expression" and (root := _root(x)) is not None:
                out.add(src.text(root))
                out.add(f"{src.text(root)}.{src.text(x.child_by_field_name('field'))}")
            elif x.type in ("identifier", "self") and (
                x.parent is None or x.parent.type not in ("index_expression", "arguments")
            ):
                out.add(src.text(x))

    for n in _own(fn):
        if n.type in ("assignment_expression", "compound_assignment_expr"):
            written(n.child_by_field_name("left"))
        elif mutators and n.type == "call_expression" and _MUTATORS.match(_call_name(src, n)):
            written(_root(_receiver(n)))
        elif (
            refs
            and n.type == "reference_expression"
            and any(c.type == "mutable_specifier" for c in n.children)
        ):
            written(_root(n.child_by_field_name("value")))
        elif n.type == "macro_invocation" and _last(src.text(n.child_by_field_name("macro"))) in (
            "write",
            "writeln",
        ):
            tokens = next((c for c in n.named_children if c.type == "token_tree"), None)
            first = (
                next((c for c in tokens.children if c.type == "identifier"), None)
                if tokens
                else None
            )
            if first is not None:
                out.add(src.text(first))  # `write!(id, ..)` appends to it
        elif n.type in ("for_expression", "let_condition", "closure_expression", "match_arm"):
            pattern = n.child_by_field_name("pattern") or n.child_by_field_name("parameters")
            if pattern is not None and pattern.type == "match_pattern":
                pattern = pattern.named_children[0] if pattern.named_children else None
            out |= set(_pattern_names(src, pattern))
        elif n.type == "call_expression" and _call_name(src, n) in _REPOINTS:
            written(_root(_receiver(n)))  # `holder.clone_from(&other)` points it elsewhere
    return out


_IDENTITY = re.compile(
    r"(?i)^(id|uuid|uid|sub|subject|email|username|login|(user|account|tenant|org|"
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
                left.type in ("identifier", ">", "!")  # `get::<i64>(..)`, `inner!(..)`
                and right.type == "token_tree"
                and right.children[:1]
                and right.children[0].type in ("(", "[")  # a call, or `INDEX[&id]`
            ):
                return True
    return False


def _strip_transparent(src: Parsed, node: Node | None) -> Node | None:
    """`st.jobs.lock().unwrap()` is `st.jobs`."""
    node = _unwrap(node)
    while (
        node is not None
        and node.type == "call_expression"
        and _call_name(src, node) in _TRANSPARENT
    ):
        node = _unwrap(_receiver(node))
    return node


def _collection(typ: str) -> bool:
    for _ in range(12):
        name, args = _generic(typ)
        if name in _CONTAINERS:
            return True
        if name not in _WRAPPERS or len(args) != 1:
            return False
        typ = args[0]
    return False


def _unescape(escape: str) -> str:
    simple = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    body = escape[1:]
    if body[:1] in simple:
        return simple[body[:1]]
    try:
        if body.startswith("x") and len(body) >= 3:
            return chr(int(body[1:3], 16))
        if body.startswith("u{"):
            return chr(int(body[2:].rstrip("}"), 16))
    except (ValueError, OverflowError):
        return "\\"  # no char (`\u{110000}`): the backslash keeps the query unread
    return " "  # a line continuation


def _where(table: str, columns: list[str]) -> str:
    """What a lookup reads: its table and the columns its ids are compared with."""
    return f"table:{table}#{','.join(columns)}"


def _root(node: Node | None) -> Node | None:
    """The variable at the base of `a.b.c`, `a[0]`, `(*a)`."""
    node = _unwrap(node)
    while node is not None and node.type in ("field_expression", "index_expression"):
        node = _unwrap(node.named_children[0]) if node.named_children else None
    return node if node is not None and node.type in ("identifier", "self") else None


def _is_guard_name(name: str) -> bool:
    from traust_core.v1.providers.rust_routes import _is_guard

    return _is_guard(name)


_TENANT_WORD = re.compile(
    r"(?i)tenant|org|organi[sz]ation|team|workspace|account|company|group|project|customer|client|realm"
)


def _agrees(owner: str, caller: str) -> bool:
    """An owner field compared with the matching caller field: a tenant with the caller's
    tenant (`org_id` with `user.org_id`), anything else with who the caller is (`owner` with
    `user.id`), never an owner with their team."""
    tenant = _TENANT_WORD.search(owner)
    if tenant:
        return (
            bool(_TENANT_WORD.search(caller))
            and tenant.group(0).lower()[:3] == _TENANT_WORD.search(caller).group(0).lower()[:3]
        )
    return not _TENANT_WORD.search(caller)


def _let_value(src: Parsed, at: Node | None, name: str) -> Node | None:
    """The value the last `let name = ..` before `at` in its function binds."""
    fn = at
    while fn is not None and fn.type not in ("function_item", "closure_expression"):
        fn = fn.parent
    found = None
    for n in walk(fn) if fn is not None and at is not None else []:
        if n.type == "let_declaration" and n.end_byte <= at.start_byte and _bound(src, n) == name:
            found = _unwrap(n.child_by_field_name("value"))
    return found


def _bindings(src: Parsed, at: Node | None, name: str) -> int:
    """How many lets, local fns and uses bind `name` in the function around `at`: with more
    than one, block scope decides which a route names, which we don't track."""
    fn = at
    while fn is not None and fn.type != "function_item":
        fn = fn.parent
    if fn is None:
        return 0
    word = re.compile(rf"(?:\bas\s+|::|\{{|,\s*){re.escape(name)}\s*(?:[,}};]|$)")
    return sum(
        (
            n.type == "let_declaration"
            and name in _pattern_names(src, n.child_by_field_name("pattern"))
        )
        or (
            n.type == "function_item"
            and n.id != fn.id
            and src.text(n.child_by_field_name("name")) == name
        )
        or (n.type == "use_declaration" and bool(word.search(src.text(n))))
        for n in walk(fn)
    )


def _is_parameter(src: Parsed, at: Node | None, name: str) -> bool:
    fn = at
    while fn is not None and fn.type != "function_item":
        fn = fn.parent
    params = fn.child_by_field_name("parameters") if fn is not None else None
    return name in {
        x
        for p in (params.named_children if params is not None else [])
        if p.type == "parameter"
        for x in _pattern_names(src, p.child_by_field_name("pattern"))
    }


def _let_closure(src: Parsed, at: Node | None, name: str) -> Node | None:
    """The closure a `let name = |..| ..` before `at` in its function binds."""
    fn = at
    while fn is not None and fn.type not in ("function_item", "closure_expression"):
        fn = fn.parent
    found = None
    for n in walk(fn) if fn is not None and at is not None else []:
        if n.type == "let_declaration" and n.start_byte < at.start_byte and _bound(src, n) == name:
            value = _unwrap(n.child_by_field_name("value"))
            found = value if value is not None and value.type == "closure_expression" else None
    return found


def _renames(toml: str, table: str) -> list[tuple[str, str]]:
    """`alias = { package = "x" }` lines and `[<table>.alias] package = "x"` sections."""
    out = []
    section = ""
    for line in toml.splitlines():
        if m := re.match(r"\s*\[([^\]]+)\]", line):
            section = m.group(1).strip()
            continue
        if section == table and (
            m := re.match(r'\s*([\w-]+)\s*=\s*\{[^}]*\bpackage\s*=\s*"([^"]+)"', line)
        ):
            out.append((m.group(1), m.group(2)))
        elif section.startswith(f"{table}.") and (
            m := re.match(r'\s*package\s*=\s*"([^"]+)"', line)
        ):
            out.append((section[len(table) + 1 :], m.group(1)))
    return [(a.replace("-", "_"), p.replace("-", "_")) for a, p in out]


def _impl_owner(src: Parsed, node: Node | None) -> str | None:
    while node is not None:
        if node.type == "impl_item":
            return _strip(src.text(node.child_by_field_name("type")))
        node = node.parent
    return None


def _local_fn(src: _Src, at: Node | None, name: str, module: tuple[str, ...]) -> _Fn | None:
    """A function declared in one of the blocks enclosing `at` (an item is seen across its
    own block, never outside it)."""
    node = at
    while node is not None:
        if node.type == "block":
            for c in node.named_children:
                if c.type == "function_item" and src.text(c.child_by_field_name("name")) == name:
                    return _Fn(src, c, module)
        node = node.parent
    return None


def _idents(src: Parsed, node: Node | None) -> set[str]:
    """The variable names an expression mentions (not path segments, not field names)."""
    if node is None:
        return set()
    out = set()
    for n in walk(node):
        if n.type == "string_literal":
            # `format!("note:{id}")` reads `id`
            out |= set(re.findall(r"(?<!\{)\{([A-Za-z_]\w*)(?::[^}]*)?\}", src.text(n)))
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
    targets: tuple[str | None, ...] = ()
    covers: tuple[set[str] | None, ...] = ()
    reads: tuple[bool, ...] = ()
    handoff_cover: set[str] | None = None
    pure_read: bool = False
    returns_caller: bool = False


class _Values:
    """Which values in one function come from the caller alone (D26)."""

    def __init__(
        self,
        src: Parsed,
        fn: Node,
        callers: dict[str, str],
        requests: set[str],
        code: RustCode,
    ) -> None:
        self.src, self.code = src, code
        # a checkout method's body is not read: `fn user_id(&self) { self.team.clone() }`
        self.ours = {name for _, name in code.methods}
        self.requests = set(requests)
        self.attrs = dict(callers)  # the caller field a name holds; "" the whole caller
        self.callers = set(callers)
        self.roots = set(callers)
        bound: dict[str, list[Node | None]] = {}
        assigned: set[str] = set()
        unwrapped = {
            _bound(src, n)
            for n in _own(fn)
            if n.type == "let_declaration"
            and n.child_by_field_name("alternative") is not None
            and (pat := n.child_by_field_name("pattern")) is not None
            and pat.type == "tuple_struct_pattern"
        } - {None}
        for n in _own(fn):
            if n.type == "let_declaration":
                pattern = n.child_by_field_name("pattern")
                value = n.child_by_field_name("value")
                if "ref mut" in src.text(pattern):
                    assigned |= _idents(src, value)  # `let AuthUser { id: ref mut uid, .. } = user`
                name = _bound(src, n) if pattern is not None else None
                if name is not None and (
                    pattern.type != "tuple_struct_pattern" or value is not None
                ):
                    bound.setdefault(name, []).append(value)
                else:
                    for x in _pattern_names(src, pattern):
                        bound.setdefault(x, []).append(None)
            elif n.type in ("assignment_expression", "compound_assignment_expr"):
                # `user = ..`, `(user.id, _) = ..`, `*user.id_mut() = ..`
                assigned |= {
                    src.text(x)
                    for x in walk(n.child_by_field_name("left"))
                    if x.type in ("identifier", "self")
                }
            elif (
                n.type == "macro_invocation"
                and _last(src.text(n.child_by_field_name("macro"))) in code.rebinding_macros
            ):
                # a checkout macro handed a name may rebind it (`impersonate!(user, ..)`)
                assigned |= _idents(src, n)
            elif n.type == "call_expression" and _call_name(src, n) == "extensions_mut":
                self.requests.clear()  # the handler rewrites what it reads back
            elif (
                n.type == "call_expression"
                and (
                    _MUTATORS.match(name := _call_name(src, n))
                    or name in code.mut_methods
                    or name.endswith("_mut")
                )
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
        # a request cloned or handed to code that may write its extensions
        for n in _own(fn):
            if n.type == "call_expression" and not _extension_read(src, n, self.requests):
                handed = {x for a in _args(n) for x in _idents(src, a)} & self.requests
                if (
                    _call_name(src, n) == "clone" and _idents(src, _receiver(n)) & self.requests
                ) or (handed and not self.request_caller(n)):
                    self.requests.clear()
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
            for n in more:
                held = {self.held(v) for v in bound[n]}
                self.attrs[n] = held.pop() if len(held) == 1 and None not in held else "is_flag"
                if n in unwrapped:
                    self.attrs[n] = ""  # `let Some(u) = maybe_user else { refuse }`
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
                    (
                        (name in _CALLER_METHODS and all(a.type == "string_literal" for a in args))
                        or _refuses_absence(src, node)
                    )
                    and name not in self.ours
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
            segs = _segments(_path_of(src, node))
            return (
                name in _CONVERTERS
                and len(args) == 1
                and (len(segs) < 2 or segs[0] in _ID_TYPES)
                and self.derived(args[0], depth + 1)
            )
        return False

    def identity(self, node: Node | None) -> bool:
        """A caller value naming who the caller is (`user.id`, `claims.sub`), not an attribute of
        theirs (`user.is_admin`, `let admin = user.is_admin`) nor a caller that may be absent."""
        held = self.held(node)
        return self.derived(node) and held is not None and held not in ("?", "")

    def held(self, node: Node | None, depth: int = 0) -> str | None:
        """The caller field a derived value is ("" the whole caller), None for an attribute."""
        whole = node
        node = _unwrap(node)
        if node is None or depth > 16:
            return None
        if node.type == "call_expression" and self.request_caller(node):
            # `req.extensions().get::<User>()` is an Option until refused
            refused = re.search(
                r"\.(ok_or(_else)?\(.*\)\s*\?|unwrap\(\)|expect\()", self.src.text(whole), re.S
            )
            return "" if refused else "?"
        if (
            node.type == "call_expression"
            and _receiver(node) is None
            and _call_name(self.src, node) != "format_"
        ):
            # `i64::from(user.is_admin)` is still the flag
            args = _args(node)
            return self.held(args[0], depth + 1) if len(args) == 1 else None
        if node.type == "call_expression" and _call_name(self.src, node) == "format_":
            args = _args(node)
            captured = (
                re.findall(r"(?<!\{)\{([A-Za-z_]\w*)", self.src.text(args[0])) if args else []
            )
            pieces = [self.attrs.get(c, "") for c in captured] + [
                self.held(a, depth + 1) for a in args[1:]
            ]
            return (
                "id"
                if pieces
                and all(p is not None and p != "?" and p and _IDENTITY.match(p) for p in pieces)
                else None
            )
        refused = False
        while node is not None and node.type == "call_expression" and _receiver(node) is not None:
            name = _call_name(self.src, node)
            if name in self.ours:
                return None
            if _IDENTITY.match(name) and not _args(node):
                return name  # `identity.id()`, `claims.user_id()`
            refused = refused or name in ("unwrap", "expect") or _refuses_absence(self.src, node)
            node = _unwrap(_receiver(node))
        if node is None:
            return None
        if node.type == "field_expression":
            field = self.src.text(node.child_by_field_name("field"))
            if self.held(node.child_by_field_name("value"), depth + 1) == "?":
                return "?"
            return field if _IDENTITY.match(field) else None
        if node.type in ("identifier", "self"):
            held = self.attrs.get(self.src.text(node), "")
            if held == "?" and refused:
                return ""  # `user.unwrap()`, `user.ok_or(..)?`: present from here on
            return held if held in ("", "?") or _IDENTITY.match(held) else None
        return ""

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


def _refuses_absence(src: Parsed, call: Node) -> bool:
    """`maybe.ok_or(..)?`: the value, or the handler returns."""
    return _call_name(src, call) in ("ok_or", "ok_or_else") and _tried(call)


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
        callers: dict[str, str],
        types: dict[str, str],
        depth: int,
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
        self.path_ids = set(ids)
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
                # a value merely built from an id is its own: two such bindings never agree
                bindings.setdefault(x, []).append(
                    (exact or f"{x}@{n.start_byte}") if carries else ""
                )
        for n in _own(self.fn):
            bound_from = None
            if n.type == "let_condition":
                bound_from = (n.child_by_field_name("pattern"), n.child_by_field_name("value"))
            elif n.type == "match_expression":
                scrutinee = n.child_by_field_name("value")
                for arm in walk(n.child_by_field_name("body")):
                    if (
                        arm.type == "match_arm"
                        and arm.parent is not None
                        and arm.parent.parent == n
                        and self.has_id(scrutinee)
                    ):
                        pattern = arm.child_by_field_name("pattern")
                        for x in _pattern_names(
                            self.src,
                            pattern.named_children[0]
                            if pattern is not None and pattern.named_children
                            else None,
                        ):
                            self.root.setdefault(x, x)
                            bindings.setdefault(x, []).extend(["", x])
            elif (
                n.type == "closure_expression"
                and n.parent is not None
                and n.parent.type == "arguments"
            ):
                call = n.parent.parent
                if (
                    call is not None
                    and call.type == "call_expression"
                    and self.has_id(_receiver(call))
                ):
                    bound_from = (n.child_by_field_name("parameters"), _receiver(call))
            if (
                bound_from is not None
                and bound_from[0] is not None
                and self.has_id(bound_from[1])
                and not self.loads(bound_from[1])  # `find(id).filter(|note| ..)` is the record
            ):
                # `if let Ok(k) = id.parse()`, `Some(id).map(|k| ..)`: they hold the id
                for x in _pattern_names(self.src, bound_from[0]):
                    self.root.setdefault(x, x)
                    bindings.setdefault(x, []).extend(["", x])
            # `for k in vec![id]`, `ids.iter().map(|k| ..)`: what iterates an id carries it
            if n.type == "for_expression" and self.has_id(n.child_by_field_name("value")):
                for x in _pattern_names(self.src, n.child_by_field_name("pattern")):
                    self.root.setdefault(x, x)
                    bindings.setdefault(x, []).extend(["", x])
            # `args.add(id)`, `ids.push(id)`: the receiver now holds the id
            elif (
                n.type == "call_expression"
                and _call_name(self.src, n) in _HOLDERS
                and any(self.has_id(a) for a in _args(n))
                and (root := _root(_receiver(n))) is not None
            ):
                self.root.setdefault(self.text(root), self.text(root))
                bindings.setdefault(self.text(root), []).extend(["", self.text(root)])
        written = _assigned(self.src, self.fn)
        shadowed = {
            x
            for n in _own(self.fn)
            if n.type == "let_declaration"
            for x in _pattern_names(self.src, n.child_by_field_name("pattern"))
        }
        self.unstable = (
            {n for n, roots in bindings.items() if n in self.root and len(set(roots)) > 1}
            | (written & self.root.keys())
            # `p.id` once `p` is shadowed or reassigned
            | {k for k in self.root if "." in k and k.split(".", 1)[0] in written | shadowed}
        )
        for n in self.unstable:
            self.root[n] = n
        self.ids = set(self.root)
        self.written = _assigned(self.src, self.fn, mutators=False)  # rebound, not mutated
        # a connection is always handed `&mut`: only a rebinding makes it another one
        self.rebound = _assigned(self.src, self.fn, mutators=False, refs=False)
        self.payload = {
            n
            for n, typ in self.types.items()
            if n in self.params and _generic(typ)[0] in ("Json", "Form", "Query", "Multipart")
        } | {
            x
            for p in (
                self.fn.child_by_field_name("parameters").named_children
                if self.fn.child_by_field_name("parameters") is not None
                else []
            )
            if p.type == "parameter"
            and _generic(
                self.src.text(p.child_by_field_name("type"))
                if p.child_by_field_name("type") is not None
                else ""
            )[0]
            in ("Json", "Form", "Query", "Multipart")
            for x in _pattern_names(self.src, p.child_by_field_name("pattern"))
        }
        self.lets: dict[str, int] = {}
        for n in _own(self.fn):
            if n.type == "let_declaration":
                for x in _pattern_names(self.src, n.child_by_field_name("pattern")):
                    self.lets[x] = self.lets.get(x, 0) + 1
        for n in sorted(
            (n for n in _own(self.fn) if n.type == "let_declaration"), key=lambda n: n.start_byte
        ):
            pattern = n.child_by_field_name("pattern")
            name = _bound(self.src, n)
            if name is None or name in self.types or self.lets.get(name, 0) != 1:
                continue
            if (typ := self.constructed(n.child_by_field_name("value"))) is not None:
                self.types[name] = typ
        self.closures = {
            name: n.start_byte
            for n in _own(self.fn)
            if n.type == "let_declaration"
            and (v := n.child_by_field_name("value")) is not None
            and v.type == "closure_expression"
            and (name := _bound(self.src, n)) is not None
        }
        self.local_macros = {
            self.text(n.child_by_field_name("name"))
            for n in _own(self.fn)
            if n.type == "macro_definition"
        }
        # a local closure handed an id: its parameters hold one
        for n in _own(self.fn):
            if (
                n.type == "let_declaration"
                and (v := n.child_by_field_name("value")) is not None
                and v.type == "closure_expression"
                and (name := _bound(self.src, n)) is not None
                and any(
                    c.type == "call_expression"
                    and _path_of(self.src, c) == name
                    and any(self.has_id(a) for a in _args(c))
                    for c in _own(self.fn)
                )
            ):
                for x in _pattern_names(self.src, v.child_by_field_name("parameters")):
                    self.root[x] = x
                    self.unstable.add(x)
        self.ids = set(self.root)
        self.records = {
            name
            for n in _own(self.fn)
            if n.type == "let_declaration"
            and (name := _bound(self.src, n)) is not None
            and (v := n.child_by_field_name("value")) is not None
            and self.loads(v)
        }
        self.lookups: list[Lookup] = []
        self.cover: list[set[str] | None] = []
        self.reads: list[bool] = []
        self.sessions: list[bool] = []
        self.made: dict[int, list[int]] = {}
        self.query_lookups: set[int] = set()
        self.queries: dict[str, int] = {}
        self.consumed: set[int] = set()
        self.targets: list[str | None] = []
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
        # `set_current_user(&mut tx, &user.id)`: a local the caller is written into
        for n in _own(self.fn):
            if n.type == "call_expression" and any(
                _idents(self.src, a) & self.v.callers for a in _args(n)
            ):
                for a in _args(n):
                    if (
                        a.type == "reference_expression"
                        and any(c.type == "mutable_specifier" for c in a.children)
                        and (root := _root(a.child_by_field_name("value"))) is not None
                    ):
                        self.session_names.add(self.text(root))
        # a parameter of a checkout extractor that isn't the caller may carry a session bound
        # to them
        self.session_names |= {
            name
            for name, typ in self.types.items()
            if name in self.params
            and _generic(typ)[0] in self.code.extractors
            and not _CALLER_TYPE.match(_generic(typ)[0])
        }

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
        if value is None or value.type != "call_expression":
            return False
        # any value a call built from the caller (`begin_as(Some(user.id))`,
        # `open_user_tx(&db, &user.id)`) that a lookup then runs on may be scoped by them
        handed = {x for a in _args(value) for x in _idents(self.src, a)}
        handed |= _idents(self.src, _receiver(value)) if _receiver(value) is not None else set()
        return (
            not self.v.derived(value)
            and bool(handed & self.v.callers)
            and not _is_query(self.src, value)
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
            if (
                receiver is None
                and name in _CONVERTERS
                and len(args) == 1
                and (
                    len(_segments(_path_of(self.src, node))) < 2
                    or _segments(_path_of(self.src, node))[0] in _ID_TYPES
                )
            ):
                return self.exact(args[0])  # `Uuid::parse_str(&id)`, never a checkout type's `from`
            segs = _segments(_path_of(self.src, node))
            if (
                receiver is None
                and len(segs) == 2
                and segs[0] in _ID_TYPES
                and segs[1] in _PARSERS
                and args
                and all(a.type in ("integer_literal", "string_literal") for a in args[1:])
            ):
                return self.exact(args[0])  # `i64::from_str_radix(&id, 36)`
        return None

    def built(self, node: Node | None) -> bool:
        """A value built from an id (`ActiveModel { id: Set(id), .. }`), not the id itself."""
        node = _unwrap(node)
        if node is not None and node.type == "identifier":
            name = self.text(node)
            return self.root.get(name) == name and name not in self.path_ids
        return self.exact(node) is None

    def exact_ids(self, values: list[Node]) -> set[str] | None:
        roots = [self.exact(v) for v in values if _idents(self.src, v) & self.ids]
        return None if not roots or None in roots else {r for r in roots if r}

    def client(self, node: Node | None) -> bool:
        """A value straight from the request's payload (`Json(q)`, `Query(p)`): an object the
        client picked, not the path's."""
        return bool(_idents(self.src, node) & self.payload)

    def has_id(self, node: Node | None) -> bool:
        if _idents(self.src, node) & self.root.keys():
            return True
        # `note.id`, `note.comment_id` of a loaded record
        records = getattr(self, "records", set())
        return node is not None and any(
            n.type == "field_expression"
            and self.text(n.child_by_field_name("value")) in records
            and _ID_FIELD.match(self.text(n.child_by_field_name("field")))
            for n in walk(node)
        )

    def loads(self, value: Node) -> bool:
        """Whether a value is (or wraps) a call or index that may load something by an id."""
        ids = set(self.root)
        for n in walk(value):
            if n.type == "call_expression":
                name = _call_name(self.src, n)
                # only a lookup gives something else back; `comment_key(id)`, `CommentKey(id)`,
                # `i64::wrapping_add(id, 1)` are still the id
                if not (
                    (name in _STORE_CALLS and _receiver(n) is not None)
                    or name in _SQL_FETCH | _DIESEL_FETCH | _SEA_FETCH | set(_SQLX_MACROS)
                    or name in _SQLX_FUNCTIONS
                ):
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
        self.reads.append(read)
        self.sessions.append(session)
        self.made.setdefault(node.id, []).append(k)
        return k

    def handoff(self, node: Node, cover: set[str] | None) -> None:
        self.handoffs.append((self.span(node), cover, node.start_byte))

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
        return self.result(self.pure_read(body))

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
            if _call_name(self.src, above) not in _QUERY_CHAIN:
                return out  # `.drop_note(&db, nid)` on the row: read as its own call
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
            self.sqlx(root, "query" if name == "sql_query" else name)
        elif (
            _receiver(root) is None
            and (
                name in ("find_by_id", "delete_by_id")
                or (name in ("find", "delete_many", "update_many") and "Entity" in _segments(path))
            )
            # a checkout fn of the name is read as code, not as sea-orm's (`NoteRepo::find_by_id`)
            and not (len(_segments(path)) > 1 and (_segments(path)[-2], name) in self.code.methods)
            and not (len(_segments(path)) == 1 and self.code.resolve(self.src, path, root))
        ):
            self.sea(root)
        elif name in ("find", "filter") and self.diesel_root(_receiver(root)):
            self.diesel(root)

    def sqlx(self, root: Node, name: str) -> None:
        links = self.chain(root)
        args = _args(root)
        if name.endswith("_with"):
            sql_node, record = (args[0] if args else None), None
            values = args[1:2]
        elif name in _SQLX_MACROS:
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
        if (
            not any(self.has_id(v) for v in values)
            and not self.has_id(sql_node)
            and not any(self.client(v) for v in values)
        ):
            return
        sql = self.sql_text(sql_node)
        fetch = next(
            (_call_name(self.src, c) for c in links[1:] if _call_name(self.src, c) in _SQL_FETCH),
            None,
        )
        parsed = _sql(sql) if sql is not None else None
        scoped, cover, columns = False, None, []
        if parsed is not None and parsed.equalities is not None:
            pairs = [(c, values[i]) for c, i in parsed.equalities if i < len(values)]
            if len(pairs) == len(parsed.equalities):
                scoped = any(
                    OWNER_CHECK_RX.match(c)
                    and self.v.identity(v)
                    and _agrees(c, self.v.held(v) or "")
                    for c, v in pairs
                )
                cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
                columns = sorted({c for c, v in pairs if self.has_id(v)})
        if name.endswith("_with"):
            scoped, cover = False, None  # `query_with(sql, args)`: which value fills which `$n`
        record_type = self.sql_record(record, parsed, macro=name in _SQLX_MACROS)
        read = (
            parsed is not None
            and parsed.kind == "select"
            and not parsed.aggregate
            and fetch in _SQL_READ
        )
        executor = self.executor(links[1:], _SQL_FETCH)
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
            target=(
                _where(f"{parsed.table}@{executor}", columns)
                if parsed is not None and parsed.table and executor is not None
                else None
            ),
        )
        self.query_lookups.add(k)
        for c in links[1:]:
            self.made.setdefault(c.id, []).append(k)
        self.keep(links[-1], k)

    def sql_record(self, record: str | None, parsed: _Sql | None, *, macro: bool) -> str | None:
        """The record a query reads. A row type without an owner field is only a projection
        unless the macro checked it against the whole row (`query_as!(T, "select * …")`)."""
        typ = self.code.record(_last(record)) if record else None
        name = parsed.table.rsplit(".", 1)[-1] if parsed is not None and parsed.table else ""
        # an unquoted name folds case (`note` is the `Note` struct); a quoted one is exact
        folded = [k for k in self.code.fields if k.lower() == name] if name[:1] != '"' else []
        exact = name.strip('"')
        table = exact if exact in self.code.fields else (folded[0] if len(folded) == 1 else None)
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
            if self.lets.get(name, 0) == 1:
                self.queries[name] = k
            fetched = any(
                c.type == "call_expression"
                and _call_name(self.src, c) in _SQL_FETCH | _DIESEL_FETCH | _SEA_FETCH
                for c in walk(last)
            )
            if not fetched:  # a builder finished elsewhere may be widened there
                x = self.lookups[k]
                self.lookups[k] = Lookup(x.span, False, x.checked, x.record_type)
                self.cover[k] = None

    def sql_text(self, node: Node | None) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        if node.type in ("string_literal", "raw_string_literal"):
            # escapes decoded: `\x20\x6f\x72` is ` or`, `\"` a quote
            return "".join(
                _unescape(self.text(c)) if c.type == "escape_sequence" else self.text(c)
                for c in node.named_children
                if c.type in ("string_content", "escape_sequence")
            )
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
        path = re.sub(r"\s+", "", self.text(node)).removesuffix("::table") if node else None
        table = path.rsplit("::", 1)[-1] if path else None
        chain = [*reversed(below), *self.chain(root)]
        wrapper = chain[-1].parent.parent if chain[-1].parent is not None else None
        if (
            wrapper is not None
            and wrapper.type == "call_expression"
            and chain[-1].parent.type == "arguments"
            and _call_name(self.src, wrapper) in ("delete", "update", "insert_into", "replace_into")
        ):
            chain += self.chain(wrapper)  # `diesel::delete(notes.find(id)).execute(conn)`
        self.consumed |= {c.id for c in chain}
        values = [a for c in chain for a in _args(c)]
        if not any(self.has_id(v) or self.client(v) for v in values):
            return
        pairs: list[tuple[str, Node]] | None = []
        for c in chain:
            name = _call_name(self.src, c)
            if name == "find" and len(_args(c)) == 1:
                pairs.append((self.code.primary_keys.get(table or "", "id"), _args(c)[0]))
            elif name not in _DIESEL_LINKS:
                pairs = None  # `union_all`, `or_filter`, a join: anything else widens or changes it
                break
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
        scoped, cover, columns = False, None, []
        if pairs is not None:
            scoped = any(
                OWNER_CHECK_RX.match(c) and self.v.identity(v) and _agrees(c, self.v.held(v) or "")
                for c, v in pairs
            )
            cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
            columns = sorted({c for c, v in pairs if self.has_id(v)})
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
        read = (
            bool(fetch)
            and fetch[0] in _DIESEL_READ
            and "optional" not in fetch[1:]
            and not any(
                re.search(r"\b(count|count_star|sum|max|min|avg)\b", self.text(c)) for c in chain
            )
        )
        session = any(
            _idents(self.src, a) & self.session_names
            for c in chain
            if _call_name(self.src, c) in _DIESEL_FETCH
            for a in _args(c)
        )
        k = self.add(
            root,
            Lookup(self.span(root), scoped, record_type=record),
            read=read,
            cover=cover,
            session=session,
            target=(
                _where(f"{path}@{executor}", columns)
                if path and (executor := self.executor(chain, _DIESEL_FETCH)) is not None
                else None
            ),
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
        if not any(self.has_id(v) or self.client(v) for v in values):
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
        scoped, cover, columns = False, None, []
        if pairs is not None:
            scoped = any(
                OWNER_CHECK_RX.match(c) and self.v.identity(v) and _agrees(c, self.v.held(v) or "")
                for c, v in pairs
            )
            cover = self.exact_ids([v for _, v in pairs if self.has_id(v)])
            columns = sorted({c for c, v in pairs if self.has_id(v)})
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
            read=fetch[:1] == ["one"]
            and not any(
                _call_name(self.src, c) in ("select_only", "column_as", "into_tuple", "count")
                for c in links
            ),
            cover=cover,
            session=session,
            target=(
                _where(f"{'::'.join(segs[:-1])}@{executor}", columns)
                if module and (executor := self.executor(links[1:], _SEA_FETCH)) is not None
                else None
            ),
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
        if _last(self.text(node.child_by_field_name("macro"))) in self.local_macros:
            self.local_macro(node)
            return
        tokens = next((c for c in node.named_children if c.type == "token_tree"), None)
        if tokens is None or not _idents(self.src, tokens) & self.ids:
            return
        name = _last(self.text(node.child_by_field_name("macro")))
        if (_LOG_MACROS.match(name) or name in _FORMAT_MACROS) and not _calls_in(tokens):
            return
        self.handoff(node, None)

    def local_macro(self, node: Node) -> None:
        """A `macro_rules!` defined in the function may close over the id: `wipe!()`."""
        name = _last(self.text(node.child_by_field_name("macro")))
        definition = next(
            (
                n
                for n in _own(self.fn)
                if n.type == "macro_definition" and self.text(n.child_by_field_name("name")) == name
            ),
            None,
        )
        if definition is not None and self.has_id(definition):
            self.handoff(node, None)

    def constructed(self, value: Node | None) -> str | None:
        """The type a value has: a typed receiver passed through (`state.repo.clone()`,
        `&state.repo`), or a checkout type built (`NoteRepo::new(db)`, `NoteRepo { .. }`)."""
        node = _unwrap(value)
        if node is None:
            return None
        if node.type == "struct_expression":
            name = _last(self.text(node.child_by_field_name("name")))
            return name if name in self.code.structs else None
        if node.type == "call_expression" and _receiver(node) is None:
            segs = _segments(_path_of(self.src, node))
            if (
                len(segs) >= 2
                and segs[-2] in self.code.structs
                and segs[-1] in ("new", "default", "from", "with", "connect", "open")
            ):
                return segs[-2]
            return None
        return self.type_of(node)

    def store(self, store: Node | None) -> str | None:
        """The store a lookup reads, by what holds it (`NoteStore.0`, `self.drafts`, `NOTES`);
        None for a local bound more than once, which may be a different store each time."""
        node = _unwrap(store)
        while (
            node is not None
            and node.type == "call_expression"
            and _call_name(self.src, node) in _TRANSPARENT
        ):
            node = _unwrap(_receiver(node))
        root = _root(node)
        text = re.sub(r"\s+", "", self.text(node))
        if root is None or "[" in text or "(" in text:
            return None  # `state.shards[shard]`, a value a call returns: which store isn't told
        name = self.text(root)
        if (
            name in self.written
            or self.lets.get(name, 0) > 1
            or (name in self.params and self.lets.get(name, 0))
        ):
            return None  # rebound, reassigned, swapped or shadowed: another store each time
        if name == "self":
            return f"store:@self{text[4:]}"  # the hop's caller says which instance
        if name in self.params:
            return f"store:@{text}"  # so does the argument it was handed
        if name in self.lets:
            return f"store:{text}"
        homes = self.code.static_homes.get(name, [])
        if name in self.code.renamed or name in self.code._block_uses(
            self.src, store, self.code.module_at(self.src, store)
        ):
            return None  # `use ARCHIVE as NOTES`: not the static so named
        return f"store:{homes[0]}::{text}" if len(homes) == 1 else None

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
        if node.type == "call_expression" and _receiver(node) is None:
            last = _last(_path_of(self.src, node))
            if last[:1].isupper() and last in self.code.structs:
                return last  # `NoteId(id)`
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
        if (
            receiver is not None
            and not any(self.has_id(v) for v in values)
            and any(self.client(v) for v in values)
            and name in _STORE_CALLS
            and not self.v.derived(receiver)
        ):
            # `NOTES.remove(&q.target)`: an object the client picked, never checked here
            self.add(
                call,
                Lookup(self.span(call), record_type=self.store_record(receiver)),
                read=False,
                cover=None,
            )
            return
        if (
            receiver is not None
            and not any(self.has_id(v) for v in values)
            and self.has_id(receiver)
            and not self.built(receiver)
            and name not in _CONVERSIONS | _COMBINATORS | _BUILDERS | _VALUE_FUNCTIONS | _ID_METHODS
        ):
            # `id.load(&db)`: a typed id that acts
            targets = self.callees(call, receiver, "", name)
            if targets and self.depth < 2:
                self.hop_into(call, targets)
            elif _LOOKUP_NAME.match(name) or _WRITE_NAME.match(name):
                self.add(
                    call, Lookup(self.span(call)), read=False, cover=self.exact_ids([receiver])
                )
            else:
                self.handoff(call, self.exact_ids([receiver]))  # `id.archive(&db)`: unread
            return
        if not any(self.has_id(v) for v in values):
            if (
                receiver is not None
                and self.has_id(receiver)
                and self.built(receiver)
                and not self.v.derived(receiver)
                and not self.loads(receiver)  # a loaded record's own methods (`.cloned()`)
                and name
                not in _CONVERSIONS
                | _COMBINATORS
                | _BUILDERS
                | _VALUE_FUNCTIONS
                | _ID_METHODS
                | _LOAD_ADAPTERS
            ):
                # an object built from the id that acts (`model.update(&db)`,
                # `NoteId(id).archive(&db)`)
                targets = self.callees(call, receiver, "", name)
                if targets and self.depth < 2:
                    self.hop_into(call, targets)
                elif _LOOKUP_NAME.match(name) or _WRITE_NAME.match(name):
                    self.add(
                        call,
                        Lookup(self.span(call)),
                        read=False,
                        cover=None,
                        session=self.on_session(call),
                    )
                else:
                    self.handoff(call, None)
            return
        cover = self.exact_ids([v for v in values if self.has_id(v)])
        path = _path_of(src, call)
        span = self.span(call)
        # a checkout function or method named like a std one (`extend(&db, id)`,
        # `NOTES.inspect(id)`) is still read
        ours = bool(self.callees(call, receiver, path, name)) if receiver or path else False
        if self.exact(call) is not None or (_INERT_CALLS.match(path or name) and not ours):
            return
        if name in _COMBINATORS and not (closures and name in _SEARCHES) and not ours:
            return
        if name in _RESPONSE_PARTS and _response(self.src, receiver):
            return
        if name in _BUILDERS and not ours:
            root = _root(_strip_transparent(self.src, receiver))
            if receiver is None or (root is not None and self.lets.get(self.text(root), 0)):
                return  # building a local value
            self.handoff(
                call, cover
            )  # `state.jobs.push(Job::Delete(id))`: someone acts on it later
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
        if path in self.closures and call.start_byte > self.closures[path]:
            return  # `let wipe = |id| ..; wipe(id)`: the closure's body is read in place
        if receiver is None and path in self.local_macros:
            self.handoff(call, cover)
        last = path.rsplit("::", 1)[-1]
        if last[:1].isupper() and re.search(r"[a-z]", last):
            # a tuple struct or variant built with the id (`NoteId(id)`): a value, not an action
            return
        # a validator's value is thrown away (`validate_id(&id)?;`): one whose value is kept may
        # have fetched something (`let note = api.check(id)?`)
        validator = bool(_VALIDATOR_NAME.match(name)) and _ignored(call)
        targets = self.callees(call, receiver, path, name)
        if targets is None:
            if not validator:
                self.handoff(call, cover)
        elif targets:
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if self.accessor(call, targets) is not None:
                    return
                if not validator:
                    self.handoff(call, cover)
                return
            self.hop_into(call, targets)
        elif self.on_session(call):
            self.add(call, Lookup(span), read=False, cover=cover, session=True)
        elif _LOOKUP_NAME.match(name) and (receiver is None or not self.v.derived(receiver)):
            self.add(call, Lookup(span), read=False, cover=cover, session=self.on_session(call))
        elif not validator:
            self.handoff(call, cover)

    def library(self, receiver: Node | None, path: str) -> bool:
        """A call that is surely a library's: a receiver whose type names no checkout type or
        trait, or a path into a crate outside the checkout."""
        module = self.code.module_at(self.src, receiver)

        def ours(name: str) -> bool:
            return (
                name in self.code.types
                or name in self.code.traits
                or name in self.code.structs
                or self.code.type_path(self.src, module, name)[1]
            )

        if receiver is not None:
            typ = self.type_of(receiver)
            return typ is not None and not any(ours(n) for n in re.findall(r"[A-Za-z_]\w*", typ))
        segs = _segments(path)
        if len(segs) < 2:
            return False
        head = self.code.uses.get((self.src.file.rel, module), {}).get(segs[0], [segs[0]])[0]
        return (
            head not in self.code.crates
            and head not in ("crate", "self", "super")
            and not ours(segs[0])
            and (self.src.crate, (*module, segs[0])) not in self.code.modules
        )

    def on_session(self, call: Node) -> bool:
        """Run through a session opened for the caller: one kept in a local, or opened inline
        (`db.as_user(&user.id).note_for(id)`)."""
        receiver = _receiver(call)
        inline = receiver is not None and any(
            n.type == "call_expression" and self.session(n) for n in walk(receiver)
        )
        return inline or bool(
            self.session_names
            & (_idents(self.src, receiver) | {n for a in _args(call) for n in _idents(self.src, a)})
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
        ):
            expr = _unwrap(_receiver(expr))
            if expr is None:
                return None
        if expr.type != "call_expression" or _call_name(target.src, expr) not in _STORE_CALLS:
            return None
        receiver = _unwrap(_receiver(expr))
        if receiver is None or _idents(target.src, receiver) - {"self"}:
            return None
        keys = [_unwrap(a) for a in _args(expr)]
        if not keys or any(
            k is None or k.type != "identifier" or [target.src.text(k)] not in params
            for k in keys[:1]
        ):
            return None  # `remove(&(id + 1))`, `remove(&linked(id))`: another key
        inner = _Walk(self.o, target, {}, {}, {}, self.depth + 1, set())
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
        target_store = self.qualified(inner.store(receiver), call, target)
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
        for target in targets:
            scan, exact = self.o.hop(self, target, call)

            def mapped(inner: set[str] | None, exact: dict[str, str] = exact) -> set[str] | None:
                return {exact[p] for p in inner} if inner and inner <= exact.keys() else None

            for x, read, inner, where in zip(
                scan.facts.lookups, scan.reads, scan.covers, scan.targets, strict=True
            ):
                where = self.qualified(where, call, target)
                # protection is credited only from the handler's own code: what a hop scopes or
                # checks comes back exposed
                self.add(
                    call,
                    Lookup(x.span, False, False, x.record_type),
                    read=read and scan.pure_read,
                    cover=mapped(inner),
                    target=where,
                )
            self.caller = self.caller or scan.facts.caller
            if scan.facts.handoff:
                self.handoffs.append(
                    (scan.facts.handoff, mapped(scan.handoff_cover), call.start_byte)
                )

    def executor(self, calls: list[Node], names: set[str]) -> str | None:
        """The connection a query runs on (`&db`, `&mut *tx`, `conn`), None when it is rebound."""
        for c in calls:
            if _call_name(self.src, c) in names and _args(c):
                arg = _args(c)[0]
                root = _root(arg)
                if root is not None and (
                    self.text(root) in self.rebound or self.lets.get(self.text(root), 0) > 1
                ):
                    return None
                return re.sub(r"[&*\s]|\bmut\b", "", self.text(arg))
        return ""

    def qualified(self, where: str | None, call: Node, target: _Fn) -> str | None:
        """A callee's store named from here: `self` is the receiver the call is made on, a
        parameter the argument handed to it (`drafts.find(id)` and `published.remove(id)`
        never share a store)."""
        if where is None or not where.startswith("store:@"):
            return where
        rest = where.removeprefix("store:@")
        head, _, tail = rest.partition(".")
        if head == "self":
            outer = self.store(_receiver(call))
        else:
            params = target.node.child_by_field_name("parameters")
            names = [
                _pattern_names(target.src, p.child_by_field_name("pattern"))
                for p in (params.named_children if params is not None else [])
                if p.type == "parameter"
            ]
            args = _args(call)
            index = next((i for i, n in enumerate(names) if n == [head]), None)
            outer = self.store(args[index]) if index is not None and index < len(args) else None
        return f"{outer}.{tail}" if outer is not None and tail else outer

    # ---- the allow-listed statements (D8, D25)
    def load(self, expr: Node | None) -> int | None:
        """The one read an expression is, unwrapped of `?`, `.await` and absence refusals; never a
        fallback, the query itself or a list."""
        expr = self.strip_absence(expr)[0]
        if expr is None or expr.type not in ("call_expression", "index_expression", "identifier"):
            return None
        if expr.type == "identifier":
            name = self.text(expr)
            k = self.queries.get(name)
            stable = name not in self.written and self.lets.get(name, 0) == 1
            return k if k is not None and self.reads[k] and stable else None
        # the lookup itself, through `?`, `.await` and error or absence adapters only: a wrapper
        # (`as_mine(load)`), a closure (`.map(|n| ..)`, `(|| ..)()`) or `.and(x)` returns
        # something else
        node: Node | None = expr
        while node is not None:
            if node.id in self.made:
                ks = set(self.made[node.id])
                k = next(iter(ks))
                return k if len(ks) == 1 and self.reads[k] else None
            if node.type in ("try_expression", "await_expression", "parenthesized_expression"):
                node = node.named_children[0] if node.named_children else None
            elif node.type == "call_expression" and _call_name(self.src, node) in _LOAD_ADAPTERS:
                node = _unwrap(_receiver(node))
            else:
                return None
        return None

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
        if self.depth > 0:
            # in a helper only an `Err` refuses: a 403 value passes the handler's `?`
            return node.type == "call_expression" and _path_of(self.src, node) == "Err" and err
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
            and _call_name(self.src, node) in ("cloned", "clone", "copied")
        ):
            node = _unwrap(_receiver(node))
        return len(self.lookups) == 1 and self.load(node) == 0

    def result(self, pure_read: bool) -> _Scan:
        # a hand-off is never covered: which object the code we can't read acts on can't be
        # told (D29)
        unheld = [(span, roots) for span, roots, _ in self.handoffs]
        lookups = []
        for k, x in enumerate(self.lookups):
            if self.sessions[k] and not x.scoped:
                # D28: through a session bound to the caller: listed, neither judged nor credited
                unheld.append((x.span, self.cover[k]))
                continue
            # D31: no check is credited in Rust, only a query bound to the caller (shape 1); a
            # record with a field we can't tell from an owner is no ownerless record
            record = (
                None
                if x.record_type
                and (
                    self.code.hidden_link(x.record_type)
                    or self.code.use_alias(_strip(x.record_type))
                )
                else x.record_type
            )
            lookups.append((k, Lookup(x.span, x.scoped, False, record)))
        handoff, handoff_cover = unheld[0] if unheld else (None, None)
        return _Scan(
            HandlerFacts(
                lookups=tuple(x for _, x in lookups),
                caller=self.caller,
                hop=self.hop,
                handoff=handoff,
            ),
            covers=tuple(self.cover[k] for k, _ in lookups),
            reads=tuple(self.reads[k] for k, _ in lookups),
            targets=tuple(self.targets[k] for k, _ in lookups),
            handoff_cover=handoff_cover,
            pure_read=pure_read,
        )


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
        if re.fullmatch(r"\w+", handler) and _bindings(src, node, handler) > 1:
            return HandlerFacts(handoff=span, takes_id=True)
        closure = _let_closure(src, node, handler) if re.fullmatch(r"\w+", handler) else None
        if closure is not None:
            target = _Fn(src, closure, module)  # `let h = |..| ..; get(h)`
        elif node is not None and node.type in ("closure_expression", "function_item"):
            target = _Fn(src, node, module, _impl_owner(src, node))
        elif re.fullmatch(r"[\w:]+", handler):
            bound = _let_value(src, node, handler) if re.fullmatch(r"\w+", handler) else None
            if re.fullmatch(r"\w+", handler) and _is_parameter(src, node, handler):
                return HandlerFacts(handoff=span, takes_id=True)  # handed in by the caller
            name = (
                src.text(bound)
                if bound is not None and bound.type in ("identifier", "scoped_identifier")
                else handler
            )
            found = self.code.resolve(src, name, node, fallback=False)
            if not found or len(found) != 1:
                return HandlerFacts(handoff=span, takes_id=True)
            target = found[0]
        else:
            return HandlerFacts(handoff=span, takes_id=True)
        ids, callers, types, unread, requests = self.parameters(target)
        if unread is not None:
            return HandlerFacts(handoff=unread, takes_id=True)
        body_text = target.src.text(target.node.child_by_field_name("body"))
        if not ids or re.search(r"\b(match_info|uri|full_url)\b", body_text):
            # the id may come from the request itself (`req.match_info()`, `req.uri()`)
            ids = {**ids, **{r: r for r in requests}}
        if not ids and self.handed_data(target):
            # a middleware may have loaded the record and handed it over (`Extension<Note>`)
            return HandlerFacts(handoff=span, takes_id=True)
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
    ) -> tuple[dict[str, str], dict[str, str], dict[str, str], CodeSpan | None, set[str]]:
        """(the path ids, the caller names with the caller field each holds ("" for the whole
        caller, "?" for one that may be absent), declared types, an unreadable caller, request
        names)."""
        src = target.src
        module = self.code.module_at(src, target.node)
        ids: dict[str, str] = {}
        callers: dict[str, str] = {}
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
            outer = self.code.type_path(src, module, outer)[0][-1]
            names = [n for n in _pattern_names(src, pattern) if n != "_"]
            if outer in self.code.derived_extractors and unread is None:
                # its fields are extracted by code we don't read: maybe the path id
                unread = CodeSpan(path=RepoPath(src.file.rel), line=src.line(p))
                continue
            if self.carries_path(src, module, type_text):
                for n in names:
                    ids[n] = n
                if pattern is not None and pattern.type == "identifier" and inner_args:
                    for f in self.code.structs.get(_strip(inner_args[0]), {}):
                        ids[f"{src.text(pattern)}.{f}"] = f"{src.text(pattern)}.{f}"
                continue
            if outer in _REQUEST_TYPES:
                requests |= set(names)
                continue
            words = set(re.findall(r"[A-Za-z_]\w*", type_text))
            if outer in _PAYLOAD_TYPES or words & _PAYLOAD_TYPES:
                if pattern is not None and pattern.type == "identifier":
                    types[src.text(pattern)] = type_text
                elif len(names) == 1 and inner_args:
                    types[names[0]] = inner_args[0]
                continue  # what the client sent, whatever its type is called
            # `type CurrentUser = Option<User>` hides the Option
            aliased = {
                x
                for w in words
                for x in re.findall(r"[A-Za-z_]\w*", self.code.alias_text(src, module, w) or "")
            }
            optional = bool((words | aliased) & {"Option", "Result", "Either"})
            attrs = {n: ("?" if optional else h) for n, h in _held_by(src, pattern).items()}
            if (
                outer in ("Extension", "ReqData")
                and inner_args
                and _CALLER_TYPE.match(_strip(inner_args[0]))
            ):
                # server code put it there (D26), unless it copied it from the request unverified
                if not self.code.inserted_unverified(_strip(inner_args[0])):
                    callers.update(attrs)
                continue
            caller = self.caller_type(type_text)
            if caller is None:
                if unread is None and any(
                    re.search(
                        r"\b(Path|RawPathParams|match_info|uri|OriginalUri|path)\b",
                        f.src.text(f.node),
                    )
                    for w in words
                    for f in self.code.extractors.get(w, [])
                ):
                    # a checkout extractor that reads the path may load the object (`Account`)
                    unread = CodeSpan(path=RepoPath(src.file.rel), line=src.line(p))
                if len(names) == 1:
                    types[names[0]] = type_text
                continue
            path, ours = self.code.type_path(src, module, caller)
            if (
                ours
                and unread is None
                and any(
                    re.search(
                        r"\b(Path|RawPathParams|match_info|uri|OriginalUri)\b", f.src.text(f.node)
                    )
                    for f in self.code.extractors.get(path[-1], [])
                )
            ):
                # an extractor reading the path itself may load the object: not read here
                unread = CodeSpan(path=RepoPath(src.file.rel), line=src.line(p))
            if ours:
                kind = self.code.caller_kind(path[-1])
            else:
                kind = (
                    "trusted"
                    if path[-1] in _LIBRARY_CALLERS
                    and len(path) > 1
                    and path[0] in _LIBRARY_CRATES  # imported from actix-identity / axum-login
                    else "unread"
                )
            if kind == "trusted":
                callers.update(attrs)
            elif kind == "unread" and unread is None:
                unread = CodeSpan(path=RepoPath(src.file.rel), line=src.line(p))
        return ids, callers, types, unread, requests

    def carries_path(
        self, src: _Src, module: tuple[str, ...], type_text: str, seen: frozenset[str] = frozenset()
    ) -> bool:
        """`Path<i64>`, `web::Path<(u64,)>`, `WithRejection<Path<_>, _>`, `OptionalPath<_>`, a
        typed path struct, an alias of one, or a checkout extractor that reads the path."""
        for name in re.findall(r"[A-Za-z_]\w*", type_text):
            path, _ = self.code.type_path(src, module, name)
            name = path[-1]
            if name in _PATH_TYPES or name in self.code.typed_paths:
                return True
            alias = self.code.module_aliases.get(
                (src.crate, module, name)
            ) or self.code.aliases.get(name)
            if (
                alias is not None
                and name not in seen
                and self.carries_path(src, module, alias, seen | {name})
            ):
                return True  # `type NotePath = Path<i64>;` (`type Result<T> = ..` names itself)
            impls = self.code.extractors.get(name, [])
            if (
                impls
                and not _CALLER_TYPE.match(name)
                and not _is_guard_name(name)
                and any(
                    _raw_reads(f.src, f.node, set(), self.code)
                    or re.search(
                        r"\b(Path|RawPathParams|match_info|uri|OriginalUri|path)\b",
                        f.src.text(f.node),
                    )
                    or (
                        f.node.child_by_field_name("body") is not None
                        and self._reads_beyond_extensions(f)
                    )
                    for f in impls
                )
            ):
                return True
        return False

    def _reads_beyond_extensions(self, f: _Fn) -> bool:
        """An extractor body handing the request to anything but an extensions read."""
        body = f.node.child_by_field_name("body")
        params = f.node.child_by_field_name("parameters")
        request = {
            f.src.text(p.child_by_field_name("pattern"))
            for p in (params.named_children if params is not None else [])
            if p.type == "parameter" and not re.search(r"(?i)state", f.src.text(p))
        }
        return any(
            n.type == "call_expression"
            and not _extensions(f.src, _receiver(n))
            and {x for a in _args(n) for x in _idents(f.src, a)} & request
            for n in walk(body)
        )

    def handed_data(self, target: _Fn) -> bool:
        """A parameter a middleware filled with something else than the caller or server state:
        `Extension(note): Extension<Note>`."""
        params = target.node.child_by_field_name("parameters")
        for p in params.named_children if params is not None else []:
            typ = p.child_by_field_name("type") if p.type == "parameter" else None
            text = target.src.text(typ) if typ is not None else ""
            for m in re.finditer(r"\b(?:Extension|ReqData)\s*<", text):
                # what it holds, through any wrapper: `Extension<Arc<RwLock<Note>>>`
                held = [
                    w
                    for w in re.findall(r"[A-Za-z_]\w*", _balanced(text, m.end() - 1))
                    if w not in _WRAPPERS and w not in ("std", "sync", "tokio", "parking_lot")
                ]
                if any(
                    not _CALLER_TYPE.match(w)
                    and (not _INFRASTRUCTURE.search(w) or self.holds_record(w))
                    for w in held
                ):
                    return True
        return False

    def holds_record(self, name: str) -> bool:
        """A checkout struct holding another: `RouteState { note: Note }`."""
        return any(
            t in self.code.structs
            for typ in self.code.structs.get(name, {}).values()
            for t in re.findall(r"[A-Za-z_]\w*", typ)
        )

    def caller_type(self, type_text: str) -> str | None:
        """The auth type a parameter carries: `AuthUser`, `Option<AuthUser>`,
        `web::ReqData<Claims>`; None for anything else."""
        from traust_core.v1.providers.rust_routes import _is_guard

        for name in re.findall(r"[A-Za-z_]\w*", type_text):
            if (
                name not in _WRAPPERS
                and name not in ("web", "axum", "extract", "actix_web", "Result", "Either")
                and _is_guard(name)
            ):
                return name
        return None

    def scan(
        self,
        target: _Fn,
        ids: dict[str, str],
        callers: dict[str, str],
        types: dict[str, str],
        depth: int,
        requests: set[str] | None = None,
    ) -> _Scan:
        key = (
            target.src.file.rel,
            target.node.start_byte,
            frozenset(ids.items()),
            frozenset(callers.items()),
            depth,
            frozenset(types.items()),
            frozenset(requests or ()),
        )
        if key not in self.code.scans:
            walk = _Walk(self, target, ids, callers, types, depth, set(requests or ()))
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
        if (receiver := _receiver(call)) is not None and walk.has_id(receiver):
            mapping["self"] = receiver  # `id.load(&db)`
        inner_ids = {p: p for p, v in mapping.items() if walk.has_id(v)}
        # only who the caller is crosses a hop, never an attribute (`user.is_admin`) as the caller
        handed = {p: "" for p, v in mapping.items() if p not in inner_ids and walk.v.identity(v)}
        receiver = _receiver(call)
        if receiver is not None and walk.v.identity(receiver):
            handed["self"] = ""
        scan = self.scan(target, inner_ids, handed, ptypes, walk.depth + 1)
        return scan, {p: r for p, v in mapping.items() if (r := walk.exact(v))}
