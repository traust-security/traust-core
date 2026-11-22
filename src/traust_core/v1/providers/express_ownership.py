"""Ownership of the object an Express id route acts on, read from its handler and the
same-repository functions it calls. Protection counts only from allow-listed shapes (D8)."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.route_ownership import (
    OWNER_CHECK_RX,
    OWNER_FIELD_RX,
    PRIVILEGED_RX,
    HandlerFacts,
    Lookup,
)
from traust_core.v1.providers.syntax import Node, Parsed, walk

_FUNCTIONS = (
    "arrow_function",
    "function_expression",
    "function",
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
)
_SCOPES = (*_FUNCTIONS, "class_declaration", "class")
_UNWRAP = (
    "await_expression",
    "parenthesized_expression",
    "as_expression",
    "non_null_expression",
    "satisfies_expression",
    "type_assertion",
)
# the store calls a model, delegate or repository answers, and which of them only read
_READS = {
    "findById",
    "findByPk",
    "findUnique",
    "findUniqueOrThrow",
    "findOne",
    "findFirst",
    "findFirstOrThrow",
    "findOneBy",
    "findOneOrFail",
    "findOneByOrFail",
    "findByIdOrFail",
    "get",
}
_WRITES = {
    "findByIdAndUpdate",
    "findByIdAndDelete",
    "findByIdAndRemove",
    "findOneAndUpdate",
    "findOneAndDelete",
    "findOneAndRemove",
    "updateOne",
    "updateMany",
    "deleteOne",
    "deleteMany",
    "update",
    "delete",
    "destroy",
    "remove",
    "upsert",
    "set",
    "save",
}
_STORE_CALLS = _READS | _WRITES | {"find", "findMany", "findAll", "findBy", "count", "exists"}
# fetches that refuse a missing record themselves
_OR_FAIL = {"findUniqueOrThrow", "findFirstOrThrow", "findOneOrFail", "findOneByOrFail"}
_LOOKUP_NAME = re.compile(
    r"^(get|find|fetch|load|read|lookup|select|query|search|retrieve|delete|remove|update|destroy)"
    r"([A-Z_]|$)"
)
_AUTHORIZE_NAME = re.compile(
    r"^(check|verify|authori[sz]e|assert|ensure|require|validate|enforce|can|has|is|owns)([A-Z_]|$)"
)
_VALIDATOR_NAME = re.compile(
    r"^(validate|check|verify|assert|ensure|require)(Id|Ids|Uuid|ObjectId|Param|Params|Input"
    r"|Format|NotEmpty|NotNull)?$|^is(Valid(ObjectId|Id|Uuid)?|UUID|Uuid|MongoId|ObjectId)$"
)
_CONVERSIONS = {
    "Number",
    "String",
    "parseInt",
    "parseFloat",
    "BigInt",
    "ObjectId",
    "Types.ObjectId",
}
_CONVERSION_METHODS = {"toString", "valueOf"}
_INERT_ROOTS = re.compile(r"^(console|logger|log|JSON|Math|Object\.keys|debug)$")
_THROWN = re.compile(r"(Error|Exception)$")
_ID_TYPES = re.compile(r"^(\w+\.)*(ObjectId|ObjectID|Number|String|BigInt|Date)$")
# what a caller object holds about itself (`req.user.id`, `req.auth.payload.sub`, its tenant);
# never another user it names (`req.user.managerId`)
_SELF_FIELD = re.compile(
    r"(?i)^(_?id|sub|uid|uuid|oid|user_?(id|uuid|name)?|email|login|payload|claims|data|"
    r"(account|org|organi[sz]ation|tenant|team|workspace|company|customer|client|realm|group)"
    r"_?(id|uuid)?)$"
)
_PRIVILEGE_FLAG = re.compile(r"^(is)?(Admin|Superuser|SuperUser|Staff|admin|superuser|staff)$")
_MUTATORS = re.compile(r"^(set\w*|push|splice|assign|update|delete)$")
# library calls that write into their first argument (`_.merge(req.user, req.body)`)
_WRITES_FIRST = re.compile(
    r"^(Object\.assign|Object\.defineProperty|Reflect\.set|(\w+\.)?(merge\w*|assign\w*|extend|"
    r"defaults\w*|set\w*))$"
)
# library calls that only read the request they are handed
_READS_REQUEST = {"validationResult"}
# request members that may carry a path id another way
_OPAQUE_REQUEST = {"param", "path", "url", "originalUrl", "baseUrl", "route", "_parsedUrl"}
_MAX_DEPTH = 64
_FUNCTION_VALUES = ("arrow_function", "function_expression", "function")
_DECLARED_FUNCTIONS = (
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
)
# library wrappers that only forward a handler's rejection to `next` (express-async-handler, …)
_ASYNC_WRAPPER = re.compile(
    r"^(asyncHandler|expressAsyncHandler|catchAsync|catchAsyncErrors|asyncMiddleware|asyncWrap|"
    r"asyncWrapper|wrapAsync|asyncRoute|asyncify)$"
)
# text without which a function can't write the caller
_MAY_WRITE = re.compile(
    r"\.(user|auth|locals)\b|assign|merge|extend|defaults|\bset\w*\(|defineProperty"
)
_Pos = int
# what a check verifies and a lookup needs verified: (the id, the model, the field); "*" is any
_Key = tuple[str, str, str]


def unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type in _UNWRAP:
        node = next(
            (
                c
                for c in node.named_children
                if c.type not in ("type_annotation", "predefined_type", "type_arguments")
            ),
            None,
        )
        if node is not None and node.type in ("type_identifier", "generic_type"):
            return None
    return node


def args(call: Node) -> list[Node]:
    a = call.child_by_field_name("arguments")
    return [x for x in a.named_children if x.type != "comment"] if a is not None else []


def own(fn: Node) -> Iterator[Node]:
    """The nodes of `fn`'s own body: nested functions and classes are yielded, not entered."""
    body = fn.child_by_field_name("body")
    stack = [body] if body is not None else []
    while stack:
        node = stack.pop()
        yield node
        if node.type not in _SCOPES:
            stack.extend(node.named_children)


def statements(fn: Node) -> list[Node]:
    """A function body's statements; an arrow's expression body is `return <expr>`."""
    body = fn.child_by_field_name("body")
    if body is None:
        return []
    if body.type != "statement_block":
        return [body]
    return [s for s in body.named_children if s.type not in ("comment", "empty_statement")]


def param_patterns(fn: Node) -> list[Node]:
    single = fn.child_by_field_name("parameter")
    if single is not None:
        return [single]
    params = fn.child_by_field_name("parameters")
    out = []
    for p in params.named_children if params is not None else []:
        if p.type in ("required_parameter", "optional_parameter"):
            pat = p.child_by_field_name("pattern")
            if pat is not None:
                out.append(pat)
        elif p.type == "assignment_pattern":
            out.append(p.child_by_field_name("left"))
        elif p.type != "comment":
            out.append(p)
    return out


def bound_names(src: Parsed, pattern: Node | None) -> list[str]:
    """The names a binding pattern introduces (`{ id, user: me }`, `[a, b]`, `x`)."""
    if pattern is None:
        return []
    if pattern.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [src.text(pattern)]
    out = []
    for c in pattern.named_children:
        if c.type == "pair_pattern":
            out += bound_names(src, c.child_by_field_name("value"))
        elif c.type == "object_assignment_pattern":
            out += bound_names(src, c.child_by_field_name("left"))
        else:
            out += bound_names(src, c)
    return out


def chain_text(src: Parsed, node: Node | None) -> str:
    """`req.user.sub` for a member chain of plain names, else ''."""
    parts: list[str] = []
    node = unwrap(node)
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None:
                return ""
            parts.append(src.text(prop))
        else:
            index = unwrap(node.child_by_field_name("index"))
            if index is None or index.type != "string":
                return ""
            parts.append(
                "".join(src.text(c) for c in index.named_children if c.type == "string_fragment")
            )
        node = unwrap(node.child_by_field_name("object"))
    if node is None or node.type not in ("identifier", "this"):
        return ""
    return ".".join([src.text(node), *reversed(parts)])


def callee_name(src: Parsed, call: Node) -> str:
    fn = unwrap(call.child_by_field_name("function"))
    if fn is not None and fn.type == "member_expression":
        return src.text(fn.child_by_field_name("property"))
    return src.text(fn) if fn is not None else ""


def converted(src: Parsed, node: Node | None) -> Node | None:
    """The value `Number(x)`, `parseInt(x, 10)`, `new ObjectId(x)`, `+x` or `x.toString()`
    converts, else None."""
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "unary_expression" and src.text(node.child_by_field_name("operator")) == "+":
        return node.child_by_field_name("argument")
    if node.type not in ("call_expression", "new_expression"):
        return None
    fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    a = args(node)
    if src.text(fn) in _CONVERSIONS and a and all(x.type == "number" for x in a[1:]):
        return a[0]
    if (
        fn is not None
        and fn.type == "member_expression"
        and not a
        and src.text(fn.child_by_field_name("property")) in _CONVERSION_METHODS
    ):
        return fn.child_by_field_name("object")
    return None


def string_value(src: Parsed, node: Node | None) -> str | None:
    node = unwrap(node)
    if node is not None and node.type == "string":
        return "".join(src.text(c) for c in node.named_children if c.type == "string_fragment")
    return None


# ---- the checkout's code, resolved exactly


@dataclass
class _File:
    src: Parsed
    functions: dict[str, list[Node]] = field(default_factory=dict)
    objects: dict[str, dict[str, Node]] = field(default_factory=dict)  # literal: prop -> fn
    classes: dict[str, Node] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)  # name -> constructor text
    models: dict[str, str | None] = field(default_factory=dict)  # name -> record, a store
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (file, export)
    namespaces: dict[str, str] = field(default_factory=dict)  # `import * as m` -> file
    exports: dict[str, str] = field(default_factory=dict)  # exported -> local
    rebound: set[str] = field(default_factory=set)  # names or objects assigned after definition


@dataclass(frozen=True)
class Target:
    """A checkout function a call runs, the class it is a method of, and the class of the
    instance it runs on, when known (`this` resolves from it)."""

    rel: str
    fn: Node
    cls: Node | None = None
    instance: tuple[str, Node] | None = None


@dataclass(frozen=True)
class Writer:
    """A checkout function that writes the caller: its file, node and name ('' if anonymous)."""

    rel: str
    fn: Node
    name: str
    built: bool = False  # named for the factory that returns it (`impersonation()`)


@dataclass(frozen=True)
class _Model:
    record: str | None  # the record type a model or store holds, when known
    key: str  # which model or store it is
    sync: bool = False  # a `Map`, read without awaiting


class JsCode:
    """Each JS/TS file's functions, object literals, classes, instances, models and stores, its
    imports and exports; and the record types with their fields (for the classification)."""

    def __init__(self, sources: list[Parsed], prisma: list[str]) -> None:
        self.files = {s.file.rel: _File(s) for s in sources}
        self.fields_by_record: dict[str, list[str]] = {}
        self.holds: dict[str, set[str]] = {}
        # records whose fields we can't all read, or that point at another record
        self.linked: set[str] = set()
        self.mongoose: set[str] = set()  # Mongoose drops a filter key its schema lacks
        self.refs: dict[tuple[str, str], str] = {}  # (model, field) -> the model it references
        for f in self.files.values():
            self._index(f)
        for text in prisma:
            self._prisma(text)
        self.fields = self._fields()
        self.scans: dict[tuple, _Scan] = {}
        self._writers: list[Writer] | None = None

    def writers(self) -> list[Writer]:
        """The checkout functions that may forge who is calling for what runs after them: they
        write `req.user`, `req.auth` or `res.locals.user` from the request's own data (its body,
        query, params, a raw header or cookie), or with a value we can't read; and those that
        hand their request to one."""
        if self._writers is None:
            self._writers = []
            functions = {
                rel: [
                    n
                    for n in walk(f.src.root)
                    if n.type in _FUNCTION_VALUES or n.type in _DECLARED_FUNCTIONS
                ]
                for rel, f in self.files.items()
                if _MAY_WRITE.search(f.src.file.text) and not _minified(rel, f.src.file.text)
            }
            for rel, nodes in functions.items():
                src = self.files[rel].src
                for n in nodes:
                    if not _MAY_WRITE.search(src.text(n)):
                        continue
                    req, res = _request_names(src, n)
                    if not req or not _handles_request(src, n, req, res):
                        continue
                    written = caller_writes(src, n, req, res)
                    if req and _hands_caller(src, n, req):
                        written = [*written, None]  # `applyOverrides(req.user, req.query)`
                    if not written:
                        continue
                    if not any(_from_request(src, n, req, v) for v in written):
                        continue  # set from a credential, the session or the caller itself
                    self._writers.append(Writer(rel, n, *_function_name(src, n)))
            # a function handing its request to a writer writes through it (`attach(req)`)
            every = (
                {
                    rel: [
                        n
                        for n in walk(f.src.root)
                        if n.type in _FUNCTION_VALUES or n.type in _DECLARED_FUNCTIONS
                    ]
                    for rel, f in self.files.items()
                }
                if self._writers
                else {}
            )
            for _ in range(4):
                names = {w.name for w in self._writers if w.name}
                if not names:
                    break
                pattern = re.compile(r"\b(" + "|".join(map(re.escape, sorted(names))) + r")\s*\(")
                known = {(w.rel, w.fn.start_byte) for w in self._writers}
                added = False
                for rel, nodes in every.items():
                    src = self.files[rel].src
                    if not pattern.search(src.file.text):
                        continue
                    for n in nodes:
                        if (rel, n.start_byte) in known or not pattern.search(src.text(n)):
                            continue
                        req = _request_names(src, n)[0]
                        if req and any(
                            c.type == "call_expression"
                            and callee_name(src, c) in names
                            and any(src.text(unwrap(x) or x) == req for x in args(c))
                            for c in walk(n)
                        ):
                            self._writers.append(Writer(rel, n, *_function_name(src, n)))
                            known.add((rel, n.start_byte))
                            added = True
                if not added:
                    break
        return self._writers

    # -- indexing
    def _resolve_module(self, rel: str, spec: str | None) -> str | None:
        if not spec or not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        stem = (
            posixpath.splitext(base)[0] if posixpath.splitext(base)[1] in (".js", ".ts") else base
        )
        suffixes = (".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
        for candidate in (
            base,
            *(stem + s for s in suffixes),
            *(f"{base}/index{s}" for s in suffixes),
        ):
            if candidate in self.files:
                return candidate
        return None

    def _index(self, f: _File) -> None:
        src, rel = f.src, f.src.file.rel
        for n in walk(src.root):
            t = n.type
            if t == "import_statement":
                where = self._resolve_module(
                    rel, string_value(src, n.child_by_field_name("source"))
                )
                if where is None:
                    continue
                for c in walk(n):
                    if c.type == "import_clause":
                        default = next(
                            (x for x in c.named_children if x.type == "identifier"), None
                        )
                        if default is not None:
                            f.imports[src.text(default)] = (where, "default")
                    elif c.type == "namespace_import":
                        ident = next((x for x in c.named_children if x.type == "identifier"), None)
                        if ident is not None:
                            f.namespaces[src.text(ident)] = where
                    elif c.type == "import_specifier":
                        name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
                        f.imports[src.text(alias or name)] = (where, src.text(name))
            elif t == "variable_declarator":
                self._declarator(f, n)
            elif t in ("function_declaration", "generator_function_declaration"):
                name = n.child_by_field_name("name")
                if name is not None:
                    f.functions.setdefault(src.text(name), []).append(n)
                    if n.parent is not None and n.parent.type == "export_statement":
                        default = any(c.type == "default" for c in n.parent.children)
                        f.exports["default" if default else src.text(name)] = src.text(name)
            elif t in ("class_declaration", "class") and (name := n.child_by_field_name("name")):
                f.classes[src.text(name)] = n
                self._class_fields(src, src.text(name), n)
                if n.parent is not None and n.parent.type == "export_statement":
                    default = any(c.type == "default" for c in n.parent.children)
                    f.exports["default" if default else src.text(name)] = src.text(name)
            elif t in ("interface_declaration", "type_alias_declaration"):
                name = n.child_by_field_name("name")
                if name is not None:
                    self._type_fields(src, src.text(name), n)
            elif t == "export_statement":
                self._export(f, n)
            elif t == "assignment_expression":
                self._commonjs_export(f, n)
                left = unwrap(n.child_by_field_name("left"))
                target = chain_text(src, left)
                if target and not target.startswith(("exports.", "module.exports")):
                    f.rebound.add(target.split(".", 1)[0])  # `show = …`, `ctrl.show = …`
            elif (
                t == "call_expression"
                and _WRITES_FIRST.match(chain_text(src, n.child_by_field_name("function")))
                and args(n)
            ):
                target = chain_text(src, args(n)[0])  # `Object.assign(Ctrl.prototype, { … })`
                if target and not target.startswith(("exports", "module.exports")):
                    f.rebound.add(target.split(".", 1)[0])
                first = unwrap(args(n)[0])
                if first is not None and first.type == "new_expression":
                    self.linked.add(src.text(first.child_by_field_name("constructor")))
            elif (
                t == "member_expression"
                and src.text(n.child_by_field_name("property")) == "prototype"
            ):
                f.rebound.add(chain_text(src, n.child_by_field_name("object")).split(".", 1)[0])
            elif t == "call_expression":
                self._sequelize_init(src, n)
                self._associations(src, n)

    def _declarator(self, f: _File, n: Node) -> None:
        src = f.src
        name, value = n.child_by_field_name("name"), unwrap(n.child_by_field_name("value"))
        if name is None or value is None:
            return
        exported = (
            n.parent is not None
            and n.parent.parent is not None
            and (n.parent.parent.type == "export_statement")
        )
        if name.type == "object_pattern" and value.type == "call_expression":
            if callee_name(src, value) == "require":
                where = self._resolve_module(
                    src.file.rel, string_value(src, (args(value) or [None])[0])
                )
                if where is not None:
                    for c in name.named_children:
                        if c.type == "shorthand_property_identifier_pattern":
                            f.imports[src.text(c)] = (where, src.text(c))
                        elif c.type == "pair_pattern":
                            key, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                            if val is not None and val.type == "identifier":
                                f.imports[src.text(val)] = (where, src.text(key))
            return
        if name.type != "identifier":
            return
        local = src.text(name)
        if exported:
            f.exports[local] = local
        if value.type in _FUNCTION_VALUES:
            f.functions.setdefault(local, []).append(value)
        elif value.type == "object":
            f.objects[local] = self._object_functions(src, value)
        elif value.type in ("class", "class_expression"):
            f.classes[local] = value
        elif value.type == "new_expression":
            ctor = src.text(value.child_by_field_name("constructor"))
            f.instances[local] = ctor
            if ctor.rsplit(".", 1)[-1] == "Map":
                typed = value.child_by_field_name("type_arguments")
                kinds = [src.text(c) for c in typed.named_children] if typed is not None else []
                f.models[local] = kinds[-1] if len(kinds) == 2 and kinds[-1] != "any" else None
        elif value.type == "call_expression":
            callee = src.text(value.child_by_field_name("function"))
            a = args(value)
            if callee == "require":
                where = self._resolve_module(src.file.rel, string_value(src, (a or [None])[0]))
                if where is not None:
                    f.imports[local] = (where, "default")
            elif (record := self._model_call(f, value)) is not False:
                f.models[local] = record  # type: ignore[assignment]
            elif (
                len(a) == 1
                and (wrapped := unwrap(a[0])) is not None
                and (wrapped.type in _FUNCTION_VALUES)
            ):
                # `const getOrder = asyncHandler(async (req, res) => …)`: the wrapped function
                f.functions.setdefault(local, []).append(wrapped)

    def _object_functions(self, src: Parsed, obj: Node) -> dict[str, Node | None]:
        """An object literal's functions; None for any name a spread may supply."""
        out: dict[str, Node | None] = {}
        for p in obj.named_children:
            if p.type == "pair":
                value = unwrap(p.child_by_field_name("value"))
                key = src.text(p.child_by_field_name("key"))
                if value is not None and value.type in _FUNCTION_VALUES:
                    out[key] = value
            elif p.type == "method_definition" and (name := p.child_by_field_name("name")):
                out[src.text(name)] = p
            elif (
                p.type == "pair"
                and (value := unwrap(p.child_by_field_name("value"))) is not None
                and (value.type == "identifier")
            ):
                out[src.text(p.child_by_field_name("key"))] = value  # resolved where it's called
            elif p.type == "shorthand_property_identifier":
                out[src.text(p)] = p  # `export default { wrap }`
            elif p.type == "spread_element":
                out = dict.fromkeys(out)  # `{ show, ...legacy }`: `legacy.show` may win
                out["..."] = None
        return out

    def _model_call(self, f: _File, call: Node) -> str | bool | None:
        """The record `mongoose.model("Item", schema)`, `sequelize.define("Item", {…})` or
        `getRepository(Item)` is a model of (None when unknown); False when it is no model."""
        src = f.src
        name = callee_name(src, call)
        a = args(call)
        if name == "model" and a and (record := string_value(src, a[0])):
            self.mongoose.add(record)
            if len(a) > 1:
                self._schema_fields(f, a[1], record)
            return record
        if name == "define" and len(a) >= 2 and (record := string_value(src, a[0])):
            self._record(src, record, unwrap(a[1]))
            return record
        if name == "getRepository" and a:
            return src.text(a[0])
        return False

    def _associations(self, src: Parsed, call: Node) -> None:
        """`Task.belongsTo(User)`: an association adds a key to one side, so both are linked."""
        fn = unwrap(call.child_by_field_name("function"))
        if (
            fn is not None
            and fn.type == "member_expression"
            and src.text(fn.child_by_field_name("property"))
            in ("belongsTo", "hasOne", "hasMany", "belongsToMany")
        ):
            self.linked.add(src.text(fn.child_by_field_name("object")))
            self.linked.update(src.text(x) for x in args(call)[:1])

    def _sequelize_init(self, src: Parsed, call: Node) -> None:
        """`Item.init({ … }, { sequelize })`: a Sequelize model class's fields."""
        fn = unwrap(call.child_by_field_name("function"))
        a = [unwrap(x) for x in args(call)]
        if (
            fn is not None
            and fn.type == "member_expression"
            and src.text(fn.child_by_field_name("property")) == "init"
            and len(a) == 2
            and all(x is not None and x.type == "object" for x in a)
            and any(
                (c.type == "shorthand_property_identifier" and src.text(c) == "sequelize")
                or (c.type == "pair" and src.text(c.child_by_field_name("key")) == "sequelize")
                for c in a[1].named_children  # type: ignore[union-attr]
            )
        ):
            self._record(src, src.text(fn.child_by_field_name("object")), a[0])

    def _schema_fields(self, f: _File, node: Node | None, record: str) -> None:
        """A Mongoose schema's fields: `new Schema({ … })`, or a name bound to one."""
        src, seen = f.src, set()
        node = unwrap(node)
        while node is not None and node.type == "identifier" and src.text(node) not in seen:
            name = src.text(node)
            seen.add(name)
            if any(
                n.type == "call_expression"
                and chain_text(src, n.child_by_field_name("function"))
                in (f"{name}.add", f"{name}.plugin", f"{name}.loadClass")
                for n in walk(src.root)
            ):
                self.linked.add(record)  # fields added later
            node = next(
                (
                    unwrap(d.child_by_field_name("value"))
                    for d in walk(src.root)
                    if d.type == "variable_declarator"
                    and src.text(d.child_by_field_name("name")) == name
                ),
                None,
            )
        if node is not None and node.type == "new_expression" and args(node):
            self._record(src, record, unwrap(args(node)[0]))
        else:
            self.linked.add(record)

    def _record(
        self, src: Parsed, record: str, obj: Node | None, prefix: str = "", depth: int = 0
    ) -> None:
        """A model's fields from its definition object; a spread, a computed key or a reference
        to another model (`{ type: ObjectId, ref: "User" }`) links it."""
        fields = self.fields_by_record.setdefault(record, [])
        if obj is None or obj.type != "object" or depth > 16:
            self.linked.add(record)
            return
        for p in obj.named_children:
            if p.type == "shorthand_property_identifier":
                fields.append(prefix + src.text(p))
                if prefix and OWNER_FIELD_RX.match(src.text(p)):
                    self.linked.add(record)
            elif p.type == "pair" and p.child_by_field_name("key").type != "computed_property_name":
                key = src.text(p.child_by_field_name("key")).strip("'\"")
                fields.append(prefix + key)
                if prefix and OWNER_FIELD_RX.match(key):
                    self.linked.add(record)  # `meta: { owner }`: owned through a nested path
                value = unwrap(p.child_by_field_name("value"))
                text = src.text(value) if value is not None else ""
                if re.search(r"\bref\s*:|ObjectId|references\s*:", text):
                    self.linked.add(record)  # a reference to another model
                    if target := re.search(r"\bref\s*:\s*[\"'](\w+)[\"']", text):
                        self.refs[(record, prefix + key)] = target.group(1)
                elif (
                    value is not None
                    and value.type == "object"
                    and not any(
                        c.type == "pair" and src.text(c.child_by_field_name("key")) == "type"
                        for c in value.named_children
                    )
                ):
                    self._record(src, record, value, f"{prefix}{key}.", depth + 1)
            elif p.type != "comment":
                self.linked.add(record)

    def _class_fields(self, src: Parsed, name: str, cls: Node) -> None:
        body = cls.child_by_field_name("body")
        members = body.named_children if body is not None else []
        fields = (
            [
                src.text(m.child_by_field_name("name") or m.child_by_field_name("property"))
                for m in members
                if m.type in ("public_field_definition", "field_definition")
            ]
            + [  # `constructor(public ownerId: string)`
                src.text(q.child_by_field_name("pattern"))
                for m in members
                if m.type == "method_definition"
                and src.text(m.child_by_field_name("name")) == "constructor"
                for q in (m.child_by_field_name("parameters") or m).named_children
                if q.type in ("required_parameter", "optional_parameter")
                and any(c.type in ("accessibility_modifier", "readonly") for c in q.children)
            ]
            + [  # `constructor(owner) { this.owner = owner }`
                src.text(a.child_by_field_name("left").child_by_field_name("property"))
                for m in members
                if m.type == "method_definition"
                and src.text(m.child_by_field_name("name")) == "constructor"
                for a in walk(m)
                if a.type == "assignment_expression"
                and a.child_by_field_name("left").type == "member_expression"
                and unwrap(a.child_by_field_name("left").child_by_field_name("object")).type
                == "this"
            ]
        )
        if fields:
            dynamic = any(
                m.type == "method_definition"
                and src.text(m.child_by_field_name("name")) == "constructor"
                for m in members
            ) or any(
                a.type == "assignment_expression"
                and src.text(a.child_by_field_name("left")).startswith("this.")
                for a in walk(cls)
            )
            if dynamic or any(c.type == "class_heritage" for c in cls.named_children):
                self.linked.add(name)  # inherited fields, or fields set at run time
            self.fields_by_record.setdefault(name, []).extend(f for f in fields if f)
            self.holds.setdefault(name, set()).update(
                {
                    src.text(t)
                    for m in body.named_children
                    for t in walk(m)
                    if t.type == "type_identifier"
                }
            )

    def _type_fields(self, src: Parsed, name: str, node: Node) -> None:
        props = [n for n in walk(node) if n.type == "property_signature"]
        value = node.child_by_field_name("value")
        if any(c.type == "extends_type_clause" for c in node.named_children) or (
            value is not None and value.type != "object_type"
        ):
            self.linked.add(name)  # `interface Doc extends Owned`, `Owned & { … }`
        if props:
            self.fields_by_record.setdefault(name, []).extend(
                src.text(p.child_by_field_name("name")) for p in props
            )
            self.holds.setdefault(name, set()).update(
                {src.text(t) for p in props for t in walk(p) if t.type == "type_identifier"}
            )

    def _prisma(self, text: str) -> None:
        for name, body in re.findall(r"(?ms)^model\s+(\w+)\s*\{(.*?)^\}", text):
            fields = re.findall(r"(?m)^\s*(\w+)\s+(\w+)", body)
            self.fields_by_record.setdefault(name, []).extend(f for f, _ in fields)
            self.holds.setdefault(name, set()).update(kind for _, kind in fields)

    def _export(self, f: _File, n: Node) -> None:
        src = f.src
        if any(c.type == "default" for c in n.children):
            value = unwrap(n.child_by_field_name("value"))
            if value is not None and value.type == "identifier":
                f.exports["default"] = src.text(value)
            elif value is not None and value.type == "new_expression":
                f.instances["<default>"] = src.text(value.child_by_field_name("constructor"))
                f.exports["default"] = "<default>"
            elif value is not None and value.type == "object":
                f.objects["<default>"] = self._object_functions(src, value)
                f.exports["default"] = "<default>"
            elif value is not None and value.type in _FUNCTION_VALUES:
                f.functions.setdefault("<default>", []).append(value)
                f.exports["default"] = "<default>"
            elif value is not None and value.type == "call_expression":
                record = self._model_call(f, value)
                if record is not False:
                    f.models["<default>"] = record  # type: ignore[assignment]
                    f.exports["default"] = "<default>"
        for c in walk(n):
            if c.type == "export_specifier":
                name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
                f.exports[src.text(alias or name)] = src.text(name)

    def _commonjs_export(self, f: _File, n: Node) -> None:
        src = f.src
        left, right = n.child_by_field_name("left"), unwrap(n.child_by_field_name("right"))
        target = src.text(left)
        if right is None:
            return
        if target == "module.exports":
            if right.type == "identifier":
                f.exports["default"] = src.text(right)
            elif right.type in _FUNCTION_VALUES:
                f.functions.setdefault("<default>", []).append(right)
                f.exports["default"] = "<default>"
            elif right.type == "object":
                f.objects["<default>"] = self._object_functions(src, right)
                f.exports["default"] = "<default>"
                for p in right.named_children:
                    if p.type == "shorthand_property_identifier":
                        f.exports[src.text(p)] = src.text(p)
                    elif p.type == "pair" and unwrap(p.child_by_field_name("value")) is not None:
                        value = unwrap(p.child_by_field_name("value"))
                        if value.type == "identifier":
                            f.exports[src.text(p.child_by_field_name("key"))] = src.text(value)
            elif right.type == "new_expression":
                f.instances["<default>"] = src.text(right.child_by_field_name("constructor"))
                f.exports["default"] = "<default>"
            elif (
                right.type == "call_expression"
                and (record := self._model_call(f, right)) is not False
            ):
                f.models["<default>"] = record  # type: ignore[assignment]
                f.exports["default"] = "<default>"
        elif target.startswith(("module.exports.", "exports.")):
            key = target.rsplit(".", 1)[-1]
            if right.type in _FUNCTION_VALUES:
                f.functions.setdefault(key, []).append(right)
                f.exports[key] = key
            elif right.type == "identifier":
                f.exports[key] = src.text(right)

    def _fields(self) -> dict[str, tuple[str, ...]]:
        """As for Java and Python: a record that may be owned through another (holding or held
        by another record, pointed at by `<name>Id`) is left out unless it names an owner."""
        records = set(self.fields_by_record)
        held_by_others = {k for n, ts in self.holds.items() for k in ts if k != n and k in records}
        pointed = {
            re.sub(r"_?id$", "", f, flags=re.I).replace("_", "").lower()
            for fs in self.fields_by_record.values()
            for f in fs
            if re.search(r"_id$|(?<=[a-z])Id$", f)
        }
        out = {}
        for name, fs in self.fields_by_record.items():
            linked = (
                not fs
                or name in self.linked
                or bool(self.holds.get(name, set()) & (records - {name}))
                or name in held_by_others
                or name.lower() in pointed
            )
            if any(OWNER_FIELD_RX.match(x) for x in fs) or not linked:
                out[name] = tuple(dict.fromkeys(fs))
        return out

    # -- resolution
    def _local(
        self, rel: str, name: str, seen: frozenset[str] = frozenset()
    ) -> tuple[str, str] | None:
        """The file and local name a name refers to from `rel`, through imports and exports."""
        f = self.files.get(rel)
        if f is None or f"{rel}:{name}" in seen:
            return None
        if (
            name in f.functions
            or name in f.objects
            or name in f.classes
            or name in f.instances
            or name in f.models
        ):
            return rel, name
        if name in f.imports:
            where, exported = f.imports[name]
            target = self.files.get(where)
            if target is None:
                return None
            local = target.exports.get(exported, exported if exported != "default" else "")
            return self._local(where, local, seen | {f"{rel}:{name}"}) if local else None
        return None

    def model(self, rel: str, node: Node | None) -> _Model | None:
        """The model, delegate, repository or store an expression is (`Item`, `prisma.item`,
        `db.Item`, `comments` a `Map`)."""
        node = unwrap(node)
        if node is None:
            return None
        src = self.files[rel].src
        if node.type == "identifier":
            found = self._local(rel, src.text(node))
            if found is None:
                return None
            f = self.files[found[0]]
            if found[1] in f.models:
                record = f.models[found[1]]
                sync = f.instances.get(found[1], "").rsplit(".", 1)[-1] == "Map"
                return _Model(record, record or f"{found[0]}:{found[1]}", sync)
            if found[1] in f.classes and found[1] in self.fields_by_record:
                return _Model(found[1], found[1])  # `class Item extends Model` (Sequelize)
            return None
        if node.type == "member_expression":
            obj = chain_text(src, node.child_by_field_name("object"))
            prop = src.text(node.child_by_field_name("property"))
            # `prisma.item`, `db.Item`, `models.Item`
            matches = [r for r in self.fields_by_record if r.lower() == prop.lower()]
            if obj.rsplit(".", 1)[-1] in ("prisma", "db", "models", "client", "orm") and matches:
                return _Model(matches[0], matches[0])
            if obj.rsplit(".", 1)[-1] == "prisma":
                return _Model(None, f"prisma:{prop.lower()}")
            if (
                node.child_by_field_name("object") is not None
                and unwrap(node.child_by_field_name("object")).type == "call_expression"
            ):
                inner = unwrap(node.child_by_field_name("object"))
                if callee_name(src, inner) == "model" and (
                    record := string_value(src, (args(inner) or [None])[0])
                ):
                    return _Model(record, record)  # `mongoose.model("Item").findById(…)`
        if node.type == "call_expression" and callee_name(src, node) == "model":
            record = string_value(src, (args(node) or [None])[0])
            return _Model(record, record) if record else None
        return None

    def functions(
        self,
        rel: str,
        node: Node | None,
        cls: Node | None,
        instance: tuple[str, Node] | None = None,
    ) -> list[Target] | None:
        """The checkout functions an expression names: [] when none, None when ambiguous."""
        node = unwrap(node)
        if node is None:
            return []
        src = self.files[rel].src
        if node.type == "identifier":
            return self._named(rel, src.text(node))
        if node.type != "member_expression":
            return []
        obj = unwrap(node.child_by_field_name("object"))
        prop = src.text(node.child_by_field_name("property"))
        if obj is None:
            return []
        if obj.type == "this" and instance is not None:
            return self._methods(instance[0], instance[1], prop, instance)
        if obj.type == "this" and cls is not None:
            # an instance of a subclass may run its override
            return None if self._overridden(rel, cls, prop) else self._methods(rel, cls, prop)
        if obj.type == "call_expression" and callee_name(src, obj) == "require":
            # `require("./get-order").default`
            module = self._resolve_module(rel, string_value(src, (args(obj) or [None])[0]))
            exported = self.files[module].exports.get(prop) if module is not None else None
            return self._named(module, exported) if module is not None and exported else []
        if obj.type != "identifier":
            return []
        name = src.text(obj)
        f = self.files[rel]
        found = self._local(rel, name)
        module = f.namespaces.get(name)
        if found is None and name in f.imports and f.imports[name][1] == "default":
            module = f.imports[name][0]  # `const c = require("./c")` with `exports.handler = …`
        exported_object = self.files[found[0]].objects.get(found[1]) if found else None
        if found is None or (
            found[1] == "<default>" and exported_object is not None and prop not in exported_object
        ):
            # `module.exports = { show }`, `show` defined beside it
            module = found[0] if found is not None else module
            exported = self.files[module].exports.get(prop) if module is not None else None
            return self._named(module, exported) if module is not None and exported else []
        where, local = found
        g = self.files[where]
        if local in g.rebound:
            return None
        if local in g.objects:
            functions = g.objects[local]
            if "..." in functions and functions.get(prop) is None:
                return None
            fn = functions.get(prop)
            if fn is not None and fn.type in ("identifier", "shorthand_property_identifier"):
                return self._named(where, g.src.text(fn))  # `{ wrap: awaitMiddleware }`, `{ wrap }`
            return [Target(where, fn)] if fn is not None else []
        if local in g.instances:
            cls_found = self._class(where, g.instances[local])
            return self._methods(cls_found[0], cls_found[1], prop, cls_found) if cls_found else []
        if local in g.classes:
            return self._methods(where, g.classes[local], prop)
        return []

    def _named(self, rel: str, name: str) -> list[Target] | None:
        found = self._local(rel, name)
        if found is None:
            return []
        fns = self.files[found[0]].functions.get(found[1], [])
        if len(fns) > 1 or (fns and found[1] in self.files[found[0]].rebound):
            return None
        return [Target(found[0], fns[0])] if fns else []

    def _overridden(self, rel: str, cls: Node, name: str) -> bool:
        """Whether a subclass of `cls` (at any depth) defines method `name`."""
        pending, seen = [(rel, cls)], set()
        while pending:
            base_rel, base = pending.pop()
            if (base_rel, base.start_byte) in seen:
                continue
            seen.add((base_rel, base.start_byte))
            for where, f in self.files.items():
                for sub in f.classes.values():
                    heritage = next(
                        (c for c in sub.named_children if c.type == "class_heritage"), None
                    )
                    ident = (
                        next((c for c in walk(heritage) if c.type == "identifier"), None)
                        if heritage
                        else None
                    )
                    parent = self._class(where, f.src.text(ident)) if ident is not None else None
                    if (
                        parent is None
                        or parent[0] != base_rel
                        or parent[1].start_byte != base.start_byte
                    ):
                        continue
                    body = sub.child_by_field_name("body")
                    if any(
                        _defines(f.src, m, name)
                        for m in (body.named_children if body is not None else [])
                    ):
                        return True
                    pending.append((where, sub))
        return False

    def _class(self, rel: str, ctor: str) -> tuple[str, Node] | None:
        found = self._local(rel, ctor)
        if found is None:
            return None
        cls = self.files[found[0]].classes.get(found[1])
        return (found[0], cls) if cls is not None else None

    def _methods(
        self, rel: str, cls: Node, name: str, instance: tuple[str, Node] | None = None
    ) -> list[Target] | None:
        src = self.files[rel].src
        seen: set[int] = set()
        current: Node | None = cls
        where = rel
        while current is not None and current.start_byte not in seen:
            seen.add(current.start_byte)
            body = current.child_by_field_name("body")
            found = [
                m
                for m in (body.named_children if body is not None else [])
                if _defines(src, m, name)
            ]
            label = current.child_by_field_name("name")
            if len(found) > 1 or (
                label is not None and src.text(label) in self.files[where].rebound
            ):
                return None  # two definitions, or `Ctrl.prototype.m = …`
            if found:
                return [Target(where, found[0], current, instance)]
            heritage = next((c for c in current.named_children if c.type == "class_heritage"), None)
            base = (
                next((c for c in walk(heritage) if c.type == "identifier"), None)
                if heritage
                else None
            )
            nxt = self._class(where, src.text(base)) if base is not None else None
            if nxt is None:
                return []
            where, current = nxt
            src = self.files[where].src
        return []


# ---- one function body


@dataclass
class _Scan:
    facts: HandlerFacts
    verified: set[_Key] = field(default_factory=set)
    owned_or_null: set[_Key] = field(default_factory=set)
    covers: tuple[set[_Key] | None, ...] = ()
    reads: tuple[bool, ...] = ()
    handoff_cover: set[_Key] | None = None
    asynchronous: tuple[bool, ...] = ()
    seen: frozenset[str] = frozenset()  # the ids read ("*": can't tell which)
    pure_read: bool = False


class _Walk:
    """One function: its lookups by id, hand-offs, and the ids each allow-listed statement in its
    body verifies from its end on. `ids`: parameters (or `req.params.<p>` for a handler) that are
    path ids; `callers`: caller roots (`req.user`, or parameters handed the caller)."""

    def __init__(
        self,
        o: ExpressOwnership,
        target: Target,
        ids: set[str],
        path_ids: set[str],
        callers: set[str],
        depth: int,
        handler: tuple[bool, bool],
    ) -> None:
        self.instance = target.instance
        self.o, self.code, self.rel, self.fn, self.cls = (
            o,
            o.code,
            target.rel,
            target.fn,
            target.cls,
        )
        self.src = self.code.files[self.rel].src
        self.depth = depth
        patterns = param_patterns(self.fn)
        self.params = {n for p in patterns for n in bound_names(self.src, p)}
        # `handler`: whether the first parameter is the request (and the second the response)
        self.req = self.src.text(patterns[0]) if handler[0] and patterns else ""
        self.res = self.src.text(patterns[1]) if handler[1] and len(patterns) > 1 else ""
        self.path_ids = path_ids if self.req else set()
        self.root: dict[str, str] = {i: i for i in ids}
        self.callers = set(callers)
        self._bind()
        self.lookups: list[Lookup] = []
        self.cover: list[set[_Key] | None] = []
        self.asynchronous: list[bool] = []  # lookups whose result must be awaited
        self.starts: list[_Pos] = []
        self.reads: list[bool] = []
        self.made: dict[int, list[int]] = {}
        self.consumed: set[int] = set()
        self.raising: set[int] = set()  # lookups whose chain refuses a missing record (`orFail`)
        self.hop_verified: dict[int, set[_Key]] = {}
        self.hop_owned: dict[int, set[_Key]] = {}
        self.hop_async: set[int] = set()  # hops into an async function
        self.handoffs: list[tuple[CodeSpan, set[str] | None, _Pos]] = []
        self.hop: CodeSpan | None = None
        self.caller = next(
            (
                self.span(n)
                for n in own(self.fn)
                if n.type == "member_expression" and self.is_caller(n)
            ),
            next(
                (
                    self.span(n)
                    for n in own(self.fn)
                    if n.type == "identifier" and self.src.text(n) in self.callers
                ),
                None,
            ),
        )
        self.verified: dict[_Key, _Pos] = {}
        self.owned_or_null: dict[_Key, _Pos] = {}
        self.swallows = False  # a closing `try` whose `catch` doesn't rethrow
        self.leaky_try: list[tuple[_Pos, _Pos]] = []  # a `try` whose `var` records `catch` can send

        self.uncovered: list[tuple[_Pos, _Pos]] = []  # a closing `try`'s `catch` and `finally`

    # -- the id and the caller
    def span(self, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.rel), line=self.src.line(node))

    def path_id(self, node: Node | None) -> str | None:
        """`req.params.id` (or `req.params["id"]`) for a path id `id`."""
        text = chain_text(self.src, node)
        if self.req and text.startswith(f"{self.req}.params."):
            name = text.removeprefix(f"{self.req}.params.")
            return name if name in self.path_ids else None
        return None

    def mentions(self, node: Node | None) -> bool:
        """Whether a value carries a path id: an id name, `req.params.<id>`, or `req.params`."""
        if node is None:
            return False
        for n in walk(node):
            if n.type == "identifier" and self.src.text(n) in self.root:
                return True
            if n.type == "shorthand_property_identifier" and self.src.text(n) in self.root:
                return True
            if n.type == "member_expression" and (
                self.path_id(n) is not None
                or (self.req and chain_text(self.src, n) == f"{self.req}.params")
            ):
                return True
        return False

    def exact(self, node: Node | None) -> str | None:
        """The path id a value is exactly: the id, `req.params.id`, or a conversion of it."""
        node = unwrap(node)
        if node is None:
            return None
        if node.type in ("identifier", "shorthand_property_identifier"):
            return self.root.get(self.src.text(node))
        if (pid := self.path_id(node)) is not None:
            return pid
        for _ in range(_MAX_DEPTH):
            node = converted(self.src, node)
            if node is None:
                return None
            node = unwrap(node)
            if node is None:
                return None
            if node.type in ("identifier", "shorthand_property_identifier"):
                return self.root.get(self.src.text(node))
            if (pid := self.path_id(node)) is not None:
                return pid
        return None

    def exact_ids(self, values: list[Node], store: str = "*", key: str = "*") -> set[_Key] | None:
        roots = [self.exact(v) for v in values if self.mentions(v)]
        return None if not roots or None in roots else {(r, store, key) for r in roots if r}

    def is_caller(self, node: Node | None) -> bool:
        """`req.user`, `req.auth`, `res.locals.user`, or a caller name."""
        node = unwrap(node)
        if node is None:
            return False
        if node.type in ("identifier", "shorthand_property_identifier"):
            return self.src.text(node) in self.callers
        text = chain_text(self.src, node)
        return bool(text) and text in self.caller_paths

    def derived(self, node: Node | None, depth: int = 0) -> bool:
        """`req.user.sub`, `String(me.id)`, `me._id.toString()`: built only from the caller and
        literals (never a fallback, a conditional or another input)."""
        node = unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return False
        if self.is_caller(node):
            return True
        t = node.type
        if t in ("member_expression", "subscript_expression"):
            if t == "subscript_expression":
                index = unwrap(node.child_by_field_name("index"))
                if index is None or index.type not in ("string", "number"):
                    return False
                field = self.src.text(index).strip("'\"`")
            else:
                field = self.src.text(node.child_by_field_name("property"))
            if not _SELF_FIELD.match(field):
                return False
            return self.derived(node.child_by_field_name("object"), depth + 1)
        if (inner := converted(self.src, node)) is not None:
            return self.derived(inner, depth + 1)
        if t == "template_string":
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            return bool(subs) and all(
                self.derived(next(iter(s.named_children), None), depth + 1) for s in subs
            )
        return False

    def _bind(self) -> None:
        """The id names (`const { id } = req.params`), the caller locals (`const me =
        req.user.id`), and what is rebound or written, which is neither."""
        src = self.src
        self.caller_paths = set()
        if self.o.guarded and self.req:
            self.caller_paths = {f"{self.req}.user", f"{self.req}.auth"}
            if self.res:
                self.caller_paths.add(f"{self.res}.locals.user")
        bindings: dict[str, int] = dict.fromkeys(self.params, 1)
        values: dict[str, list[Node | None]] = {}
        written: set[str] = set()
        aliases: dict[str, str] = {}  # `const u = req.user`: a local naming the request's state
        body = self.fn.child_by_field_name("body")
        for n in walk(body) if body is not None else []:
            if n.type == "variable_declarator":
                pattern, value = n.child_by_field_name("name"), n.child_by_field_name("value")
                if pattern is None:
                    continue
                for name in bound_names(src, pattern):
                    bindings[name] = bindings.get(name, 0) + 1
                    values.setdefault(name, []).append(n if own_scope(self.fn, n) else None)
                chain = chain_text(src, value)
                if pattern.type == "identifier" and chain.split(".", 1)[0] in (self.req, self.res):
                    aliases[src.text(pattern)] = chain
            elif n.type in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier":
                    bindings[src.text(left)] = bindings.get(src.text(left), 0) + 1
                    values.setdefault(src.text(left), []).append(None)
                elif left is not None and left.type in ("object_pattern", "array_pattern"):
                    for m in walk(left):  # `({ user: req.user } = req.body)`
                        if m.type in ("member_expression", "subscript_expression"):
                            written.add(written_path(src, m))
                        elif m.type in ("identifier", "shorthand_property_identifier_pattern"):
                            bindings[src.text(m)] = bindings.get(src.text(m), 0) + 1
                            values.setdefault(src.text(m), []).append(None)
                elif left is not None:
                    written.add(written_path(src, left))  # `req.user.id = …`, `req.user[k] = …`
            elif n.type == "update_expression":
                written.add(written_path(src, n.child_by_field_name("argument")))
            elif n.type == "call_expression":
                fn = unwrap(n.child_by_field_name("function"))
                if fn is not None and fn.type == "member_expression":
                    prop = src.text(fn.child_by_field_name("property"))
                    target = written_path(src, fn.child_by_field_name("object"))
                    # `res.setHeader(…)` writes the response, not what it holds (`res.locals`)
                    if _MUTATORS.match(prop) and target not in (self.req, self.res):
                        written.add(target)
                if _WRITES_FIRST.match(chain_text(src, fn)) and args(n):
                    written.add(written_path(src, args(n)[0]))
            elif n.type in ("for_in_statement",):
                for name in bound_names(src, n.child_by_field_name("left")):
                    bindings[name] = bindings.get(name, 0) + 2  # rebound on every pass
            elif n.type in _FUNCTION_VALUES or n.type in (
                "function_declaration",
                "method_definition",
            ):
                if n != self.fn:
                    for name in {x for q in param_patterns(n) for x in bound_names(src, q)}:
                        bindings[name] = bindings.get(name, 0) + 2  # shadowed in a closure
        for w in list(written):
            head, _, rest = w.partition(".")
            if head in aliases:
                written.add(f"{aliases[head]}.{rest}" if rest else aliases[head])
        written.discard("")
        # a caller path written in the handler (`req.user = …`, `req.user.id = …`) isn't the caller
        self.caller_paths = {
            p
            for p in self.caller_paths
            if not any(w == p or w.startswith(p + ".") or p.startswith(w + ".") for w in written)
        }
        if caller_writes(src, self.fn, self.req, self.res) or any(
            caller_writes(
                self.code.files[t.rel].src, t.fn, *_request_names(self.code.files[t.rel].src, t.fn)
            )
            for n in (walk(body) if body is not None and self.req else [])
            if n.type == "call_expression"
            and any(src.text(unwrap(x) or x) == self.req for x in args(n))
            for t in self.code.functions(
                self.rel, n.child_by_field_name("function"), self.cls, self.instance
            )
            or []
        ):
            self.caller_paths = set()  # `const { user } = req; user.id = …`, a helper rewriting it
        aliases = {
            src.text(n.child_by_field_name("name"))
            for n in (walk(body) if body is not None else [])
            if n.type == "variable_declarator"
            and n.child_by_field_name("name").type == "identifier"
            and chain_text(src, n.child_by_field_name("value")) in self.caller_paths
        } | {
            src.text(c)
            for n in (walk(body) if body is not None else [])
            if n.type == "variable_declarator"
            and n.child_by_field_name("name").type == "object_pattern"
            and chain_text(src, n.child_by_field_name("value")) in {self.req, self.res}
            for c in n.child_by_field_name("name").named_children
            if c.type == "shorthand_property_identifier_pattern"
            and f"{chain_text(src, n.child_by_field_name('value'))}.{src.text(c)}"
            in self.caller_paths
        }
        if any(self.escapes(n, aliases) for n in (walk(body) if body is not None else [])):
            self.caller_paths = set()  # `touch(req.user)`, `{ me: req.user }`, `[me] = [req.user]`
        self.callers -= {n for n, c in bindings.items() if c > 1}
        self.callers -= {w.split(".", 1)[0] for w in written}
        # ids and caller locals, bound once
        for _ in range(3):
            for name, decls in values.items():
                if bindings.get(name, 0) != 1 or len(decls) != 1 or decls[0] is None:
                    continue
                decl = decls[0]
                pattern, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
                if pattern is None or value is None:
                    continue
                if pattern.type == "object_pattern":
                    base = chain_text(src, value)
                    for c in pattern.named_children:
                        key_node = (
                            c.child_by_field_name("left")
                            if c.type == "object_assignment_pattern"
                            else c.child_by_field_name("key") or c
                        )
                        # a static key: the property name, unquoted (`{ "id": ownerId }`);
                        # a computed key (`{ [k]: v }`) is no field name we can read
                        key = string_value(src, key_node) or (
                            "" if key_node.type == "computed_property_name" else src.text(key_node)
                        )
                        local = bound_names(src, c)[:1]
                        if not local or local[0] != name:
                            continue
                        if self.req and base == f"{self.req}.params" and key in self.path_ids:
                            self.root[name] = key
                        elif base and f"{base}.{key}" in self.caller_paths:
                            self.callers.add(name)
                        elif (
                            self.req
                            and base == self.req
                            and f"{self.req}.{key}" in self.caller_paths
                        ):
                            self.callers.add(name)  # `const { user } = req`
                        elif (
                            base
                            and self.derived(value)
                            and c.type in ("pair_pattern", "shorthand_property_identifier_pattern")
                            and _SELF_FIELD.match(key)
                        ):
                            self.callers.add(name)  # `const { id } = req.user`
                    continue
                if pattern.type != "identifier":
                    continue
                if self.mentions(value) and not self.loads(value):
                    self.root[name] = self.exact(value) or name
                elif name not in written and self.derived(value):
                    self.callers.add(name)
        moved = {n for n, c in bindings.items() if c > 1}
        for n in moved & set(self.root):
            self.root[n] = n
        self.unstable = moved & set(self.root)
        for n in written:
            if n in self.root:
                self.unstable.add(n)
        params = f"{self.req}.params"
        if self.req and any(w == params or w.startswith(params + ".") for w in written):
            self.unstable |= self.path_ids | set(self.root)  # `req.params.id = …`

    def escapes(self, node: Node, aliases: set[str]) -> bool:
        """`req.user` itself (not a member of it), or a local naming it, handed where it may be
        written: a call, an object or array, a closure's return."""
        if node.type == "member_expression":
            if chain_text(self.src, node) not in self.caller_paths:
                return False
        elif node.type != "identifier" or self.src.text(node) not in aliases:
            return False
        while node.parent is not None and (
            node.parent.type in _UNWRAP
            or (
                node.parent.type == "binary_expression"
                and self.src.text(node.parent.child_by_field_name("operator")) in ("||", "??", "&&")
            )
            or (
                node.parent.type == "ternary_expression"
                and node.parent.child_by_field_name("condition") != node
            )
        ):
            node = node.parent
        parent = node.parent
        if parent is None:
            return False
        if parent.type in ("member_expression", "subscript_expression") and (
            parent.child_by_field_name("object") == node
        ):
            return False  # `req.user.id`
        if parent.type in (
            "binary_expression",
            "unary_expression",
            "if_statement",
            "ternary_expression",
            "spread_element",
            "expression_statement",
        ):
            return False  # a test, or a copy (`{ ...req.user }`)
        if parent.type == "variable_declarator":
            return parent.child_by_field_name("name") == node or parent.child_by_field_name(
                "name"
            ).type not in ("identifier", "object_pattern")
        if parent.type == "arguments":
            call = parent.parent
            root = root_of(self.src, call.child_by_field_name("function")) if call else ""
            return not (
                root == self.res or _INERT_ROOTS.match(root) or root in ("String", "Number")
            )
        if parent.type == "return_statement":
            return not own_scope(self.fn, parent)  # `const me = () => req.user`
        if parent.type in _FUNCTION_VALUES:
            return True  # an arrow returning it
        return True

    def loads(self, value: Node) -> bool:
        """Whether a value is read from something by the id (a call or subscript), not the id."""
        return any(
            (
                n.type in ("call_expression", "new_expression")
                and converted(self.src, n) is None
                and any(self.mentions(a) for a in args(n))
            )
            or (n.type == "subscript_expression" and self.mentions(n.child_by_field_name("index")))
            for n in walk(value)
        )

    # -- recording
    def add(
        self,
        node: Node,
        lookup: Lookup,
        *,
        read: bool,
        cover: set[_Key] | None,
        asynchronous: bool = True,
    ) -> int:
        k = len(self.lookups)
        self.lookups.append(lookup)
        self.cover.append(cover)
        self.asynchronous.append(asynchronous)
        self.starts.append(self.at(node))
        self.reads.append(read)
        self.made.setdefault(self.key(node), []).append(k)
        return k

    def handoff(self, node: Node, cover: set[_Key] | None) -> None:
        self.handoffs.append((self.span(node), cover, self.at(node)))

    def at(self, node: Node) -> _Pos:
        """Where code can first run: a closure's from its definition on, a hoisted function's
        or a class's from the start."""
        scope, parent = None, node.parent
        while parent is not None and parent != self.fn:
            if parent.type in _SCOPES:
                scope = parent
            parent = parent.parent
        if scope is None:
            return node.start_byte
        if scope.type in _FUNCTION_VALUES or scope.type == "method_definition":
            return scope.start_byte
        return self.fn.start_byte

    def verify(self, keys: set[_Key], at: _Pos) -> None:
        for key in keys:
            if key[0] not in self.unstable:
                self.verified[key] = min(at, self.verified.get(key, at))

    @staticmethod
    def key(node: Node) -> int:
        return node.start_byte * 100000 + node.end_byte

    # -- the walk
    def run(self) -> _Scan:
        body_node = self.fn.child_by_field_name("body")
        shadowing = [
            n
            for n in (walk(body_node) if body_node is not None else [])
            if (
                n.type in _FUNCTION_VALUES
                or n.type in ("function_declaration", "method_definition")
            )
            and {self.req, self.res} - {""}
            & {x for q in param_patterns(n) for x in bound_names(self.src, q)}
        ]
        for n in shadowing:
            if ".params" in self.src.text(n) or any(
                m.type == "identifier" and self.src.text(m) in self.root for m in walk(n)
            ):
                self.handoff(n, None)  # `(req) => Post.findOne(…)` called with a request of its own
        calls = sorted(
            (
                n
                for n in (walk(body_node) if body_node is not None else [])
                if n.type in ("call_expression", "new_expression", "subscript_expression")
                and not any(s.start_byte <= n.start_byte < s.end_byte for s in shadowing)
            ),
            key=lambda n: (n.start_byte, -n.end_byte),
        )
        for n in calls:
            if n.type == "subscript_expression":
                self.subscript(n)
            elif n.type == "new_expression":
                self.creation(n)
            else:
                self.call(n)
        self.opaque()
        body = statements(self.fn)
        if body and body[-1].type == "try_statement":
            # `try { … } catch (err) { next(err) }` closing the body: its block runs in order, and
            # what `catch` or `finally` runs is never covered by a check inside it
            last = body[-1]
            for name in ("handler", "finalizer"):
                if (part := last.child_by_field_name(name)) is not None:
                    self.uncovered.append((part.start_byte, part.end_byte))
            handler = last.child_by_field_name("handler")
            caught = statements(handler) if handler is not None else []
            final = last.child_by_field_name("finalizer")
            self.swallows = (
                handler is not None and not (caught and caught[-1].type == "throw_statement")
            ) or (final is not None and any(n.type == "return_statement" for n in walk(final)))
            block = last.child_by_field_name("body")
            leaked = {
                x
                for d in (walk(block) if block is not None else [])
                if d.type == "variable_declaration"
                for v in d.named_children
                if v.type == "variable_declarator"
                for x in bound_names(self.src, v.child_by_field_name("name"))
            }
            if (
                block is not None
                and handler is not None
                and any(
                    n.type == "identifier" and self.src.text(n) in leaked for n in walk(handler)
                )
            ):
                self.leaky_try.append(
                    (block.start_byte, block.end_byte)
                )  # `var item` sent by `catch`
            body = body[:-1] + [
                s
                for s in (block.named_children if block is not None else [])
                if s.type not in ("comment", "empty_statement")
            ]
        following: list[list[Node]] = [[] for _ in body]
        after: list[Node] = []
        for k in range(len(body) - 1, -1, -1):
            following[k] = after
            if not self.caller_declaration(body[k]):
                after = [body[k], *after[:1]]
        for stmt, nxt in zip(body, following, strict=True):
            self.statement(stmt, nxt)
        returns = [
            s
            for s in body
            if s.type == "return_statement"
            or any(n.type == "return_statement" for n in self._own_of(s))
        ]
        expression_body = (self.fn.child_by_field_name("body") or self.fn).type != "statement_block"
        first = (
            returns[0].start_byte
            if returns
            else (body[0].start_byte if expression_body and body else None)
        )
        return self.result(first, self.pure_read(body))

    def opaque(self) -> None:
        """Hand-offs for what reaches the id where it isn't read: a closure that calls with it
        (`res.on("finish", () => Post.deleteOne(…))`), and the request used other than through
        `req.params.<id>` (`const { params } = req`, `const r = req`, `req.param("id")`)."""
        body = self.fn.child_by_field_name("body")
        for n in walk(body) if body is not None else []:  # closures' bindings too
            if (
                n.type == "variable_declarator"
                and (value := n.child_by_field_name("value")) is not None
                and self.mentions(value)
                and not self.loads(value)
                and not self.binds(n)
            ):
                self.handoff(n, None)  # `const [id] = [req.params.id]`: the id under another name
            elif (
                n.type == "assignment_expression"
                and self.mentions(n.child_by_field_name("right"))
                and not self.loads(n.child_by_field_name("right"))
            ):
                self.handoff(n, None)  # `ctx.id = req.params.id`, `id = req.params.id`
            elif n.type == "for_in_statement" and self.mentions(n.child_by_field_name("right")):
                self.handoff(n, None)  # `for (const id of [req.params.id])`
        if body is not None:
            for n in walk(body):
                text = chain_text(self.src, n) if n.type == "member_expression" else ""
                if (self.res and text == f"{self.res}.req") or (
                    n.type == "identifier" and self.src.text(n) == "arguments"
                ):
                    self.handoff(n, None)  # `res.req.params`, `arguments[0].params`
        if not self.req or body is None:
            return
        for n in walk(body):
            if n.type == "shorthand_property_identifier" and self.src.text(n) == self.req:
                call = n.parent.parent.parent if n.parent and n.parent.parent else None
                logged = (
                    call is not None
                    and call.type == "call_expression"
                    and bool(
                        _INERT_ROOTS.match(root_of(self.src, call.child_by_field_name("function")))
                    )
                )
                if not logged:
                    self.handoff(n, None)  # `show({ req })`
                continue
            if n.type != "identifier" or self.src.text(n) != self.req or self.declares(n):
                continue
            node = n
            while node.parent is not None and node.parent.type in _UNWRAP:
                node = node.parent
            parent = node.parent
            if parent is None or parent.type == "arguments":
                continue  # handed on: read where the call is
            if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
                prop = self.src.text(parent.child_by_field_name("property"))
                if prop not in _OPAQUE_REQUEST and (prop != "params" or self.named_param(parent)):
                    continue
            elif parent.type == "variable_declarator" and self.destructures(parent, "params"):
                continue
            self.handoff(n, None)

    def binds(self, decl: Node) -> bool:
        """A declaration `_bind` reads: one name, or `{ id } = req.params`."""
        pattern = decl.child_by_field_name("name")
        if pattern is not None and pattern.type == "identifier":
            return self.src.text(pattern) in self.root  # bound once, as the id
        value = chain_text(self.src, decl.child_by_field_name("value"))
        return bool(self.req) and value == f"{self.req}.params" and self.destructures(decl, None)

    def declares(self, node: Node) -> bool:
        parent = node.parent
        return parent is not None and parent.type in (
            "required_parameter",
            "optional_parameter",
            "formal_parameters",
        )

    def named_param(self, params: Node) -> bool:
        """`req.params.<name>`, `req.params["name"]`, or `const { id } = req.params`."""
        node = params
        while node.parent is not None and node.parent.type in _UNWRAP:
            node = node.parent
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
            return True
        if parent.type == "subscript_expression" and parent.child_by_field_name("object") == node:
            if chain_text(self.src, parent):
                return True
            # `ObjectId.isValid(req.params[name])`: only validated
            call = parent.parent.parent if parent.parent is not None else None
            return (
                parent.parent.type == "arguments"
                and call is not None
                and bool(_VALIDATOR_NAME.match(callee_name(self.src, call)))
            )
        return parent.type == "variable_declarator" and self.destructures(parent, None)

    def destructures(self, decl: Node, avoiding: str | None) -> bool:
        """A plain `{ a, b: c, d = 1 }` pattern, without the `avoiding` key."""
        pattern = decl.child_by_field_name("name")
        if pattern is None or pattern.type != "object_pattern":
            return False
        for c in pattern.named_children:
            if c.type == "shorthand_property_identifier_pattern":
                key = self.src.text(c)
            elif c.type == "pair_pattern" and c.child_by_field_name("value").type == "identifier":
                key = self.src.text(c.child_by_field_name("key"))
            elif c.type == "object_assignment_pattern":
                key = self.src.text(c.child_by_field_name("left"))
            elif c.type == "comment":
                continue
            else:
                return False
            if key == avoiding:
                return False
        return True

    def _own_of(self, node: Node) -> Iterator[Node]:
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            if n.type not in _SCOPES:
                stack.extend(n.named_children)

    def chain(self, call: Node) -> list[Node]:
        """`call` and the calls chained on its result (`.populate(…).orFail().exec()`)."""
        out, node = [call], call
        while True:
            parent = node.parent
            grand = (
                parent.parent if parent is not None and parent.type == "member_expression" else None
            )
            if not (
                grand is not None
                and grand.type == "call_expression"
                and grand.child_by_field_name("function") == parent
            ):
                return out
            out.append(grand)
            node = grand

    def filters(
        self, value: Node | None, *, mongoose: bool = False
    ) -> list[tuple[str, Node]] | None:
        """The (field, value) equalities a query narrows by (`{ _id: id, owner: me }`, or its
        `where`); None when any is something else (an operator, `$or`, a spread, a computed key)."""
        value = unwrap(value)
        if value is None or value.type != "object":
            return None
        where = next(
            (
                c.child_by_field_name("value")
                for c in value.named_children
                if c.type == "pair" and self.src.text(c.child_by_field_name("key")) == "where"
            ),
            None,
        )
        children = [c for c in value.named_children if c.type != "comment"]
        spreads = [k for k, c in enumerate(children) if c.type == "spread_element"]
        wheres = [
            k
            for k, c in enumerate(children)
            if c.type == "pair" and self.src.text(c.child_by_field_name("key")) == "where"
        ]
        if spreads and (not wheres or max(spreads) > wheres[-1]):
            return None  # `{ where, ...req.query }`: the spread may replace it
        if where is not None and not mongoose:
            # the rest are options (`include`, Prisma's `data`); a `where` within it is a field
            return self.filters(where, mongoose=True) if unwrap(where) != value else None
        pairs: list[tuple[str, Node]] = []
        for p in value.named_children:
            if p.type == "shorthand_property_identifier":
                pairs.append((self.src.text(p), p))
            elif p.type == "pair":
                key = p.child_by_field_name("key")
                if key is None or key.type == "computed_property_name":
                    return None
                name = self.src.text(key).strip("'\"")
                v = unwrap(p.child_by_field_name("value"))
                if name.startswith("$") or name in ("OR", "AND", "NOT") or v is None:
                    return None
                if v.type == "object" and (relation := self.relation(v)) is not None:
                    v = relation  # Prisma's `author: { id: me }`
                elif v.type in ("object", "array"):
                    return None  # `{ owner: { $ne: me } }`, `{ id: { in: ids } }`
                pairs.append((name, v))
            elif p.type != "comment":
                return None
        names = [k for k, _ in pairs]
        return pairs if len(names) == len(set(names)) else None  # the last duplicate wins

    def relation(self, value: Node) -> Node | None:
        """The id a relation filter equals: `{ id: me }`, one plain pair and nothing else."""
        pairs = [c for c in value.named_children if c.type != "comment"]
        if len(pairs) != 1 or pairs[0].type != "pair":
            return None
        key = self.src.text(pairs[0].child_by_field_name("key")).strip("'\"")
        v = unwrap(pairs[0].child_by_field_name("value"))
        return (
            v
            if key in ("id", "_id") and v is not None and v.type not in ("object", "array")
            else None
        )

    def store_call(self, call: Node, model: _Model) -> None:
        name = callee_name(self.src, call)
        a = args(call)
        span = self.span(call)
        links = self.chain(call)
        self.consumed |= {self.key(c) for c in links}
        names = [callee_name(self.src, c) for c in links]
        raised = [k for k, n in enumerate(names) if n == "orFail" or (k == 0 and n in _OR_FAIL)]
        raising = bool(raised) and not any(n in ("catch", "then") for n in names[raised[0] :])
        if not any(self.mentions(x) for x in a):
            return  # not a load of the path's object (`findById(req.user.id)`)
        objects = [x for x in (unwrap(y) for y in a) if x is not None and x.type == "object"]
        first = unwrap(a[0]) if a else None
        if first is not None and first.type != "object":
            # by key: `findById(id)`, `.delete(id)`
            scoped, cover = False, self.exact_ids(a[:1], model.key, "pk")
        else:
            # the filter, first but for Sequelize's `update(values, { where })`
            second = unwrap(a[1]) if len(a) > 1 else None
            query = (
                second
                if name == "update"
                and second is not None
                and second.type == "object"
                and self.keyed(second, "where")
                else first
            )
            pairs = self.filters(query, mongoose=model.record in self.code.mongoose)
            known = (
                self.code.fields_by_record.get(model.record or "")
                if model.record in self.code.mongoose
                else None
            )
            if pairs is None:
                scoped, cover = False, None
            else:
                # shape 1: plain equalities, one on an owner field (of the schema, for Mongoose)
                # with a caller-only value
                scoped = any(
                    OWNER_CHECK_RX.match(k)
                    and (model.record not in self.code.mongoose or (known and k in known))
                    and self.derived(v)
                    for k, v in pairs
                )
                keys = [
                    self.exact_ids([v], model.key, "pk" if k in ("_id", "id") else k)
                    for k, v in pairs
                    if self.mentions(v)
                ]
                cover = None if not keys or None in keys else set().union(*keys)  # type: ignore[arg-type]
            raising = raising or any(self.rejects_empty(o) for o in objects)
        read = name in _READS
        k = self.add(
            links[-1],
            Lookup(span, scoped, record_type=model.record),
            read=read,
            cover=cover,
            asynchronous=not model.sync,
        )
        for c in links:
            self.made.setdefault(self.key(c), [])
            if k not in self.made[self.key(c)]:
                self.made[self.key(c)].append(k)
        if raising:
            self.raising.add(k)

    def keyed(self, obj: Node, key: str) -> bool:
        return any(
            c.type == "pair" and self.src.text(c.child_by_field_name("key")).strip("'\"") == key
            for c in obj.named_children
        )

    def rejects_empty(self, obj: Node) -> bool:
        """Sequelize's `rejectOnEmpty: true` (or an error to throw); `false` or a value we can't
        read lets a missing record through as null."""
        for c in obj.named_children:
            if c.type == "pair" and self.src.text(c.child_by_field_name("key")).strip("'\"") == (
                "rejectOnEmpty"
            ):
                value = unwrap(c.child_by_field_name("value"))
                return value is not None and value.type in ("true", "new_expression")
        return False

    def subscript(self, node: Node) -> None:
        if self.key(node) in self.consumed or not self.mentions(node.child_by_field_name("index")):
            return
        if self.derived(node.child_by_field_name("object")):
            return
        store = f"{self.rel}:{chain_text(self.src, node.child_by_field_name('object'))}"
        cover = self.exact_ids([node.child_by_field_name("index")], store, "pk")
        self.add(node, Lookup(self.span(node)), read=True, cover=cover, asynchronous=False)

    def creation(self, node: Node) -> None:
        a = args(node)
        if self.req and any(self.src.text(unwrap(x) or x) == self.req for x in a):
            self.handoff(node, None)  # `new Loader(req)`
            return
        if not any(self.mentions(x) for x in a):
            return
        ctor = self.src.text(node.child_by_field_name("constructor"))
        if _ID_TYPES.match(ctor) or _THROWN.search(ctor):
            return
        self.handoff(node, self.exact_ids([x for x in a if self.mentions(x)]))

    def call(self, call: Node) -> None:
        if self.key(call) in self.consumed:
            return
        src = self.src
        fn = unwrap(call.child_by_field_name("function"))
        a = args(call)
        name = callee_name(src, call)
        receiver = (
            unwrap(fn.child_by_field_name("object"))
            if fn is not None and fn.type == "member_expression"
            else None
        )
        # a store call: a model, delegate, repository or Map
        if (
            receiver is not None
            and (model := self.code.model(self.rel, receiver)) is not None
            and name in _STORE_CALLS
        ):
            self.store_call(call, model)
            return
        used = [x for x in a if self.mentions(x)]
        passes = bool(self.req) and any(
            (x := unwrap(y)) is not None and x.type == "identifier" and src.text(x) == self.req
            for y in a
        )
        if passes and not used and name not in ("next",) and root_of(src, fn) != self.res:
            targets = self.code.functions(self.rel, fn, self.cls, self.instance)
            if targets is None or (targets and self.depth >= 1):
                self.handoff(call, None)
            elif targets:
                self.hop_into(call, targets)
            elif name not in _READS_REQUEST:
                self.handoff(call, None)  # code we can't read may load by `req.params`
            return
        if not used:
            if (
                receiver is not None
                and self.mentions(receiver)
                and any(
                    (unwrap(x) is not None and unwrap(x).type in _FUNCTION_VALUES)
                    or (x.type == "identifier" and src.text(x) not in self.root)
                    for x in a
                )
                and not self.loads(receiver)
            ):
                self.handoff(call, None)  # `[req.params.id].forEach(remove)`
            return
        cover = self.exact_ids(used)
        dotted = chain_text(src, fn)
        root = dotted.split(".", 1)[0]
        if (
            dotted in _CONVERSIONS
            or _INERT_ROOTS.match(root)
            or _INERT_ROOTS.match(dotted)
            or _THROWN.search(name)
        ):
            return
        if self.res and root == self.res:
            return  # the response: `res.json(…)`, `res.status(404)`
        if dotted == "next" or (self.req and root == self.req):
            return
        targets = self.code.functions(self.rel, fn, self.cls, self.instance)
        if targets is None:
            if not _VALIDATOR_NAME.match(name):
                self.handoff(call, cover)
            return
        if targets:
            if self.depth >= 2 or (self.depth == 1 and not _AUTHORIZE_NAME.match(name)):
                if not _VALIDATOR_NAME.match(name):
                    self.handoff(call, cover)
                return
            self.hop_into(call, targets)
            return
        if self.kept(call) and receiver is not None and not self.derived(receiver):
            # shape 4: a kept load we can't follow, handed a caller-only value
            scoped = any(self.derived(x) for x in a)
            self.add(call, Lookup(self.span(call), scoped), read=False, cover=cover)
        elif _LOOKUP_NAME.match(name) and (receiver is None or not self.derived(receiver)):
            self.add(call, Lookup(self.span(call)), read=False, cover=cover)
        elif not _VALIDATOR_NAME.match(name):
            self.handoff(call, cover)

    def kept(self, call: Node) -> bool:
        node = call
        while node.parent is not None and node.parent.type in _UNWRAP:
            node = node.parent
        return node.parent is not None and node.parent.type == "variable_declarator"

    def hop_into(self, call: Node, targets: list[Target]) -> None:
        self.hop = self.hop or self.span(call)
        verified: set[_Key] | None = None
        owned: set[_Key] | None = None
        for target in targets:
            scan, exact = self.o.hop(self, target, call)

            def mapped(inner: set[_Key] | None, exact: dict[str, str] = exact) -> set[_Key] | None:
                if not inner or any(r not in exact for r, _, _ in inner):
                    return None
                return {(exact[r], s, f) for r, s, f in inner}

            asynchronous = _is_async(target.fn)
            if asynchronous:
                self.hop_async.add(self.key(call))
            for x, read, inner, waits in zip(
                scan.facts.lookups, scan.reads, scan.covers, scan.asynchronous, strict=True
            ):
                lookup = Lookup(x.span, x.scoped, x.checked, x.record_type)
                self.add(
                    call,
                    lookup,
                    read=read and scan.pure_read,
                    cover=mapped(inner),
                    asynchronous=waits or asynchronous,
                )
            self.caller = self.caller or scan.facts.caller
            if scan.facts.handoff:
                self.handoffs.append(
                    (scan.facts.handoff, mapped(scan.handoff_cover), call.start_byte)
                )
            v = {(exact[r], s, f) for r, s, f in scan.verified if r in exact}
            o = {(exact[r], s, f) for r, s, f in scan.owned_or_null if r in exact}
            verified = v if verified is None else verified & v
            owned = o if owned is None else owned & o
        self.hop_verified[self.key(call)] = verified or set()
        self.hop_owned[self.key(call)] = owned or set()

    # -- the allow-listed statements
    def load(self, expr: Node | None) -> int | None:
        """The one read an expression is (a store read, or a hop doing only that), never a
        fallback, a conditional or a write."""
        expr = unwrap(expr)
        if expr is None or expr.type not in ("call_expression", "subscript_expression"):
            return None
        if any(n.type in ("binary_expression", "ternary_expression") for n in walk(expr)):
            return None
        made = {k for n in walk(expr) for k in self.made.get(self.key(n), [])}
        if len(made) != 1:
            return None
        k = next(iter(made))
        return k if self.reads[k] else None

    def declared(self, stmt: Node) -> tuple[str, Node] | None:
        """`const item = <value>` (one plain name), its name and value."""
        if stmt.type not in ("lexical_declaration", "variable_declaration"):
            return None
        decls = [d for d in stmt.named_children if d.type == "variable_declarator"]
        if len(decls) != 1:
            return None
        name, value = decls[0].child_by_field_name("name"), decls[0].child_by_field_name("value")
        if name is None or name.type != "identifier" or value is None:
            return None
        return self.src.text(name), value

    def statement(self, stmt: Node, following: list[Node]) -> None:
        end = stmt.end_byte
        value = None
        if (stmt.type == "expression_statement" and stmt.named_children) or (
            stmt.type == "return_statement" and stmt.named_children
        ):
            value = stmt.named_children[0]
        elif (d := self.declared(stmt)) is not None:
            value = d[1]
        elif stmt.type not in ("lexical_declaration", "variable_declaration") and stmt.type in (
            "call_expression",
            "await_expression",
            "member_expression",
            "identifier",
            "ternary_expression",
            "subscript_expression",
        ):
            value = stmt  # an arrow's expression body
        inner = unwrap(value)
        awaited = value is not None and _bare(value).type == "await_expression"
        if (
            inner is not None
            and inner.type == "call_expression"
            and (awaited or self.key(inner) not in self.hop_async)
        ):
            self.verify(self.hop_verified.get(self.key(inner), set()), end)
        k = self.load(value)
        if k is not None and self.asynchronous[k] and not awaited:
            k = None  # an un-awaited query never runs, and its promise is never missing
        scoped = k is not None and self.lookups[k].scoped
        if scoped and k in self.raising:
            # shape 1, refused when absent: `.orFail()`, `findUniqueOrThrow`, `rejectOnEmpty`
            self.verify(self.cover[k] or set(), end)  # type: ignore[index]
        d = self.declared(stmt)
        if d is None or not following:
            return
        record = d[0]
        nxt = following[0]
        absent = self.refuses_absence(nxt, record)
        if scoped and absent:
            # shape 1: a scoped query's record, then `if (!item) return res.status(404)…`
            self.verify(self.cover[k] or set(), nxt.end_byte)  # type: ignore[index]
        check = following[1] if absent and len(following) > 1 else nxt
        if k is not None and self.refuses_foreign(check, record):
            # shape 2: the load, then a refusal of a record the caller doesn't own
            self.checked(k)
            self.verify(self.cover[k] or set(), check.end_byte)
        elif k is not None and self.returns_if_owned(nxt, record):
            # shape 5: the load, then `return item?.owner === me ? item : undefined`
            self.checked(k)
            self.owned_or_null.update(dict.fromkeys(self.cover[k] or set(), nxt.start_byte))
        elif (
            inner is not None
            and inner.type == "call_expression"
            and absent
            and (awaited or self.key(inner) not in self.hop_async)
        ):
            self.verify(self.hop_owned.get(self.key(inner), set()), nxt.end_byte)

    def checked(self, k: int) -> None:
        x = self.lookups[k]
        self.lookups[k] = Lookup(x.span, x.scoped, True, x.record_type)

    def caller_declaration(self, stmt: Node) -> bool:
        d = self.declared(stmt)
        return d is not None and d[0] in self.callers

    # refusals: a 4xx response then return, a throw, or `return next(err)`
    def refusal(self, node: Node | None, record: str = "") -> bool:
        """A 4xx response then return, a throw or `return next(err)`, sending nothing of the
        record (`res.status(403).json(item)` is no refusal)."""
        if node is None or (
            record
            and any(n.type == "identifier" and self.src.text(n) == record for n in walk(node))
        ):
            return False
        if node.type == "statement_block":
            body = [s for s in node.named_children if s.type != "comment"]
            if len(body) == 1:
                return self.refusal(body[0], record)
            if len(body) == 2 and body[1].type == "return_statement" and not body[1].named_children:
                return self.responds_4xx(body[0]) or self.calls_next(body[0])
            return False
        if node.type == "throw_statement":
            # a `catch` that can see what the `try` declared with `var` may send it
            return not any(start <= node.start_byte < end for start, end in self.leaky_try)
        if node.type == "return_statement" and node.named_children:
            value = unwrap(node.named_children[0])
            return self.responds_4xx(value) or self.calls_next(value)
        return False

    def responds_4xx(self, node: Node | None) -> bool:
        """`res.status(403).json(…)`, `res.sendStatus(404)`: a 4xx response."""
        node = unwrap(node)
        if node is not None and node.type == "expression_statement" and node.named_children:
            node = unwrap(node.named_children[0])
        if node is None or node.type != "call_expression" or not self.res:
            return False
        for n in walk(node):
            if n.type != "call_expression":
                continue
            fn = unwrap(n.child_by_field_name("function"))
            if fn is None or fn.type != "member_expression":
                continue
            if chain_text(self.src, fn.child_by_field_name("object")) != self.res:
                continue
            prop = self.src.text(fn.child_by_field_name("property"))
            status = (args(n) or [None])[0]
            if prop in ("status", "sendStatus") and status is not None:
                code = self.src.text(status)
                return code.isdigit() and 400 <= int(code) < 500
        return False

    def calls_next(self, node: Node | None) -> bool:
        node = unwrap(node)
        if node is not None and node.type == "expression_statement" and node.named_children:
            node = unwrap(node.named_children[0])
        if node is None or node.type != "call_expression":
            return False
        a = args(node)
        return (
            self.src.text(node.child_by_field_name("function")) == "next"
            and len(a) == 1
            and self.error(a[0])
        )

    def error(self, node: Node | None) -> bool:
        """An error value: `new Error(…)`, `createError(403)`, a `catch` parameter, or a name
        bound once to one (`next(null)` and `const err = null` are none)."""
        node = unwrap(node)
        if node is None:
            return False
        if node.type in ("new_expression", "call_expression"):
            return True
        if node.type != "identifier":
            return False
        name = self.src.text(node)
        body = self.fn.child_by_field_name("body")
        if any(
            c.type == "catch_clause" and self.src.text(c.child_by_field_name("parameter")) == name
            for c in (walk(body) if body is not None else [])
            if c.child_by_field_name("parameter") is not None
        ):
            return True
        bound = [
            d.child_by_field_name("value")
            for d in (walk(body) if body is not None else [])
            if d.type == "variable_declarator"
            and self.src.text(d.child_by_field_name("name")) == name
        ]
        return (
            len(bound) == 1
            and name not in self.unstable
            and unwrap(bound[0]) is not None
            and unwrap(bound[0]).type in ("new_expression", "call_expression")
        )

    def condition(self, stmt: Node, record: str = "") -> Node | None:
        if stmt.type != "if_statement" or stmt.child_by_field_name("alternative") is not None:
            return None
        if not self.refusal(stmt.child_by_field_name("consequence"), record):
            return None
        return unwrap(stmt.child_by_field_name("condition"))

    def parts(self, node: Node | None, op: str) -> list[Node]:
        out, stack = [], [node]
        while stack:
            n = unwrap(stack.pop())
            if n is None:
                continue
            if (
                n.type == "binary_expression"
                and self.src.text(n.child_by_field_name("operator")) == op
            ):
                stack += [n.child_by_field_name("right"), n.child_by_field_name("left")]
            else:
                out.append(n)
        return out

    def absence(self, node: Node | None, record: str, *, present: bool) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        text = self.src.text
        if (
            not present
            and node.type == "unary_expression"
            and text(node.child_by_field_name("operator")) == "!"
        ):
            arg = unwrap(node.child_by_field_name("argument"))
            return arg is not None and text(arg) == record
        if present and node.type == "identifier":
            return text(node) == record
        if node.type == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            sides = {
                text(unwrap(node.child_by_field_name("left"))),
                text(unwrap(node.child_by_field_name("right"))),
            }
            nothing = {"null", "undefined"}
            wanted = ("!=", "!==") if present else ("==", "===")
            return op in wanted and record in sides and bool(sides & nothing)
        return False

    def refuses_absence(self, stmt: Node, record: str) -> bool:
        test = self.condition(stmt, record)
        return test is not None and self.absence(test, record, present=False)

    def refuses_foreign(self, stmt: Node, record: str) -> bool:
        """`if (!item || item.owner !== req.user.id) { res.status(403)…; return; }`, also behind
        `!req.user.isAdmin &&`."""
        test = self.condition(stmt, record)
        if test is None:
            return False
        ands = self.parts(test, "&&")
        if len(ands) == 2:
            rest = [p for p in ands if not self.unprivileged(p)]
            if len(rest) != 1:
                return False
            test = rest[0]
        elif len(ands) > 2:
            return False
        compared = False
        for part in self.parts(test, "||"):
            if self.absence(part, record, present=False):
                continue
            if not self.compares(part, record, negated=True):
                return False
            compared = True
        return compared

    def unprivileged(self, node: Node | None) -> bool:
        node = unwrap(node)
        if (
            node is None
            or node.type != "unary_expression"
            or self.src.text(node.child_by_field_name("operator")) != "!"
        ):
            return False
        arg = unwrap(node.child_by_field_name("argument"))
        if arg is None or arg.type != "member_expression":
            return False
        prop = self.src.text(arg.child_by_field_name("property"))
        base = unwrap(arg.child_by_field_name("object"))
        return (
            bool(_PRIVILEGE_FLAG.match(prop))
            and base is not None
            and chain_text(self.src, base) in self.caller_paths
        )

    def returns_if_owned(self, stmt: Node, record: str) -> bool:
        """`return item?.owner === me ? item : undefined` (or `null`), optionally `item && …`."""
        if stmt.type != "return_statement" or not stmt.named_children:
            return False
        expr = unwrap(stmt.named_children[0])
        if expr is None or expr.type != "ternary_expression":
            return False
        yes = unwrap(expr.child_by_field_name("consequence"))
        no = unwrap(expr.child_by_field_name("alternative"))
        if (
            yes is None
            or self.src.text(yes) != record
            or no is None
            or no.type not in ("null", "undefined")
        ):
            return False
        compared = False
        for part in self.parts(expr.child_by_field_name("condition"), "&&"):
            if self.absence(part, record, present=True):
                continue
            if not self.compares(part, record, negated=False):
                return False
            compared = True
        return compared

    def compares(self, part: Node | None, record: str, *, negated: bool) -> bool:
        """`item.owner !== me` (`negated`), `item.owner === me`, `item.owner.equals(me)`,
        `String(item.owner) === me`; the owner a member of the record, `me` caller-only."""
        part = unwrap(part)
        if part is None:
            return False
        text = self.src.text
        if part.type == "unary_expression" and text(part.child_by_field_name("operator")) == "!":
            return negated and self.compares(
                part.child_by_field_name("argument"), record, negated=False
            )
        if part.type == "binary_expression":
            op = text(part.child_by_field_name("operator"))
            if op not in (("!==", "!=") if negated else ("===", "==")):
                return False
            sides = (part.child_by_field_name("left"), part.child_by_field_name("right"))
            return any(
                self.owner_of(a, record) and self.derived(b) for a, b in (sides, sides[::-1])
            )
        if not negated and part.type == "call_expression":
            fn = unwrap(part.child_by_field_name("function"))
            a = args(part)
            if (
                fn is not None
                and fn.type == "member_expression"
                and text(fn.child_by_field_name("property")) == "equals"
                and len(a) == 1
            ):
                return self.owner_of(fn.child_by_field_name("object"), record) and self.derived(
                    a[0]
                )
        return False

    def owner_of(self, node: Node | None, record: str) -> bool:
        """`item.owner`, `item?.ownerId`, `item.owner.toString()`, `String(item.owner)`."""
        node = unwrap(node)
        if node is None:
            return False
        if (inner := converted(self.src, node)) is not None:
            return self.owner_of(inner, record)
        if node.type != "member_expression":
            return False
        base = unwrap(node.child_by_field_name("object"))
        prop = self.src.text(node.child_by_field_name("property"))
        if base is not None and base.type == "identifier" and self.src.text(base) == record:
            return bool(OWNER_CHECK_RX.match(prop))
        # `item.owner._id`, `item.author.id`: the owner's own id
        return (
            prop in ("_id", "id")
            and base is not None
            and base.type == "member_expression"
            and self.owner_of(base, record)
        )

    def pure_read(self, body: list[Node]) -> bool:
        """`return <read>`, an arrow returning one, or `const r = <read>; return r`."""
        if not body:
            return False
        last = body[-1]
        value = (
            last.named_children[0]
            if last.type == "return_statement" and last.named_children
            else (
                last
                if last.type
                not in (
                    "return_statement",
                    "expression_statement",
                    "lexical_declaration",
                    "variable_declaration",
                    "if_statement",
                )
                else None
            )
        )
        if value is None:
            return False
        if len(body) == 2 and (d := self.declared(body[0])) is not None:
            if unwrap(value) is None or self.src.text(unwrap(value)) != d[0]:
                return False
            value = d[1]
        elif len(body) != 1:
            return False
        return len(self.lookups) == 1 and self.load(value) == 0

    def result(self, first_return: int | None, pure_read: bool) -> _Scan:
        verified = {k: at for k, at in self.verified.items() if k[0] not in self.unstable}

        def holds(keys: set[_Key] | None, at: int) -> bool:
            return (
                bool(keys)
                and all(
                    any(
                        v[0] == r
                        and pos <= at
                        and s != "*"
                        and (
                            (s == v[1] and f in ("*", v[2]))
                            # `Comment.deleteMany({ post: id })` once the post is the caller's
                            or (
                                s != v[1]
                                and v[2] == "pk"
                                and (_references(f, v[1]) or self.code.refs.get((s, f)) == v[1])
                            )
                        )
                        for v, pos in verified.items()
                    )
                    for r, s, f in keys  # type: ignore[union-attr]
                )
                and not any(start <= at < end for start, end in self.uncovered)
            )

        unheld = [(span, keys) for span, keys, at in self.handoffs if not holds(keys, at)]
        handoff, handoff_cover = unheld[0] if unheld else (None, None)
        before = first_return if first_return is not None else 1 << 60
        exported = set() if self.swallows else self.params | self.path_ids
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
            verified={k for k, at in verified.items() if at <= before and k[0] in exported},
            owned_or_null={
                k
                for k, at in self.owned_or_null.items()
                if k[0] in exported - self.unstable and at <= before
            },
            covers=tuple(self.cover),
            reads=tuple(self.reads),
            handoff_cover=handoff_cover,
            pure_read=pure_read,
            asynchronous=tuple(self.asynchronous),
            seen=frozenset(
                r
                for keys in [*self.cover, *(k for _, k, _ in self.handoffs)]
                for r in ({"*"} if keys is None else {r for r, _, _ in keys})
            ),
        )


def _defines(src: Parsed, member: Node, name: str) -> bool:
    """A class member that may define method `name`: `m() {}`, a field `m = …`, or a
    constructor assigning `this.m = …`."""
    if member.type == "method_definition":
        if src.text(member.child_by_field_name("name")) == name:
            return True
        return src.text(member.child_by_field_name("name")) == "constructor" and any(
            a.type == "assignment_expression"
            and src.text(a.child_by_field_name("left")) == f"this.{name}"
            and src.text(a.child_by_field_name("right")) != f"this.{name}.bind(this)"
            for a in walk(member)
        )
    if member.type in ("public_field_definition", "field_definition"):
        label = member.child_by_field_name("name") or member.child_by_field_name("property")
        return label is not None and src.text(label) == name
    return False


def _passes_on(code: JsCode, wrapper: Target, made: Target) -> bool:
    """`fn => (req, res, next) => fn(req, res, next).catch(next)`: the wrapper's handler only
    calls the function it wraps (and catches)."""
    src = code.files[wrapper.rel].src
    params = param_patterns(wrapper.fn)
    if len(params) != 1 or params[0].type != "identifier":
        return False
    wrapped = src.text(params[0])
    mine = [src.text(q) for q in param_patterns(made.fn)]
    for n in walk(made.fn):
        if (
            n.type == "call_expression"
            and src.text(n.child_by_field_name("function")) == wrapped
            and [src.text(x) for x in args(n)] != mine[: len(args(n))]
        ):
            return False  # `fn({ ...req, user }, res, next)`
        if n.type == "subscript_expression" and src.text(n.child_by_field_name("object")) in {
            m.removeprefix("...") for m in mine
        }:
            continue  # `.catch(args[2])`: its own arguments
        if n.type in (
            "new_expression",
            "subscript_expression",
            "assignment_expression",
            "augmented_assignment_expression",
            "update_expression",
        ):
            return False
        if n.type == "call_expression":
            fn = unwrap(n.child_by_field_name("function"))
            name = callee_name(src, n)
            # its own response or `next` (`return res.status(400).json(…)`) loads nothing
            responds = _base(src, fn) in {m.removeprefix("...") for m in mine[1:3]}
            if not (
                responds
                or src.text(fn) in (wrapped, "Promise.resolve")
                or (
                    fn is not None
                    and fn.type == "member_expression"
                    and name in ("catch", "then", "finally")
                )
            ):
                return False
    return True


def _base(src: Parsed, node: Node | None) -> str:
    """The name a chain of members and calls starts from: `res` for `res.status(400).json`."""
    for _ in range(_MAX_DEPTH):
        node = unwrap(node)
        if node is None:
            return ""
        if node.type == "identifier":
            return src.text(node)
        if node.type == "member_expression":
            node = node.child_by_field_name("object")
        elif node.type == "call_expression":
            node = node.child_by_field_name("function")
        else:
            return ""
    return ""


def _references(field: str, store: str) -> bool:
    """`post`, `postId`, `post_id` for the model `Post`."""
    name = re.sub(r"_?id$", "", field, flags=re.I).replace("_", "").lower()
    return bool(name) and name == store.rsplit(":", 1)[-1].replace("_", "").lower()


def _bare(node: Node) -> Node:
    while node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    return node


def _is_async(fn: Node) -> bool:
    return any(c.type == "async" for c in fn.children)


def written_path(src: Parsed, node: Node | None) -> str:
    """The named path a write lands under: `req.user` for `req.user[k]`."""
    node = unwrap(node)
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        if text := chain_text(src, node):
            return text
        node = unwrap(node.child_by_field_name("object"))
    return chain_text(src, node)


def own_scope(fn: Node, node: Node) -> bool:
    """Whether `node` is in `fn`'s own scope, not a function or class nested in it."""
    parent = node.parent
    while parent is not None and parent != fn:
        if parent.type in _SCOPES:
            return False
        parent = parent.parent
    return True


def root_of(src: Parsed, node: Node | None) -> str:
    return chain_text(src, node).split(".", 1)[0]


def _plain_request(src: Parsed, fn: Node) -> bool:
    patterns = param_patterns(fn)
    return bool(patterns) and all(p.type == "identifier" for p in patterns[:2])


def _flat(nodes: list[Node]) -> Iterator[Node]:
    stack = list(reversed(nodes))
    while stack:
        popped = stack.pop()
        node = unwrap(popped) or popped
        if node.type == "array":
            stack += reversed(node.named_children)
        else:
            yield node


def _request_names(src: Parsed, fn: Node) -> tuple[str, str]:
    names = [src.text(p) if p.type == "identifier" else "" for p in param_patterns(fn)[:2]]
    req, res = [*names, "", ""][:2]
    return req, res


def _function_name(src: Parsed, fn: Node) -> tuple[str, bool]:
    """The name a function is known by: its own, the binding or key it is assigned to (through
    wrappers like `asyncHandler(…)`), or the enclosing factory's (then `built`); '' when
    anonymous."""
    node: Node | None = fn
    built = False
    for _ in range(_MAX_DEPTH):
        if node is None:
            return "", built
        if (
            node.type in _DECLARED_FUNCTIONS or node.type in _FUNCTION_VALUES
        ) and node.child_by_field_name("name") is not None:
            return src.text(node.child_by_field_name("name")), built
        parent = node.parent
        if parent is None:
            return "", built
        if parent.type == "variable_declarator":
            return src.text(parent.child_by_field_name("name")), built
        if parent.type == "pair":
            return src.text(parent.child_by_field_name("key")).strip("'\""), built
        if parent.type in ("assignment_expression", "public_field_definition", "field_definition"):
            label = parent.child_by_field_name("left") or parent.child_by_field_name("name")
            return (chain_text(src, label).rsplit(".", 1)[-1] if label is not None else ""), built
        if parent.type in ("arguments", "call_expression"):
            node = parent  # `asyncHandler(…)`
            continue
        if (
            parent.type in ("return_statement", "statement_block")
            or parent.type in _FUNCTION_VALUES
        ):
            node, built = parent, True  # `(opts) => (req, res, next) => …`
            continue
        if parent.type in ("parenthesized_expression", "await_expression"):
            node = parent
            continue
        return "", built
    return "", built


def _minified(rel: str, text: str) -> bool:
    """A bundled or minified file (`static/libs/htmx.min.js`): vendored, not the app's code."""
    lines = text.count("\n") + 1
    return ".min." in rel.rsplit("/", 1)[-1] or len(text) / lines > 500


def _handles_request(src: Parsed, fn: Node, req: str, res: str) -> bool:
    """Whether a function reads its first parameter as a request (or its second as a
    response): not any function whose first parameter has a `user` field."""
    text = src.text(fn)
    members = r"(params|body|query|headers|header|get|user|auth|session|cookies|ip|method|path|url)"
    if re.search(rf"\b{re.escape(req)}\s*(\?\.|\.)\s*{members}\b", text):
        return True
    for alias in re.findall(rf"\b(\w+)\s*=\s*{re.escape(req)}\s*[;,\n)]", text):
        if re.search(rf"\b{re.escape(alias)}\s*(\?\.|\.)\s*{members}\b", text):
            return True  # `const r = req; r.user = …`
    return bool(res) and bool(
        re.search(
            rf"\b{re.escape(res)}\s*(\?\.|\.)\s*(locals|status|json|send|redirect|render)\b", text
        )
    )


def _hands_caller(src: Parsed, fn: Node, req: str) -> bool:
    """Whether a function hands the caller and request data to the same call, which may write
    one into the other (`applyOverrides(req.user, req.query)`)."""
    caller = {f"{req}.user", f"{req}.auth"}
    data = re.compile(rf"\b{re.escape(req)}\s*\.\s*(body|query|params|param|get|header|headers)\b")
    for n in walk(fn.child_by_field_name("body") or fn):
        if n.type == "call_expression":
            given = [src.text(unwrap(x) or x) for x in args(n)]
            if any(g in caller for g in given) and any(data.search(g) for g in given):
                return True
    return False


def _from_request(src: Parsed, fn: Node, req: str, value: Node | None) -> bool:
    """Whether a value written as the caller is built from the request's own data: its body,
    query, params or a header read raw, directly or through locals, aliases of the request,
    or a helper handed the request (`req.user = fromRequest(req)`). A credential checked by a
    verifying call (`jwt.verify(req.headers.authorization)`) is not."""
    if value is None:
        return True
    body = fn.child_by_field_name("body") or fn
    requests = {req}
    tainted: set[str] = set()
    data = (
        "body",
        "query",
        "params",
        "param",
        "get",
        "header",
        "headers",
        "cookies",
    )

    def reads(node: Node) -> bool:
        for m in walk(node):
            if m.type == "identifier" and src.text(m) in tainted and not _verified(src, m, body):
                return True
            if m.type in ("member_expression", "subscript_expression"):
                base = m.child_by_field_name("object")
                prop = m.child_by_field_name("property") or m.child_by_field_name("index")
                key = (
                    string_value(src, prop)
                    if prop is not None and prop.type == "string"
                    else (src.text(prop) if prop is not None else "")
                )
                if (
                    chain_text(src, base) in requests
                    and key in data
                    and not _verified(src, m, body)
                ):
                    return True
            if (
                m.type == "call_expression"
                and any(src.text(unwrap(x) or x) in requests for x in args(m))
                and not _VERIFYING.search(callee_name(src, m))
            ):
                return True  # a helper reading the request
        return False

    for _ in range(4):
        for n in walk(body):
            if n.type != "variable_declarator":
                continue
            pattern, bound = n.child_by_field_name("name"), n.child_by_field_name("value")
            if pattern is None or bound is None:
                continue
            chain = chain_text(src, bound)
            if pattern.type == "identifier" and chain in requests:
                requests.add(src.text(pattern))  # `const r = req`
            elif (
                pattern.type == "object_pattern"
                and chain in requests
                and any(k in data for k in bound_names(src, pattern))
            ):
                tainted.update(bound_names(src, pattern))  # `const { query } = req`
            elif reads(bound):
                tainted.update(bound_names(src, pattern))
        for n in walk(body):
            if n.type != "call_expression":
                continue
            fn_ = unwrap(n.child_by_field_name("function"))
            receiver = (
                fn_.child_by_field_name("object")
                if fn_ is not None and fn_.type == "member_expression"
                else None
            )
            callbacks = [
                unwrap(x)
                for x in args(n)
                if unwrap(x) is not None and unwrap(x).type in _FUNCTION_VALUES
            ]
            plain = [
                x for x in args(n) if unwrap(x) is None or unwrap(x).type not in _FUNCTION_VALUES
            ]
            if callbacks and (
                (receiver is not None and reads(receiver)) or any(reads(x) for x in plain)
            ):
                for cb in callbacks:
                    tainted.update(x for q in param_patterns(cb) for x in bound_names(src, q))

    return reads(value)


# calls that check a credential, not echo request data (`jwt.verify`, `getApiKeyInfo(req)`)
_VERIFYING = re.compile(
    r"(?i)(verify|decode|authenticat|introspect|jwt|token|api_?key|credential|bearer|signature|hmac)"
)


def _verified(src: Parsed, node: Node, stop: Node) -> bool:
    """Whether a request read sits in a verifying call's arguments (`jwt.verify(token)`)."""
    parent = node.parent
    while parent is not None and parent != stop:
        if parent.type == "call_expression" and _VERIFYING.search(callee_name(src, parent)):
            return True
        parent = parent.parent
    return False


def caller_writes(src: Parsed, fn: Node, req: str, res: str) -> list[Node | None]:
    """The values written under `req.user`, `req.auth` or `res.locals.user` anywhere in `fn` (its
    closures too), directly or through locals naming them (`const { user } = req`)."""
    paths = {f"{req}.user", f"{req}.auth"} if req else set()
    if res:
        paths.add(f"{res}.locals.user")
    body = fn.child_by_field_name("body") or fn
    aliases: dict[str, str] = {}

    def expand(path: str) -> str:
        head, _, rest = path.partition(".")
        return f"{aliases[head]}.{rest}".rstrip(".") if head in aliases else path

    for _ in range(4):  # aliases of aliases
        for n in walk(body):
            if n.type != "variable_declarator":
                continue
            pattern = n.child_by_field_name("name")
            chain = expand(chain_text(src, n.child_by_field_name("value")))
            if pattern is None or not chain or chain.split(".", 1)[0] not in {req, res} - {""}:
                continue
            if pattern.type == "identifier":
                aliases[src.text(pattern)] = chain
            for c in pattern.named_children if pattern.type == "object_pattern" else []:
                if c.type == "shorthand_property_identifier_pattern":
                    aliases[src.text(c)] = f"{chain}.{src.text(c)}"
                elif (
                    c.type == "pair_pattern" and c.child_by_field_name("value").type == "identifier"
                ):
                    key = src.text(c.child_by_field_name("key"))
                    aliases[src.text(c.child_by_field_name("value"))] = f"{chain}.{key}"
    out: list[Node | None] = []
    for n in walk(body):
        targets: list[Node] = []
        value: Node | None = None
        whole = True
        if n.type in ("assignment_expression", "augmented_assignment_expression"):
            left, value = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type in ("object_pattern", "array_pattern"):
                targets = [
                    m for m in walk(left) if m.type in ("member_expression", "subscript_expression")
                ]
            elif left is not None:
                targets = [left]
        elif n.type == "update_expression":
            targets = [n.child_by_field_name("argument")]
        elif n.type == "call_expression":
            fn_ = unwrap(n.child_by_field_name("function"))
            value = n
            if _WRITES_FIRST.match(chain_text(src, fn_)) and args(n):
                targets = [args(n)[0]]  # `Object.assign(req, { user })` may write any of it
            elif (
                fn_ is not None
                and fn_.type == "member_expression"
                and _MUTATORS.match(src.text(fn_.child_by_field_name("property")))
            ):
                targets = [fn_.child_by_field_name("object")]
                whole = False  # `res.setHeader(…)` writes the response, not `res.locals`
        for target in targets:
            written = expand(written_path(src, target))
            if written and any(
                written == q
                or written.startswith(q + ".")
                or (whole and q.startswith(written + "."))
                for q in paths
            ):
                out.append(value)
    return out


def _admin_only(src: Parsed, fn: Node, roles: frozenset[str] = frozenset()) -> bool:
    """Whether middleware refuses every unprivileged caller before anything else: after plain
    declarations, its first statement is `if (<unprivileged>) <refusal>`, its if/else, or a
    returned ternary, reading only the caller's role. `roles`: the factory parameters bound to
    privileged roles (`authorize("admin")`)."""
    req, res = _request_names(src, fn)
    params = param_patterns(fn)
    following = src.text(params[2]) if len(params) > 2 and params[2].type == "identifier" else ""
    if not req:
        return False
    user = f"{req}.user"
    aliases: dict[str, str] = {}  # `const { role } = req.user`, `const isAdmin = req.user.isAdmin`
    values: dict[str, Node] = {}
    body = statements(fn)
    k = 0
    while k < len(body) and body[k].type in ("lexical_declaration", "variable_declaration"):
        for d in body[k].named_children:
            pattern, value = d.child_by_field_name("name"), d.child_by_field_name("value")
            if pattern is None or value is None:
                continue
            chain = chain_text(src, value)
            if pattern.type == "identifier":
                values[src.text(pattern)] = value
                if chain:
                    aliases[src.text(pattern)] = chain
            for c in pattern.named_children if pattern.type == "object_pattern" and chain else []:
                if c.type == "shorthand_property_identifier_pattern":
                    aliases[src.text(c)] = f"{chain}.{src.text(c)}"
        if any(n.type == "call_expression" for n in walk(body[k])):
            return False  # work done before the check
        k += 1
    if k >= len(body):
        return False

    def caller(node: Node | None) -> bool:
        chain = chain_text(src, node)
        head, _, rest = chain.partition(".")
        chain = f"{aliases[head]}.{rest}".rstrip(".") if head in aliases else chain
        return chain == user or chain.startswith(user + ".")

    def role(node: Node | None) -> bool:
        """A privileged role: `"admin"`, `Role.Admin`, `ROLES.ADMIN`, a role parameter."""
        node = unwrap(node)
        if node is None:
            return False
        if (value := string_value(src, node)) is not None:
            return bool(PRIVILEGED_RX.fullmatch(value))
        if node.type == "identifier":
            return src.text(node) in roles
        chain = chain_text(src, node)
        return (
            bool(chain) and "." in chain and bool(PRIVILEGED_RX.fullmatch(chain.rsplit(".", 1)[-1]))
        )

    def test(node: Node | None, depth: int = 0) -> int:
        """+1: true exactly for a privileged caller; -1: exactly for an unprivileged one."""
        node = unwrap(node)
        if node is None or depth > _MAX_DEPTH:
            return 0
        op = (
            src.text(node.child_by_field_name("operator"))
            if node.type in ("unary_expression", "binary_expression")
            else ""
        )
        if node.type == "unary_expression" and op == "!":
            return -test(node.child_by_field_name("argument"), depth + 1)
        if node.type == "identifier" and src.text(node) in values and src.text(node) not in aliases:
            return test(values[src.text(node)], depth + 1)
        if node.type in ("member_expression", "identifier"):
            chain = chain_text(src, node)
            return int(caller(node) and bool(_PRIVILEGE_FLAG.match(chain.rsplit(".", 1)[-1])))
        if node.type == "binary_expression" and op in ("===", "==", "!==", "!="):
            sides = [unwrap(node.child_by_field_name(x)) for x in ("left", "right")]
            for a, b in (sides, sides[::-1]):
                if caller(a) and role(b):
                    return 1 if op in ("===", "==") else -1
        if node.type == "binary_expression" and op == "in":
            left, right = (node.child_by_field_name(x) for x in ("left", "right"))
            return int(role(left) and caller(right))
        if node.type == "call_expression":
            fn_ = unwrap(node.child_by_field_name("function"))
            a = args(node)
            owner = (
                fn_.child_by_field_name("object")
                if fn_ is not None and fn_.type == "member_expression"
                else None
            )
            name = callee_name(src, node)
            if (
                len(a) == 1
                and name in ("hasRole", "hasAnyRole", "includes")
                and caller(owner)
                and role(a[0])
            ):
                return 1  # `req.user.hasRole("admin")`, `req.user.roles.includes("admin")`
            owner = unwrap(owner)
            if (
                len(a) == 1
                and name == "includes"
                and caller(a[0])
                and owner is not None
                and (
                    (
                        owner.type == "array"
                        and owner.named_children
                        and all(role(x) for x in owner.named_children)
                    )
                    or (owner.type == "identifier" and src.text(owner) in roles)
                )
            ):
                return 1  # `["admin"].includes(req.user.role)`, `roles.includes(req.user.role)`
        return 0

    def parts(node: Node | None, op: str) -> list[Node]:
        out, stack = [], [node]
        while stack:
            n = unwrap(stack.pop())
            if n is None:
                continue
            if n.type == "binary_expression" and src.text(n.child_by_field_name("operator")) == op:
                stack += [n.child_by_field_name("right"), n.child_by_field_name("left")]
            else:
                out.append(n)
        return out

    def absent(node: Node, present: bool) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        if present:
            return chain_text(src, node) == user
        return (
            node.type == "unary_expression"
            and chain_text(src, node.child_by_field_name("argument")) == user
        )

    def unprivileged(cond: Node | None) -> bool:
        terms = parts(cond, "||")
        return any(test(x) == -1 for x in terms) and all(
            absent(x, False) or test(x) == -1 for x in terms
        )

    def privileged(cond: Node | None) -> bool:
        terms = parts(cond, "&&")
        return any(test(x) == 1 for x in terms) and all(
            absent(x, True) or test(x) == 1 for x in terms
        )

    def refusing(node: Node | None) -> bool:
        """`res.status(403).json(…)`, `res.sendStatus(401)`, `next(err)`."""
        node = unwrap(node)
        if node is None or node.type != "call_expression":
            return False
        a = args(node)
        if following and src.text(node.child_by_field_name("function")) == following:
            value = unwrap(a[0]) if len(a) == 1 else None
            return value is not None and value.type in (
                "identifier",
                "new_expression",
                "call_expression",
            )
        for n in walk(node):
            if (
                n.type == "call_expression"
                and root_of(src, n.child_by_field_name("function")) == res
            ):
                code = args(n)[0] if args(n) else None
                if callee_name(src, n) in ("status", "sendStatus") and code is not None:
                    text = src.text(code)
                    return text.isdigit() and 400 <= int(text) < 500
        return False

    def stops(branch: Node | None, final: bool = False) -> bool:
        """A refusal that ends the middleware (D13); `final`: nothing follows the branch."""
        branch = unwrap(branch)
        if branch is None:
            return False
        stmts = (
            [s for s in branch.named_children if s.type != "comment"]
            if branch.type == "statement_block"
            else [branch]
        )
        if len(stmts) == 1 and stmts[0].type == "throw_statement":
            return True
        if len(stmts) == 1 and stmts[0].type == "return_statement" and stmts[0].named_children:
            return refusing(stmts[0].named_children[0])
        if len(stmts) == 2 and stmts[1].type in ("return_statement", "throw_statement"):
            first = stmts[0].named_children[0] if stmts[0].named_children else None
            ends = stmts[1].type == "throw_statement" or not stmts[1].named_children
            return ends and refusing(first)
        if final and len(stmts) == 1 and stmts[0].type == "expression_statement":
            return refusing(stmts[0].named_children[0] if stmts[0].named_children else None)
        return branch.type == "call_expression" and refusing(branch)

    stmt = body[k]
    if stmt.type == "if_statement":
        cond = stmt.child_by_field_name("condition")
        yes, no = stmt.child_by_field_name("consequence"), stmt.child_by_field_name("alternative")
        if no is not None and no.type == "else_clause":
            no = next((c for c in no.named_children if c.type != "comment"), None)
        final = k == len(body) - 1
        return (unprivileged(cond) and stops(yes, final)) or (privileged(cond) and stops(no, final))
    value = unwrap(
        stmt.named_children[0] if stmt.type == "return_statement" and stmt.named_children else stmt
    )
    if value is not None and value.type == "ternary_expression":
        cond = value.child_by_field_name("condition")
        yes, no = value.child_by_field_name("consequence"), value.child_by_field_name("alternative")
        return (unprivileged(cond) and stops(yes)) or (privileged(cond) and stops(no))
    return False


class ExpressOwnership:
    """An Express handler's ownership facts. `guarded`: an authenticating middleware runs before
    it, so `req.user` (and `req.auth`, `res.locals.user`) is the caller."""

    def __init__(self, code: JsCode) -> None:
        self.code = code
        self.guarded = False

    def handler(
        self,
        rel: str,
        fn_node: Node,
        path_ids: set[str],
        *,
        guarded: bool,
        middleware: list[tuple[Node, bool]] = (),  # type: ignore[assignment]
        preloaded: set[str] = frozenset(),  # type: ignore[assignment]
    ) -> HandlerFacts:
        target = self._target(rel, fn_node)
        if target is None:
            span = CodeSpan(path=RepoPath(rel), line=self.code.files[rel].src.line(fn_node))
            return HandlerFacts(handoff=span if path_ids else None, takes_id=bool(path_ids))
        if path_ids & preloaded or not _plain_request(self.code.files[target.rel].src, target.fn):
            # `router.param("id", load)` hands the id to code that runs first, and a destructured
            # request (`({ params }, res) => …`) isn't read: neither is followed
            span = CodeSpan(path=RepoPath(rel), line=self.code.files[rel].src.line(fn_node))
            return HandlerFacts(handoff=span, takes_id=bool(path_ids))
        self.guarded = guarded
        scan = self.scan(target, set(), path_ids, 0)
        # checkout middleware in the route's chain that reads the path (`loadPost, update`): its
        # own lookups count, but nothing it checks covers the handler's
        loaders = []
        for node, before in middleware:  # each with the guards that ran before it
            m = self._target(rel, node)
            if (
                m is not None
                and ".params" in self.code.files[m.rel].src.text(m.fn)
                and (_plain_request(self.code.files[m.rel].src, m.fn))
            ):
                self.guarded = before
                loaders.append(self.scan(m, set(), path_ids, 0))
        self.guarded = guarded
        seen = scan.seen.union(*(s.seen for s in loaders))
        if path_ids and "*" not in seen and not path_ids <= seen:
            # the path id is read nowhere we can see: by middleware, `req.param`, `req.path`, …
            span = CodeSpan(path=RepoPath(rel), line=self.code.files[rel].src.line(fn_node))
            return HandlerFacts(handoff=span, takes_id=True)
        facts = [*(s.facts for s in loaders), scan.facts]
        return HandlerFacts(
            lookups=tuple(x for f in facts for x in f.lookups),
            caller=next((f.caller for f in facts if f.caller), None),
            hop=scan.facts.hop,
            handoff=next((f.handoff for f in facts if f.handoff), None),
            takes_id=bool(path_ids),
        )

    def admin_only(self, rel: str, node: Node) -> bool | None:
        """Whether checkout middleware refuses an unprivileged caller; None when it isn't
        checkout code."""
        if (
            unwrap(node) is not None
            and unwrap(node).type != "call_expression"
            and (self.code.functions(rel, node, None) is None)
        ):
            return False  # ambiguous: not read by its name either
        target = self._target(rel, node)
        if target is None:
            return None
        src = self.code.files[target.rel].src
        roles: frozenset[str] = frozenset()
        if unwrap(node).type == "call_expression":
            # `authorize("admin")`: the factory's parameters hold the privileged roles
            found = self.code.functions(rel, unwrap(node).child_by_field_name("function"), None)
            if found and len(found) == 1:
                fsrc = self.code.files[found[0].rel].src
                roles = frozenset(
                    x for q in param_patterns(found[0].fn) for x in bound_names(fsrc, q)
                )
        return _admin_only(src, target.fn, roles)

    def files_src(self, rel: str) -> Parsed:
        return self.code.files[rel].src

    def _target(self, rel: str, node: Node) -> Target | None:
        node = unwrap(node)
        if node is None:
            return None
        if node.type in _FUNCTION_VALUES:
            return Target(rel, node)
        if node.type == "call_expression":
            a = args(node)
            inner = unwrap(a[0]) if len(a) == 1 else None
            found = self.code.functions(rel, node.child_by_field_name("function"), None)
            if found is None:
                return None  # an ambiguous wrapper
            made_by = self._made(found[0]) if found and len(found) == 1 else None
            if (
                inner is not None
                and (
                    (not found and _ASYNC_WRAPPER.match(callee_name(self.files_src(rel), node)))
                    or (made_by is not None and _passes_on(self.code, found[0], made_by))
                )
                and (wrapped := self._target(rel, inner)) is not None
            ):
                return wrapped  # `asyncHandler(async (req, res) => …)`
            # a factory: `retrieveBasket()` (or a wrapper `cached(show)`) returning the handler
            return made_by
        found = self.code.functions(rel, node, None)
        if found and len(found) == 1:
            return found[0]
        return None

    def _made(self, factory: Target) -> Target | None:
        """The one function a factory returns."""
        made = [
            fn
            for s in statements(factory.fn)
            if (
                fn := unwrap(
                    s.named_children[0] if s.type == "return_statement" and s.named_children else s
                )
            )
            is not None
            and fn.type in _FUNCTION_VALUES
        ]
        returns = [n for n in own(factory.fn) if n.type == "return_statement"]
        expression_body = (factory.fn.child_by_field_name("body") or factory.fn).type != (
            "statement_block"
        )
        return (
            Target(factory.rel, made[0])
            if len(made) == 1 and (expression_body or len(returns) == 1)
            else None
        )

    def scan(
        self,
        target: Target,
        ids: set[str],
        path_ids: set[str],
        depth: int,
        handed: set[str] = frozenset(),  # type: ignore[assignment]
        handler: tuple[bool, bool] = (True, True),
    ) -> _Scan:
        guarded = self.guarded and handler[0]
        key = (target.rel, target.fn.start_byte, frozenset(ids), frozenset(path_ids))
        key += (frozenset(handed), depth, handler, guarded)
        if target.instance is not None:
            key += (target.instance[0], target.instance[1].start_byte)
        if key not in self.code.scans:
            walk_ = _Walk(self, target, ids, path_ids, set(handed), depth, handler)
            self.code.scans[key] = walk_.run()
        return self.code.scans[key]

    def hop(self, walk_: _Walk, target: Target, call: Node) -> tuple[_Scan, dict[str, str]]:
        src = self.code.files[target.rel].src
        patterns = param_patterns(target.fn)
        a = args(call)
        if any(x.type == "spread_element" for x in a) or len(a) > len(patterns):
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}

        def passed(k: int, name: str) -> bool:
            value = unwrap(a[k]) if k < len(a) else None
            return bool(name) and value is not None and walk_.src.text(value) == name

        # `ctrl.get(req, res)`: the request handed on whole, its path ids with it
        handler = (passed(0, walk_.req), passed(0, walk_.req) and passed(1, walk_.res))
        if any(passed(k, walk_.req) for k in range(1, len(a))) or (
            handler[0] and (patterns[0].type != "identifier")
        ):
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}
        mapping = {}
        for k, (p, v) in enumerate(zip(patterns, a, strict=False)):
            if k < sum(handler):
                continue
            if p.type != "identifier":
                if walk_.mentions(v):
                    return _Scan(HandlerFacts(handoff=walk_.span(call))), {}  # destructured
                continue
            mapping[src.text(p)] = v
        inner_ids = {p for p, v in mapping.items() if walk_.mentions(v)}
        handed = {p for p, v in mapping.items() if p not in inner_ids and walk_.derived(v)}
        path_ids = walk_.path_ids if handler[0] else set()
        if path_ids & mapping.keys():
            return _Scan(HandlerFacts(handoff=walk_.span(call))), {}  # a parameter named as an id
        scan = self.scan(target, inner_ids, path_ids, walk_.depth + 1, handed, handler)
        exact = {p: r for p, v in mapping.items() if (r := walk_.exact(v))}
        return scan, {**{i: i for i in path_ids}, **exact}
