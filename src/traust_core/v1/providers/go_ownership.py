"""Go ownership facts. The reader judges only (D35's terms): a read of a record by the path id
alone is judged, and anything else reads unknown. It reads the handler the Go route matrix
resolved, over the matrix's own parse, and follows the id one checkout call deep."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator

from traust_core.v1.models.code_facts import RouteFamily
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.go_routes import (
    _CONTEXT_PARAM,
    _HANDLER_TYPE,
    _args,
    _Checkout,
    _field,
    _params,
    _receivers,
    _Source,
    _unwrap,
)
from traust_core.v1.providers.route_ownership import HandlerFacts, Lookup, path_params
from traust_core.v1.providers.route_plumbing import _Row
from traust_core.v1.providers.syntax import Node, walk

# the calls that read a path id: `r.PathValue("id")`, gin/echo `c.Param`, fiber `c.Params`,
# httprouter `ps.ByName`, gin's `c.Params.Get`; chi's and gorilla's are told by their import
_PARAM_METHODS = {"PathValue", "Param", "Params", "ParamsInt", "ByName", "AllParams"}
_BINDERS = {"ShouldBindUri", "BindUri", "MustBindUri", "ParamsParser", "BindPathParams"}
_CHI = re.compile(r"(^|/)go-chi/chi(/v\d+)?$")
_GORILLA = re.compile(r"(^|/)gorilla/mux$")
_FIBER = re.compile(r"(^|/)gofiber/fiber(/v\d+)?$")
# what a client sent is no record read: parsing and formatting the id, logging it, answering
_PURE = re.compile(
    r"^(strconv|strings|fmt|errors|log|slog|uuid|time|math|bytes|url|json|base64|hex|regexp|"
    r"path|filepath|sort|reflect|utf8|unicode|xid|ulid|shortuuid|bson|primitive)\."
)
_PURE_PATHS = re.compile(
    r"(?i)(^strconv$|(^|/)(go\.)?uuid(/v\d+)?$|/cast$|/xid$|/ulid(/v\d+)?$|/ksuid$|shortid$|"
    r"hashids(/v\d+)?$|sqids(-go)?$|^strings$|^fmt$|"
    r"^errors$|^log$|^log/slog$|^encoding/|^net/url$|/zap$|/logrus$|/zerolog|gofiber/(fiber/v\d+/)?utils)"
)
_BUILTINS = {
    "len", "cap", "append", "copy", "panic", "print", "println", "string", "int", "int8",
    "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32",
    "float64", "byte", "rune", "bool", "new", "make", "min", "max",
}  # fmt: skip
_LOGS = re.compile(
    r"(?i)^(print\w*|info\w*|debug\w*|warn\w*|error\w*|fatal\w*|panic\w*|log\w*|trace\w*|"
    r"with\w*|str|msg\w*|int\d*|any|err|send|errorf)$"
)
_ANSWERS = re.compile(
    r"^(JSON|IndentedJSON|PureJSON|SecureJSON|AsciiJSON|JSONP|String|HTML|XML|YAML|TOML|"
    r"ProtoBuf|Status|SendStatus|SendString|Send|Abort\w*|Redirect|Render|NoContent|Blob|"
    r"Attachment|File|FileAttachment|Stream|Set|SetCookie|Header|Write|WriteHeader|"
    r"WriteString|Error|Errorf|NewError|NewHTTPError|Data)$"
)
# who the caller is, read as words with `ctx`/`context`/`key` dropped: `ctxKeyUser`,
# `claimsKey{}`, `authenticatedUserID`, `contextGetUser`
_CALLER_WORDS = re.compile(
    r"^((current|auth|authenticated|logged|in|session|signed|request|req)_)*"
    r"(user|me|account|identity|member|principal|owner|tenant|caller|uid|sub|subject|claims?|"
    r"token|jwt|viewer|actor|auth)(_(id|obj|info|data|name|email|uid))?$"
)
_CALLER_VERBS = re.compile(r"^((must|get|load|fetch|lookup|read|extract|require|from)_)+")
_CALLER_PACKAGE = re.compile(r"(?i)(jwt|auth|session|identity|claims|oidc|oauth|user|principal)")
_CONTEXT_GETTERS = {"Get", "MustGet", "Locals", "Value", "GetString", "GetInt", "GetInt64",
                    "GetUint", "GetUint64"}  # fmt: skip
# what the client sent: a `Get` on these reads the request, not who is calling
_CLIENT_INPUT = re.compile(r"(?i)(query|form|header|url|params?\b|cookie|body)")
_DROPPED_WORDS = {"ctx", "context", "key", "keys", "type", "from", "value", "val", "request",
                  "req"}  # fmt: skip
# a query builder rendering its SQL: what it renders still holds the id (`ToSql()`)
_RENDERS = {"ToSql", "ToSQL", "MustSql", "Build", "BuildSQL"}
# a call that narrows a query: the caller in its arguments scopes what it reads
_FILTERS = re.compile(
    r"(?i)^(where|filter\w*|and|or|eq|scopes?|having|join\w*|on|by\w*|"
    r"for\w*|of|in|owned\w*|belong\w*|with\w*)$"
)
_TEMPLATES = {"Execute", "ExecuteTemplate"}
_ERR = re.compile(r"(?i)^_?$|^err\w*$|\w*Err$")
_ASSIGNS = ("short_var_declaration", "assignment_statement", "var_spec")
_FUNCS = ("function_declaration", "method_declaration", "func_literal")
_MAX_PASSES = 8
_Pred = Callable[["_Source", Node, Node], bool]


class GoOwnership:
    """What a Go handler does with the path ids and the caller."""

    def __init__(self, co: _Checkout) -> None:
        self.co = co
        self.fields, self.dups = _record_fields(co)
        self.dead: dict[int, set[int]] = {}
        self.reads_ids: dict[int, bool] = {}
        self.ids_memo: dict[tuple[str, int], bool] = {}
        self.callers_memo: dict[tuple[str, int], bool] = {}
        self.loading: dict[int, bool] = {}
        self.insides: dict[tuple[int, frozenset[str], frozenset[str]], HandlerFacts | None] = {}
        self.callers_of: dict[int, bool] = {}
        self.active: set[int] = set()  # functions being read: a call back into one adds nothing

    def facts(self, src: _Source, fn: Node) -> HandlerFacts | None:
        """The handler's facts, or None where it isn't one this reader can follow."""
        handler = self.handler_body(src, fn)
        if handler is None:
            return None
        ids = self.taint(src, handler, set(), self.id_source, ids=True)
        loaders = [
            (call, found)
            for call in _calls(handler)
            if (found := self.checkout_call(src, call)) and self.touches_id(*found)
        ]  # `n, err := loadNote(r)`: a helper reading the id and loading the record
        if not ids.names and not ids.read and not loaders:
            return HandlerFacts(ignores_id=True)
        callers = self.taint(src, handler, set(), self.caller(ids.names))
        out = _Facts(callers.first)
        for node, holder in self.reads(src, handler, ids.names):
            if _param_call(src, node, handler):
                out.handoff = out.handoff or self.span(src, node)
                continue
            found = self.checkout_call(src, node)
            if found is None:
                out.lookups.append(self.lookup(src, node, holder, ids.names, callers.names))
                continue
            inner = self.hop(*found, node, src, handler, ids.names, callers.names)
            out.merge(inner, self.span(src, node))
        for call, found in loaders:
            out.merge(self.load(*found, call, src, handler, callers.names), self.span(src, call))
        return HandlerFacts(
            lookups=tuple(out.lookups),
            caller=out.caller,
            hop=out.hop,
            handoff=out.handoff,
            takes_id=True,
        )

    def handler_body(self, src: _Source, fn: Node) -> Node | None:
        """A handler, or the one handler a factory returns (`getNote(db)`)."""
        if any(_CONTEXT_PARAM.search(k) or _HANDLER_TYPE.search(k) for _, k in _params(src, fn)):
            return fn if fn.child_by_field_name("body") is not None else None
        returns = [_unwrap(r) or r for r in self.co.returned(src, fn)]
        literals = [r for r in returns if r.type == "func_literal"]
        inner = [
            (_unwrap(a) or a)
            for r in returns
            if r.type == "call_expression"
            for a in _args(r)
            if (_unwrap(a) or a).type == "func_literal"
        ]  # `http.HandlerFunc(func(w, r) {..})`
        found = literals + inner
        return found[0] if len(found) == 1 and len(returns) == 1 else None

    def checkout_call(self, src: _Source, node: Node) -> tuple[_Source, Node] | None:
        if node.type != "call_expression":
            return None
        found = self.co.function(src, node.child_by_field_name("function"))
        return found if found is not None and found[1].type != "func_literal" else None

    # ---- what flows where
    def taint(
        self, src: _Source, fn: Node, seeds: set[str], source: _Pred, *, ids: bool = False
    ) -> _Taint:
        """The names that hold what `source` reads, through assignments, and the first read.
        For ids, only what still is the id passes on (`strconv.Atoi(id)`, not `store.Get(id)`)."""
        body = fn.child_by_field_name("body") or fn
        out = _Taint(set(seeds))
        for n in self.live(src, body):
            if source(src, n, fn):
                out.read = True
                out.first = out.first or self.span(src, n)
        for _ in range(_MAX_PASSES):
            grew = False
            for n in self.live(src, body):
                if n.type not in (*_ASSIGNS, "range_clause"):
                    if n.type == "call_expression":
                        for name in self.fills(src, n, fn, out.names, source, ids):
                            if name not in out.names:
                                out.names.add(name)
                                grew = True
                    continue
                left = n.child_by_field_name("left") if n.type != "var_spec" else None
                right = n.child_by_field_name("right" if n.type != "var_spec" else "value")
                if right is None:
                    continue
                if not (self.mentions(src, right, out.names) or _any(src, right, fn, source)):
                    continue
                if ids and not self.passes_id(src, right, fn, out.names):
                    continue  # `note, err := store.Get(id)`: the record, not the id
                if not ids and not self.passes_caller(src, right, fn, out.names, source):
                    continue  # `ctx, span := tracer.Start(ctx, .., user.ID)`: no caller value
                targets = (
                    [c for c in n.named_children if c.type == "identifier"]
                    if n.type == "var_spec"
                    else (left.named_children if left is not None else [])
                )
                for t in targets:
                    if not ids and t.type != "identifier":
                        continue  # `d.UpdatedBy = user.ID` writes the caller, it filters nothing
                    name = _root_name(src, t)  # `in.ID = id`: `in` holds it
                    if name and not _ERR.match(name) and name not in out.names:
                        out.names.add(name)
                        grew = True
            for n in self.live(src, body) if ids else ():  # `c.ShouldBindUri(&req)` fills `req`
                if n.type == "call_expression" and self.binds(src, n, fn):
                    for a in _args(n):
                        inner = _unwrap(a)
                        if inner is not None and inner.type == "identifier":
                            name = src.text(inner)
                            if name not in out.names:
                                out.names.add(name)
                                grew = True
            if not grew:
                break
        if not ids:
            out.names -= self.overwritten(src, body, fn, out.names, source)
        return out

    def overwritten(
        self, src: _Source, body: Node, fn: Node, callers: set[str], source: _Pred
    ) -> set[str]:
        """Caller names assigned something else after they held the caller (`if x { uid = 0 }`):
        they may not hold it where they are read."""
        held: dict[str, int] = {}
        out = set()
        for n in self.live(src, body):
            if n.type not in _ASSIGNS[:2]:
                continue
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is None or right is None:
                continue
            caller = self.mentions(src, right, callers) or _any(src, right, fn, source)
            for t in left.named_children:
                name = src.text(t) if t.type == "identifier" else ""
                if name not in callers:
                    continue
                if caller and self.passes_caller(src, right, fn, callers, source):
                    held.setdefault(name, n.start_byte)
                elif name in held:
                    out.add(name)
        return out

    def fills(
        self, src: _Source, call: Node, fn: Node, names: set[str], source: _Pred, ids: bool
    ) -> list[str]:
        """What a call writes through its `&x` arguments: an id parsed out (`fmt.Sscanf(id, ..,
        &n)`, echo's `PathParamsBinder(c).Int64("id", &id)`), or the claims a JWT parse fills."""
        outs = [
            src.text(inner)
            for a in _args(call)
            if a.type == "unary_expression"
            and (inner := _unwrap(a)) is not None
            and inner.type == "identifier"
        ]
        if not outs:
            return []
        if ids:
            binder = any(
                src.text(c.child_by_field_name("function")).endswith("PathParamsBinder")
                for c in _calls(call, True)
            )
            given = any(self.handed_id(src, a, fn, names) for a in _args(call))
            return outs if binder or (given and self.converts(src, call)) else []
        operand, method = _field(src, call)
        alias = src.text(operand) if operand is not None else ""
        parses = method.startswith(("Parse", "Verify", "Validate"))
        return outs if parses and _CALLER_PACKAGE.search(src.imports.get(alias, "")) else []

    def passes_caller(
        self, src: _Source, node: Node, fn: Node, callers: set[str], source: _Pred
    ) -> bool:
        """An expression still holding the caller, or a query narrowed by it: a value, field or
        conversion of it, a caller source, or a `Where("user_id = ?", uid)` chain."""
        node = _unwrap(node) or node
        if node.type == "expression_list":
            return any(self.passes_caller(src, c, fn, callers, source) for c in node.named_children)
        if node.type != "call_expression":
            return True
        if source(src, node, fn) or self.converts(src, node):
            return True
        for call in _calls(node, True):
            _, method = _field(src, call)
            if _FILTERS.match(method) and any(
                self.mentions(src, a, callers) or _any(src, a, fn, source) for a in _args(call)
            ):
                return True
        return False

    def binds(self, src: _Source, call: Node, fn: Node) -> bool:
        operand, method = _field(src, call)
        if method in _BINDERS:
            return True
        echo = {p for p, k in _params(src, fn) if "echo.Context" in k}
        return method == "Bind" and operand is not None and src.text(operand) in echo

    def passes_id(self, src: _Source, node: Node, fn: Node, ids: set[str]) -> bool:
        """An expression whose value is still the id: the read itself, a parse or conversion of
        it (`strconv.Atoi(id)`, `cast.ToUint(id)`, a checkout `parseID(id)`), a field or index
        of it; not a record read."""
        node = _unwrap(node) or node
        if node.type == "expression_list":
            return any(self.passes_id(src, c, fn, ids) for c in node.named_children)
        if node.type != "call_expression":
            return self.mentions(src, node, ids) or _any(src, node, fn, self.id_source)
        found = self.checkout_call(src, node)
        if self.id_source(src, node, fn):
            return found is None or not self.loads(*found)
        if self.converts(src, node):
            return any(self.passes_id(src, a, fn, ids) for a in _args(node))
        if _field(src, node)[1] in _RENDERS:  # `q, args, _ := sq.Select(..).Where(..).ToSql()`
            return self.mentions(src, node, ids) or _any(src, node, fn, self.id_source)
        if found is not None:  # a checkout transform reads no record: `parseID(id)`
            return self.hop(*found, node, src, fn, ids, set()) is None and any(
                self.passes_id(src, a, fn, ids) for a in _args(node)
            )
        return False

    def converts(self, src: _Source, call: Node) -> bool:
        callee = call.child_by_field_name("function")
        text = src.text(callee)
        if text in _BUILTINS or _PURE.match(text):
            return True
        operand, _ = _field(src, call)
        alias = src.text(operand) if operand is not None else ""
        path = src.imports.get(alias, "")
        return bool(path and _PURE_PATHS.search(path) and self.co.directory(path) is None)

    def mentions(self, src: _Source, node: Node, names: set[str]) -> bool:
        return bool(names) and any(
            n.type == "identifier" and src.text(n) in names for n in _walk(node)
        )

    def id_source(self, src: _Source, n: Node, fn: Node) -> bool:
        """A read of a path id: by the request's or framework's own call, or a checkout helper
        that returns one (`id, err := parseID(r)`)."""
        if n.type != "call_expression":
            return False
        key = (src.file.rel, n.id)
        if key not in self.ids_memo:
            self.ids_memo[key] = False
            self.ids_memo[key] = self._id_source(src, n)
        return self.ids_memo[key]

    def _id_source(self, src: _Source, n: Node) -> bool:
        operand, method = _field(src, n)
        if method in _PARAM_METHODS and operand is not None:
            return self.handed(src, operand)  # `r.PathValue`, `c.Param`, not `cfg.Param("id")`
        if method == "Get" and operand is not None and operand.type == "selector_expression":
            return src.text(operand.child_by_field_name("field")) == "Params"  # gin `c.Params`
        alias = src.text(operand) if operand is not None else ""
        path = src.imports.get(alias, "")
        if method in ("URLParam", "URLParamFromCtx") and (
            _CHI.search(path) or "RouteContext(" in alias
        ):
            return True
        if method == "Vars" and _GORILLA.search(path):
            return True
        callee = n.child_by_field_name("function")
        if callee is not None and callee.type == "index_expression":  # fiber v3 `Params[int]`
            head = callee.child_by_field_name("operand")
            if head is not None and head.type == "selector_expression":
                pkg = src.text(head.child_by_field_name("operand"))
                if src.text(head.child_by_field_name("field")) == "Params":
                    return bool(_FIBER.search(src.imports.get(pkg, "")))
        found = self.checkout_call(src, n)
        return found is not None and self.reads_id(*found)

    def handed(self, src: _Source, value: Node, depth: int = 0) -> bool:
        """A value rooted in what a function was handed (`r`, `c`, `e.Request`, `ps`), or a
        local bound to one."""
        root = _unwrap(value) or value
        while root.type in ("selector_expression", "call_expression", "index_expression"):
            nxt = root.child_by_field_name(
                "function" if root.type == "call_expression" else "operand"
            )
            if nxt is None:
                return False
            root = _unwrap(nxt) or nxt
        if root.type != "identifier" or depth > _MAX_PASSES:
            return False
        name, fn = src.text(root), _scope_of(root)
        while fn is not None:
            if name in {p for p, _ in _params(src, fn)} | _receivers(src, fn):
                return True
            bound = self.co.binding(src, root, name, fn)
            if bound is not None:
                return self.handed(src, bound.value, depth + 1)
            fn = _scope_of(fn)
        return False

    def reads_id(self, src: _Source, fn: Node) -> bool:
        """A checkout helper that returns a path id (`parseID(r)`), not one that only reads it
        on the way (`log(r.PathValue("id")); return 42`)."""
        key = id(fn)
        if key not in self.reads_ids:
            self.reads_ids[key] = False  # recursion reads as no
            inner = self.taint(src, fn, set(), self.id_source, ids=True)
            self.reads_ids[key] = any(
                self.passes_id(src, r, fn, inner.names) for r in self.co.returned(src, fn)
            )
        return self.reads_ids[key]

    def touches_id(self, src: _Source, fn: Node) -> bool:
        """A checkout helper that reads a path id itself, whatever it returns (`loadNote(r)`)."""
        body = fn.child_by_field_name("body") or fn
        return any(self.id_source(src, n, fn) for n in _calls(body))

    def caller(self, ids: set[str]) -> _Pred:
        """A caller source that isn't handed the path id: `store.GetUser(id)` is a record read."""

        def source(src: _Source, n: Node, fn: Node) -> bool:
            return self.caller_source(src, n, fn) and not (
                n.type == "call_expression"
                and any(
                    self.mentions(src, a, ids) or _any(src, a, fn, self.id_source) for a in _args(n)
                )
            )

        return source

    def caller_source(self, src: _Source, n: Node, fn: Node) -> bool:
        if n.type not in ("call_expression", "selector_expression", "index_expression"):
            return False
        key = (src.file.rel, n.id)
        if key not in self.callers_memo:
            self.callers_memo[key] = self._caller_source(src, n, fn)
        return self.callers_memo[key]

    def _caller_source(self, src: _Source, n: Node, fn: Node) -> bool:
        """Who the caller is: `c.Get("user")`, `r.Context().Value(userKey)`, a session's
        `user_id`, `CurrentUser(r)`, `jwtauth.FromContext(ctx)`, PocketBase's `e.Auth`."""
        if n.type == "selector_expression":
            operand = n.child_by_field_name("operand")
            field = src.text(n.child_by_field_name("field"))
            return (
                operand is not None
                and (field == "Auth" or _caller_key(field))
                and self.request_value(src, operand, fn)
            )  # PocketBase's `e.Auth`, a custom echo context's `ac.User`
        if n.type == "index_expression":  # `sess.Values["user_id"]`, gin's `c.Keys["user"]`
            operand = n.child_by_field_name("operand")
            index = src.string(n.child_by_field_name("index"))
            return (
                operand is not None
                and operand.type == "selector_expression"
                and src.text(operand.child_by_field_name("field")) in ("Values", "Keys")
                and self.request_or_session(src, operand.child_by_field_name("operand"), fn)
                and index is not None
                and _caller_key(index)
            )
        operand, method = _field(src, n)
        args = _args(n)
        if method in _CONTEXT_GETTERS and args:
            if operand is not None and _CLIENT_INPUT.search(src.text(operand)):
                return False  # `r.URL.Query().Get("user_id")`: what the client sent
            if operand is None or not self.request_or_session(src, operand, fn):
                return False  # `cache.Get("user_id")`: no request or session holds it
            asserted = n.parent.child_by_field_name("type") if (
                n.parent is not None and n.parent.type == "type_assertion_expression"
            ) else None  # fmt: skip
            if asserted is not None and _caller_key(_last_word(src.text(asserted))):
                return True  # `r.Context().Value(ctxKey{}).(*User)`
            return any(self.caller_key_arg(src, a) for a in args)
        if self.fills(src, n, fn, set(), self.caller_source, False):
            return True  # `jwt.ParseWithClaims(raw, &claims, ..)`
        found = self.checkout_call(src, n)
        if found is not None and self.reads_caller(*found):
            return True  # `me := whoAmI(r)`
        if method == "BasicAuth" and not args:
            return True
        alias = src.text(operand) if operand is not None else ""
        if method == "FromContext" and _CALLER_PACKAGE.search(src.imports.get(alias, alias)):
            return True
        name = method or src.text(n.child_by_field_name("function"))
        if not _caller_call(name):
            return False
        # `auth.CurrentUser(r)`, `app.contextGetUser(r)`: a package's or the handler's own;
        # `note.User()` names a record's owner, not the caller
        return operand is None or self.handed(src, operand) or not self.local(src, operand)

    def local(self, src: _Source, value: Node) -> bool:
        """A value rooted in a local the function binds itself (`note` in `note.User()`)."""
        root = _unwrap(value) or value
        while root.type in ("selector_expression", "call_expression", "index_expression"):
            nxt = root.child_by_field_name(
                "function" if root.type == "call_expression" else "operand"
            )
            if nxt is None:
                return False
            root = _unwrap(nxt) or nxt
        if root.type != "identifier":
            return False
        fn = _scope_of(root)
        while fn is not None:
            if self.co.binding(src, root, src.text(root), fn) is not None:
                return True
            fn = _scope_of(fn)
        return False

    def request_or_session(self, src: _Source, value: Node | None, fn: Node) -> bool:
        """What a caller key is read from: the request or framework context the handler was
        handed, its `Context()`, a context or session value (`ctx`, `sess`, `sessionManager`)."""
        if value is None:
            return False
        text = src.text(value)
        return (
            self.handed(src, value)
            or text.endswith("Context()")
            or bool(re.search(r"(?i)(^|\.)(ctx|context|sess\w*|session\w*|\w*session\w*)$", text))
        )

    def request_value(self, src: _Source, value: Node, fn: Node) -> bool:
        """The request or framework context the handler was given, or a cast of it
        (`ac := c.(*AppContext)`)."""
        params = {p for p, _ in _params(src, fn)}
        value = _unwrap(value) or value
        if src.text(value) in params:
            return True
        if value.type != "identifier":
            return False
        scope = _scope_of(value)
        binds = self.co.bindings(src, scope).get(src.text(value), []) if scope is not None else []
        return any(
            (v := _unwrap(b.value) or b.value).type == "type_assertion_expression"
            and src.text(v.child_by_field_name("operand")) in params
            for b in binds
        )

    def reads_caller(self, src: _Source, fn: Node) -> bool:
        """A checkout helper that reads who the caller is (`func whoAmI(r) *User`)."""
        key = id(fn)
        if key not in self.callers_of:
            self.callers_of[key] = False
            body = fn.child_by_field_name("body") or fn
            self.callers_of[key] = any(self.caller_source(src, n, fn) for n in _walk(body))
        return self.callers_of[key]

    def caller_key_arg(self, src: _Source, arg: Node) -> bool:
        """A context or session key naming the caller: `"user"`, `userKey`, `claimsKey{}`, or
        an auth library's own key (`jwtmiddleware.ContextKey{}`)."""
        arg = _unwrap(arg) or arg
        literal = src.string(arg)
        if literal is not None:
            return _caller_key(literal)
        if arg.type == "composite_literal":
            arg = arg.child_by_field_name("type") or arg
        text = src.text(arg)
        alias, _, name = text.rpartition(".")
        if alias and alias in src.imports and _CALLER_PACKAGE.search(src.imports[alias]):
            return True
        return _caller_key(name or text)

    # ---- the record reads the ids reach
    def reads(self, src: _Source, fn: Node, ids: set[str]) -> Iterator[tuple[Node, Node | None]]:
        """Each call or map read handed a path id that may read or write a record, outermost of
        its chain (`db.Where("id = ?", id).First(&note)`), with the assignment holding it."""
        seen: set[int] = set()
        body = fn.child_by_field_name("body") or fn
        for n in self.live(src, body):
            if n.type == "index_expression":
                index, operand = n.child_by_field_name("index"), n.child_by_field_name("operand")
                if (
                    index is not None
                    and operand is not None
                    and self.handed_id(src, index, fn, ids)
                    and not self.handed_id(src, operand, fn, ids)
                    and not _any(src, n, fn, self.caller_source)
                ):
                    yield n, _holder(n)  # `notes[id]`: an in-memory store read
                continue
            if n.type != "call_expression":
                continue
            if not any(self.handed_id(src, a, fn, ids) for a in _args(n)):
                continue
            if self.id_source(src, n, fn) or self.inert(src, n, fn):
                continue
            top = _chain_top(n)
            if top.id in seen:
                continue
            seen.add(top.id)
            yield top, _holder(top)

    def handed_id(self, src: _Source, node: Node, fn: Node, ids: set[str]) -> bool:
        return self.mentions(src, node, ids) or _any(src, node, fn, self.id_source)

    def inert(self, src: _Source, call: Node, fn: Node) -> bool:
        """A call that reads no record: parsing, logging, answering the client."""
        if self.converts(src, call):
            return True
        operand, method = _field(src, call)
        if not method:
            return False
        if method in _RENDERS or method in _TEMPLATES:
            return True  # a query rendered for later, a page rendered for the client
        if _LOGS.match(method) and operand is not None and re.search(r"(?i)log", src.text(operand)):
            return True
        params = {p for p, _ in _params(src, fn)}
        head = operand
        while head is not None and head.type in ("selector_expression", "call_expression"):
            head = head.child_by_field_name("operand" if head.type == "selector_expression" else
                                            "function")  # fmt: skip
        if _ANSWERS.match(method) and (
            head is None or src.text(head) in params or src.text(head) in ("http", "render")
        ):
            return True
        return bool(re.match(r"(?i)^(encode|marshal\w*)$", method))

    def hop(
        self,
        fsrc: _Source,
        fn: Node,
        call: Node,
        src: _Source,
        handler: Node,
        ids: set[str],
        callers: set[str],
    ) -> HandlerFacts | None:
        """The checkout function the id is handed to, one call deep, with the caller values it
        is handed too; None for one that reads no record (`parseID(id)`)."""
        if fn.child_by_field_name("body") is None:
            return None
        params, args = _params(fsrc, fn), _args(call)
        given = [(params[i][0], a) for i, a in enumerate(args) if i < len(params) and params[i][0]]
        seeds = {p for p, a in given if self.handed_id(src, a, handler, ids)}
        if not seeds:
            return None
        caller_seeds = {
            p
            for p, a in given
            if self.mentions(src, a, callers) or _any(src, a, handler, self.caller(ids))
        }
        return self.inside(fsrc, fn, seeds, caller_seeds)

    def load(
        self, fsrc: _Source, fn: Node, call: Node, src: _Source, handler: Node, callers: set[str]
    ) -> HandlerFacts | None:
        """A checkout helper that reads the id itself and loads the record (`loadNote(r)`)."""
        params, args = _params(fsrc, fn), _args(call)
        caller_seeds = {
            params[i][0]
            for i, a in enumerate(args)
            if i < len(params)
            and params[i][0]
            and (self.mentions(src, a, callers) or _any(src, a, handler, self.caller(set())))
        }
        return self.inside(fsrc, fn, set(), caller_seeds)

    def loads(self, fsrc: _Source, fn: Node) -> bool:
        key = id(fn)
        if key not in self.loading:
            self.loading[key] = False
            self.loading[key] = self.inside(fsrc, fn, set(), set()) is not None
        return self.loading[key]

    def inside(
        self, fsrc: _Source, fn: Node, seeds: set[str], caller_seeds: set[str]
    ) -> HandlerFacts | None:
        if fn.child_by_field_name("body") is None:
            return None
        key = (id(fn), frozenset(seeds), frozenset(caller_seeds))
        if key not in self.insides:
            self.insides[key] = None  # a function that recurses reads as reading nothing more
            self.active.add(id(fn))
            try:
                self.insides[key] = self._inside(fsrc, fn, seeds, caller_seeds)
            finally:
                self.active.discard(id(fn))
        return self.insides[key]

    def _inside(
        self, fsrc: _Source, fn: Node, seeds: set[str], caller_seeds: set[str]
    ) -> HandlerFacts | None:
        inner = self.taint(fsrc, fn, seeds, self.id_source, ids=True)
        callers = self.taint(fsrc, fn, caller_seeds, self.caller(inner.names))
        record = self.result_type(fsrc, fn)
        lookups, handoff = [], None
        for n, holder in self.reads(fsrc, fn, inner.names):
            target = self.checkout_call(fsrc, n)
            if target is not None and id(target[1]) in self.active:
                continue  # `normalize(id[1:])` inside `normalize`
            if target is not None or _param_call(fsrc, n, fn):
                handoff = handoff or self.span(fsrc, n)  # `f(id)`: whatever the caller passed
                continue
            lookups.append(self.lookup(fsrc, n, holder, inner.names, callers.names, record))
        if not lookups and handoff is None:
            return None
        return HandlerFacts(lookups=tuple(lookups), caller=callers.first, handoff=handoff)

    def lookup(
        self,
        src: _Source,
        node: Node,
        holder: Node | None,
        ids: set[str],
        callers: set[str],
        record: str | None = None,
    ) -> Lookup:
        """A read by id: scoped when the call chain also names the caller."""
        fn = _scope_of(node)
        held = holder.child_by_field_name("left") if holder is not None else None
        scoped = (
            self.mentions(src, node, callers)
            or (fn is not None and _any(src, node, fn, self.caller(ids)))
            or (
                held is not None
                and fn is not None
                and self.scoped_before_run(src, held, fn, callers, ids)
            )
        )  # `q := db.Where("id = ?", id); q = q.Where("user_id = ?", uid); q.First(&n)`
        found = self.record(src, node, holder, ids)
        return Lookup(self.span(src, node), scoped=scoped, record_type=found or record)

    def scoped_before_run(
        self, src: _Source, held: Node, fn: Node, callers: set[str], ids: set[str]
    ) -> bool:
        """A query built into a local that the caller narrows before it next runs: the
        `q = q.Where("user_id = ?", uid)` comes before the `q.First(&n)`."""
        names = {src.text(t) for t in held.named_children if t.type == "identifier"} & callers
        if not names:
            return False
        body = fn.child_by_field_name("body") or fn
        scoped_at: list[int] = []
        runs: list[int] = []
        for n in self.live(src, body):
            if n.type == "assignment_statement" and held.start_byte < n.start_byte:
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if (
                    left is not None
                    and right is not None
                    and {src.text(t) for t in left.named_children} & names
                    and self.passes_caller(src, right, fn, callers, self.caller(ids))
                    and self.mentions(src, right, callers - names)
                ):
                    scoped_at.append(n.start_byte)
            elif n.type == "call_expression" and n.start_byte > held.start_byte:
                operand, _ = _field(src, n)
                if operand is not None and src.text(operand) in names:
                    runs.append(n.start_byte)  # `q.First(&n)`, `q.Where(..)` alike
        if not scoped_at:
            return False
        first_run = min((r for r in runs if r > min(scoped_at)), default=None)
        early = [r for r in runs if r < min(scoped_at)]
        return first_run is not None and not early

    def record(self, src: _Source, call: Node, holder: Node | None, ids: set[str]) -> str | None:
        """The checkout record type a read loads: what it fills (`&note`, a `new(Note)`), a
        `Model(&Note{})` in its chain, or what its result is declared as."""
        fills = [
            inner
            for n in _walk(call)
            if n.type == "unary_expression" and (inner := _root(_unwrap(n))) is not None
        ]  # `&note`, and `&n.UserID` in a `Scan`
        args = [_unwrap(x) or x for n in _calls(call, True) for x in _args(n)]
        bare = [a for a in args if a.type == "identifier" and src.text(a) not in ids]
        for a in args:  # `db.First(new(Note), id)`
            if a.type == "call_expression" and src.text(a.child_by_field_name("function")) == "new":
                kind = self.named(src, src.text(a.child_by_field_name("arguments")))
                if kind in self.fields:
                    return kind
        literals = [n for n in _walk(call) if n.type == "composite_literal"]
        targets = holder.child_by_field_name("left") if holder is not None else None
        held = [
            t
            for t in (targets.named_children if targets is not None else [])
            if t.type == "identifier" and not _ERR.match(src.text(t))
        ]
        for ident in [*fills, *bare]:
            if (kind := self.type_name(src, ident)) in self.fields:
                return kind
        for lit in literals:
            kind = self.named(src, src.text(lit.child_by_field_name("type")))
            if kind in self.fields:
                return kind
        for ident in held:
            if kind := self.type_name(src, ident):
                return kind
        return self.run_fills(src, call, held, ids)

    def run_fills(self, src: _Source, call: Node, held: list[Node], ids: set[str]) -> str | None:
        """The record a built query fills where it runs: `q := db.Where(..)`, then
        `q.First(&n)`."""
        names = {src.text(t) for t in held}
        fn = _scope_of(call)
        if not names or fn is None:
            return None
        for n in self.live(src, fn.child_by_field_name("body") or fn):
            operand, _ = _field(src, n) if n.type == "call_expression" else (None, "")
            if operand is None or src.text(operand) not in names or n.start_byte < call.start_byte:
                continue
            for a in _args(n):
                inner = _root(_unwrap(a)) if a.type == "unary_expression" else None
                if inner is not None and (kind := self.type_name(src, inner)) in self.fields:
                    return kind
        return None

    def type_name(self, src: _Source, ident: Node) -> str | None:
        kind = self.co.type_of(src, ident)
        if kind:
            return self.qualify(src, kind, self.co.type_home(src, ident))
        fn = _scope_of(ident)
        for b in self.co.bindings(src, fn).get(src.text(ident), []) if fn is not None else []:
            value = _unwrap(b.value) or b.value
            if value.type == "var_spec":  # `var note Note`
                return self.named(src, src.text(value.child_by_field_name("type")))
            if (
                value.type == "call_expression"
                and src.text(value.child_by_field_name("function")) == "new"
            ):  # `n := new(Note)`
                return self.named(src, src.text(value.child_by_field_name("arguments")))
        return None

    def named(self, src: _Source, type_text: str) -> str | None:
        """The record key a type as written names: `Note`, or `models.Note` qualified by its
        package where several declare one."""
        text = type_text.strip().strip("()").split(",")[0]
        kind = _last_word(text)
        return self.qualify(src, kind, self.co.kind_home(src, text)) if kind else None

    def qualify(self, src: _Source, kind: str, home: str | None = None) -> str:
        if kind not in self.dups:
            return kind
        return f"{home}.{kind}" if home else kind  # unqualified: no fields, owner untold

    def result_type(self, src: _Source, fn: Node) -> str | None:
        """The checkout record a function says it returns first: `(*Note, error)` is `Note`."""
        result = fn.child_by_field_name("result")
        kind = self.named(src, src.text(result)) if result is not None else None
        return kind if kind in self.fields else None

    def live(self, src: _Source, body: Node) -> Iterator[Node]:
        """A body's nodes, less those of a closure bound to a local the body never uses
        (`load := func() { db.First(&n, id) }`, never called): it doesn't run."""
        if body.id not in self.dead:
            self.dead[body.id] = _dead_closures(src, body)
        dead = self.dead[body.id]
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "func_literal" and n.id in dead:
                continue
            yield n
            stack.extend(reversed(n.children))

    def span(self, src: _Source, node: Node) -> CodeSpan:
        return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))


class _Taint:
    def __init__(self, names: set[str]) -> None:
        self.names = names
        self.read = False
        self.first: CodeSpan | None = None


class _Facts:
    """What a handler's reads and hops add up to."""

    def __init__(self, caller: CodeSpan | None) -> None:
        self.lookups: list[Lookup] = []
        self.caller = caller
        self.hop: CodeSpan | None = None
        self.handoff: CodeSpan | None = None

    def merge(self, inner: HandlerFacts | None, at: CodeSpan) -> None:
        if inner is None:
            return  # a checkout transform: no read
        self.hop = self.hop or at
        self.lookups += inner.lookups
        self.caller = self.caller or inner.caller
        self.handoff = self.handoff or inner.handoff


def _record_fields(co: _Checkout) -> tuple[dict[str, list[str]], set[str]]:
    """Each checkout struct type's data fields, an embedded struct's included
    (`type Doc struct{ Owned; Body string }`), by name; a name several packages declare is
    keyed `dir.Name` for each, and listed in the second value."""
    homes: dict[str, set[str]] = {}
    for where, kind in co.data_fields:
        homes.setdefault(kind, set()).add(where)
    dups = {k for k, v in homes.items() if len(v) > 1}
    fields: dict[str, set[str]] = {}
    for (where, kind), names in co.data_fields.items():
        fields.setdefault(f"{where}.{kind}" if kind in dups else kind, set()).update(names)
    embeds: dict[str, set[str]] = {}
    for src in co.sources:
        for spec in walk(src.root):
            kind = spec.child_by_field_name("type") if spec.type == "type_spec" else None
            if kind is None or kind.type != "struct_type":
                continue
            name = src.text(spec.child_by_field_name("name"))
            for decl in walk(kind):
                if decl.type == "field_declaration" and not any(
                    c.type == "field_identifier" for c in decl.named_children
                ):
                    embeds.setdefault(name, set()).add(
                        _last_word(src.text(decl.child_by_field_name("type")))
                    )
    for _ in range(_MAX_PASSES):
        grew = False
        for kind, inner in embeds.items():
            for e in inner:
                if kind in dups or e in dups:
                    continue  # which package's isn't told here
                extra = fields.get(e, set()) - fields.get(kind, set())
                if extra:
                    fields.setdefault(kind, set()).update(extra)
                    grew = True
        if not grew:
            break
    return {k: sorted(v) for k, v in fields.items()}, dups


def _words(text: str) -> list[str]:
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b|_)|[A-Z]?[a-z]+|[A-Z]+|\d+", text)
    return [p.lower() for p in parts if p.lower() not in _DROPPED_WORDS]


def _caller_key(text: str) -> bool:
    return bool(_CALLER_WORDS.match("_".join(_words(text))))


def _caller_call(name: str) -> bool:
    """`CurrentUser`, `GetUserID`, `contextGetUser`, `MustGetClaims`: named for the caller."""
    joined = "_".join(_words(name))
    return bool(_CALLER_WORDS.match(_CALLER_VERBS.sub("", joined)))


def _root_name(src: _Source, target: Node) -> str:
    """The variable an assignment target writes: `in` for `in.ID`, `n` for `n`."""
    node: Node | None = target
    while node is not None and node.type in ("selector_expression", "index_expression"):
        node = node.child_by_field_name("operand")
    return src.text(node) if node is not None and node.type == "identifier" else ""


def _dead_closures(src: _Source, body: Node) -> set[int]:
    names: dict[str, int] = {}
    for n in walk(body):
        if n.type == "identifier":
            names[src.text(n)] = names.get(src.text(n), 0) + 1
    dead = set()
    for n in walk(body):
        if n.type != "func_literal" or n.parent is None or n.parent.type != "expression_list":
            continue
        holder = n.parent.parent
        if holder is None or holder.type not in _ASSIGNS[:2]:
            continue
        values = n.parent.named_children
        left = holder.child_by_field_name("left")
        targets = left.named_children if left is not None else []
        i = values.index(n)
        if (
            i < len(targets)
            and targets[i].type == "identifier"
            and names.get(src.text(targets[i]), 0) <= 1
        ):
            dead.add(n.id)  # bound and never named again: never called, never handed on
    return dead


def _root(node: Node | None) -> Node | None:
    while node is not None and node.type == "selector_expression":
        node = node.child_by_field_name("operand")
    return node if node is not None and node.type == "identifier" else None


def _param_call(src: _Source, node: Node, fn: Node) -> bool:
    """A call of a function the enclosing one was handed (`withID(c, func(id uint) {..})`)."""
    callee = node.child_by_field_name("function") if node.type == "call_expression" else None
    return (
        callee is not None
        and callee.type == "identifier"
        and src.text(callee) in {p for p, _ in _params(src, fn)}
    )


def _any(src: _Source, node: Node, fn: Node, source: _Pred) -> bool:
    return any(source(src, n, fn) for n in _walk(node))


def _walk(node: Node) -> Iterator[Node]:
    yield node
    yield from walk(node)


def _calls(node: Node, chain: bool = False) -> Iterator[Node]:
    """The calls under a node; `chain`: only those of its own call chain."""
    if not chain:
        yield from (n for n in _walk(node) if n.type == "call_expression")
        return
    current: Node | None = node
    while current is not None and current.type == "call_expression":
        yield current
        callee = current.child_by_field_name("function")
        current = callee.child_by_field_name("operand") if callee is not None else None
        while current is not None and current.type in (
            "selector_expression", "parenthesized_expression",
        ):  # fmt: skip
            current = current.child_by_field_name("operand") or (
                current.named_children[0] if current.named_children else None
            )


def _chain_top(call: Node) -> Node:
    """`db.Where(..).First(&n)` for its `Where(..)`: the call the chain ends in."""
    top = call
    while (
        top.parent is not None
        and top.parent.type == "selector_expression"
        and top.parent.parent is not None
        and top.parent.parent.type == "call_expression"
    ):
        top = top.parent.parent
    return top


def _holder(node: Node) -> Node | None:
    """The assignment a value goes to (`note, err := store.Get(id)`)."""
    parent = node.parent
    while parent is not None and parent.type in ("expression_list", "parenthesized_expression"):
        parent = parent.parent
    return parent if parent is not None and parent.type in _ASSIGNS[:2] else None


def _scope_of(node: Node) -> Node | None:
    parent = node.parent
    while parent is not None and parent.type not in _FUNCS:
        parent = parent.parent
    return parent


def _last_word(text: str) -> str:
    words = re.findall(r"\w+", text)
    return words[-1] if words and words[-1] not in ("error", "bool", "string", "int") else ""


def own_go(rows: list[_Row], handled: dict[int, tuple[_Source, Node]], co: _Checkout) -> None:
    """Fill `ownership` on the Go rows' authenticated id routes, judging only (D35); a route
    whose handler the reader can't follow stays unclassified, an ownership coverage gap."""
    from traust_core.v1.providers.flask_ownership import own_routes

    reader = GoOwnership(co)
    facts: dict[int, HandlerFacts] = {}
    for row in rows:
        found = handled.get(id(row))
        if found is None or not (path_params(row.pattern) or row.dynamic):
            continue
        if (read := reader.facts(*found)) is not None:
            facts[id(row)] = read
    read_rows = [r for r in rows if id(r) in facts]
    own_routes(read_rows, RouteFamily.GO_HTTP, _Read(reader.fields, facts))


class _Read:
    """Each row's facts, as `own_routes` asks for them."""

    def __init__(self, fields: dict[str, list[str]], facts: dict[int, HandlerFacts]) -> None:
        self.fields, self.read = fields, facts

    def facts(self, row: _Row) -> HandlerFacts:
        return self.read[id(row)]

    def roles(self, row: _Row) -> list[str]:
        return []
