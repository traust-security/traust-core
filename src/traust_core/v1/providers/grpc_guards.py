"""gRPC service x interceptor matrix: a checkout's Go `grpc.NewServer` calls, the server
interceptors reaching each, the services registered on them and their methods, matched by name
and over-inclusive; Rust tonic servers come from `tonic_services`. Target code is read, never
built. gRPC servers in other languages are coverage gaps."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from traust_core.v1.models.code_facts import (
    CodeFactDetail,
    CodeFactKind,
    CoverageGap,
    GrpcCallKind,
    GrpcExposure,
    GrpcExposureKind,
    GrpcFramework,
    GrpcGuardFact,
    GrpcInterceptor,
    GrpcMethodReference,
    GrpcServerSite,
    GrpcService,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.route_guards import GUARD_RX, UNGUARD_RX
from traust_core.v1.providers.syntax import grammar_missing
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

GRPC_IMPORT = "google.golang.org/grpc"
# gRPC-only guard words on top of the route guards': argo's `gatekeeper`, `authz`/`authn` filters.
_GRPC_GUARD_EXTRA = re.compile(r"(?i)(gatekeep|authz|authn|authfunc|mtls)")
_TEST_NAME = re.compile(r"(^|[._-])(test|spec|mock|fixture|fake)s?([._-]|$)")
_TEST_DIR_PARTS = {"test", "tests", "testing", "testutil", "fixtures", "examples", "example",
                   "samples", "sample", "e2e"}  # fmt: skip

_IMPORT_ALIAS = re.compile(
    r'(?m)^\s*(?:import\s+)?(?P<alias>(?!import\b)[A-Za-z_]\w*)\s+"google\.golang\.org/grpc"'
)
_REGISTER = re.compile(
    r"(?<![\w.])(?:(?P<pkg>[A-Za-z_]\w*)\.)?Register(?P<name>\w+?)Server\(\s*(?P<server>[\w.]+)\s*,"
    r"\s*(?P<impl>[^)\n]{1,200}?)\s*\)"
)
_FUNC_DEF = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?$")
_REFLECTION = re.compile(r"(?<![\w.])reflection\.Register\(\s*(?P<server>[\w.]+)\s*\)")
_CHANNELZ = re.compile(
    r"(?<![\w.])\w+\.RegisterChannelzServiceToServer\(\s*(?P<server>[\w.]+)\s*\)"
)
_ADMIN = re.compile(r"(?<![\w.])admin\.Register\(\s*(?P<server>[\w.]+)\s*\)")
_HEALTH_NAMES = {"Health"}
_GATEWAY_SUFFIX = "Handler"
_SERVICE_NAME = re.compile(r'ServiceName:\s*"(?P<name>[\w.]+)"')
_METHOD_NAME = re.compile(r'MethodName:\s*"(?P<name>\w+)"')
_STREAM_NAME = re.compile(r'StreamName:\s*"(?P<name>\w+)"')
_FULL_METHOD = re.compile(r'"(?P<method>/[A-Za-z_][\w.]*\.[A-Za-z_]\w*/[A-Za-z_]\w*)"')
_MENTIONS = re.compile(r"Register\w+Server\(|ServiceName:")
_GENERATED = re.compile(r"(?m)^// Code generated .* DO NOT EDIT\.$")

OTHER_LANGUAGES = (
    (
        "python-grpc",
        (".py",),
        re.compile(r"\bgrpc\.(?:aio\.)?server\(|add_\w+Servicer_to_server\("),
    ),
    (
        "java-grpc",
        (".java", ".kt"),
        re.compile(r"\b(?:Netty)?ServerBuilder\.forPort\(|\bGrpcService\b"),
    ),
    ("node-grpc", (".js", ".ts"), re.compile(r"new\s+grpc\.Server\(|@grpc/grpc-js")),
)


def mask_comments(text: str) -> str:
    """Go source with comments blanked (newlines kept), so offsets and line numbers still hold."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            end = i + 1
            while end < n and text[end] != c and not (c != "`" and text[end] == "\n"):
                end += 2 if c != "`" and text[end] == "\\" else 1
            i = end + 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out[i:end] = " " * (end - i)
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out[i:end] = [ch if ch == "\n" else " " for ch in text[i:end]]
            i = end
        else:
            i += 1
    return "".join(out)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _call_args(text: str, open_paren: int) -> tuple[str, int] | None:
    """The text inside the parentheses opening at `open_paren`, and the offset after the close."""
    depth, i = 0, open_paren
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i], i + 1
        elif c in "\"'`":
            end = text.find(c, i + 1)
            if end < 0:
                return None
            i = end
        i += 1
    return None


def _split_top(args: str) -> list[str]:
    items, depth, start = [], 0, 0
    for i, c in enumerate(args):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            items.append(args[start:i])
            start = i + 1
    items.append(args[start:])
    return [" ".join(x.split()) for x in items if x.strip()]


def _is_guard(expr: str) -> bool:
    return bool(GUARD_RX.search(expr) or _GRPC_GUARD_EXTRA.search(expr)) and not UNGUARD_RX.search(
        expr
    )


@dataclass
class _Source:
    file: TreeFile
    alias: str
    test_path: bool
    text: str

    def span(self, offset: int) -> CodeSpan:
        return CodeSpan(path=RepoPath(self.file.rel), line=_line(self.text, offset))


def _wrappers(alias: str) -> list[tuple[re.Pattern[str], GrpcCallKind]]:
    a = re.escape(alias)
    out = []
    for kind, word in ((GrpcCallKind.UNARY, "Unary"), (GrpcCallKind.STREAM, "Stream")):
        out += [
            (re.compile(rf"(?<![\w.]){a}\.(?:Chain)?{word}Interceptor\("), kind),
            (re.compile(rf"\b\w+\.(?:Chain{word}Server|With{word}ServerChain)\("), kind),
            (re.compile(rf"\[\]{a}\.{word}ServerInterceptor\s*\{{"), kind),
        ]
    return out


_WRAPPER_NAME = re.compile(
    r"(?:^|\.)(?:Chain(?:Unary|Stream)(?:Interceptor|Server)|(?:Unary|Stream)Interceptor|"
    r"With(?:Unary|Stream)ServerChain)$"
)


def _interceptors(src: _Source, start: int, end: int) -> list[GrpcInterceptor]:
    """Server interceptors in `text[start:end]`, chains flattened to their members."""
    text = src.text
    found: dict[tuple[GrpcCallKind, str, int], GrpcInterceptor] = {}
    for rx, kind in _wrappers(src.alias):
        for m in rx.finditer(text, start, end):
            parsed = _call_args(text, m.end() - 1)
            if parsed is None:
                continue
            for item in _split_top(parsed[0]):
                head = item.split("(", 1)[0]
                if _WRAPPER_NAME.search(head) or item.endswith("..."):
                    continue  # a nested chain or a spread slice: its members are found directly
                key = (kind, item, m.start())
                found.setdefault(
                    key,
                    GrpcInterceptor(
                        kind=kind,
                        expr=item[:200],
                        location=src.span(m.start()),
                        guard=_is_guard(item),
                    ),
                )
    return list(found.values())


def _server_sites(src: _Source) -> list[tuple[GrpcServerSite, str | None]]:
    text = src.text
    file_level = _interceptors(src, 0, len(text))
    sites = []
    rx = re.compile(rf"(?:(?P<var>[\w.]+)\s*:?=\s*)?(?<![\w.]){re.escape(src.alias)}\.NewServer\(")
    for m in rx.finditer(text):
        parsed = _call_args(text, m.end() - 1)
        args = parsed[0] if parsed else ""
        inline = _interceptors(src, m.end() - 1, parsed[1] if parsed else m.end())
        variadic = "..." in args
        chosen: list[GrpcInterceptor] = []
        for i in inline + (file_level if variadic else []):
            if all((i.kind, i.expr) != (c.kind, c.expr) for c in chosen):
                chosen.append(i)
        creds_rx = re.compile(rf"(?<![\w.]){re.escape(src.alias)}\.Creds\(")
        scope = (0, len(text)) if variadic else (m.end() - 1, parsed[1] if parsed else m.end())
        creds = []
        for c in creds_rx.finditer(text, *scope):
            got = _call_args(text, c.end() - 1)
            if got and " ".join(got[0].split()) not in creds:
                creds.append(" ".join(got[0].split())[:200])
        site = GrpcServerSite(
            location=src.span(m.start("var") if m.group("var") else m.start()),
            variable=m.group("var"),
            interceptors=tuple(chosen),
            unary_guarded=any(i.guard and i.kind is GrpcCallKind.UNARY for i in chosen),
            stream_guarded=any(i.guard and i.kind is GrpcCallKind.STREAM for i in chosen),
            options_variadic=variadic,
            credentials=tuple(creds),
            test_path=src.test_path,
        )
        sites.append((site, m.group("var")))
    return sites


def _descriptors(sources: list[_Source]) -> dict[str, list[tuple[str, list[str], list[str]]]]:
    """Short service name -> [(full name, methods, streams)] from generated service descriptors."""
    by_short: dict[str, list[tuple[str, list[str], list[str]]]] = defaultdict(list)
    for src in sources:
        text = src.text
        for m in _SERVICE_NAME.finditer(text):
            body_end = text.find("\n}", m.end())
            body = text[m.end() : body_end if body_end > 0 else len(text)]
            full = m.group("name")
            methods = [x.group("name") for x in _METHOD_NAME.finditer(body)]
            streams = [x.group("name") for x in _STREAM_NAME.finditer(body)]
            entry = (full, methods, streams)
            if entry not in by_short[full.rsplit(".", 1)[-1]]:
                by_short[full.rsplit(".", 1)[-1]].append(entry)
    return by_short


def _test_path(f: TreeFile) -> bool:
    return bool(_TEST_DIR_PARTS & set(f.parts[:-1])) or bool(_TEST_NAME.search(f.name.lower()))


def _reasons(
    sites: list[GrpcServerSite], methods: list[str], streams: list[str], known: bool
) -> list[str]:
    if not sites:
        return ["server built outside this file: interceptors not resolved"]
    reasons = []
    if (methods or not known) and not all(s.unary_guarded for s in sites):
        reasons.append("no auth-shaped unary interceptor on a server it is registered on")
    if (streams or not known) and not all(s.stream_guarded for s in sites):
        reasons.append("no auth-shaped stream interceptor on a server it is registered on")
    if reasons and any(s.credentials for s in sites):
        reasons.append(
            "transport credentials set: whether they verify client certificates is a judgement"
        )
    if not known:
        reasons.append("service descriptor not found: methods unknown")
    return reasons


def grpc_guards(files: list[TreeFile]) -> GrpcGuardFact:
    """The matrix over a checkout's Go files; services needing judgement first."""
    go = [f for f in files if f.path.suffix == ".go" and not f.name.endswith("_test.go")]
    sources = []
    for f in go:
        if GRPC_IMPORT not in f.text and not _MENTIONS.search(f.text):
            continue
        m = _IMPORT_ALIAS.search(f.text)
        alias = m.group("alias") if m else "grpc"
        sources.append(_Source(f, alias, _test_path(f), mask_comments(f.text)))
    descriptors = _descriptors(sources)
    servers: list[GrpcServerSite] = []
    services: list[GrpcService] = []
    exposures: list[GrpcExposure] = []
    references: list[GrpcMethodReference] = []
    for src in sources:
        text = src.text
        generated = bool(_GENERATED.search(src.file.text))
        site_vars = _server_sites(src) if not generated else []
        servers += [s for s, _ in site_vars]
        by_var: dict[str, list[GrpcServerSite]] = defaultdict(list)
        for site, var in site_vars:
            if var:
                by_var[var].append(site)
        if generated:
            continue
        for m in _REGISTER.finditer(text):
            if _FUNC_DEF.search(text, max(0, m.start() - 80), m.start()) or m.group(
                "name"
            ).endswith(_GATEWAY_SUFFIX):
                continue
            name, server = m.group("name"), m.group("server")
            sites = by_var.get(server, [])
            spans = tuple(s.location for s in sites)
            if name in _HEALTH_NAMES:
                exposures.append(_exposure(GrpcExposureKind.HEALTH, src, m, sites))
                continue
            candidates = descriptors.get(name, [])
            known = len(candidates) == 1
            methods = candidates[0][1] if known else []
            streams = candidates[0][2] if known else []
            reasons = _reasons(sites, methods, streams, known)
            services.append(
                GrpcService(
                    service=name,
                    full_names=tuple(c[0] for c in candidates),
                    registration=src.span(m.start()),
                    implementation=" ".join(m.group("impl").split())[:200],
                    server=server,
                    server_sites=spans,
                    methods=tuple(methods),
                    streams=tuple(streams),
                    methods_known=known,
                    judgement_required=bool(
                        not sites or any(r.startswith("no auth") for r in reasons)
                    ),
                    judgement_reasons=tuple(reasons),
                    test_path=src.test_path,
                )
            )
        for kind, rx in (
            (GrpcExposureKind.REFLECTION, _REFLECTION),
            (GrpcExposureKind.CHANNELZ, _CHANNELZ),
            (GrpcExposureKind.ADMIN, _ADMIN),
        ):
            for m in rx.finditer(text):
                exposures.append(_exposure(kind, src, m, by_var.get(m.group("server"), [])))
        if site_vars or "UnaryServerInfo" in text or "StreamServerInfo" in text:
            references += [
                GrpcMethodReference(method=m.group("method"), location=src.span(m.start()))
                for m in _FULL_METHOD.finditer(text)
            ]
    from traust_core.v1.providers.tonic_services import tonic_services  # it builds on this

    tonic = tonic_services(files)
    servers += tonic.servers
    services += tonic.services
    exposures += tonic.exposures
    services.sort(
        key=lambda s: (
            not s.judgement_required,
            s.test_path,
            s.registration.path,
            s.registration.line or 0,
        )
    )
    gaps = _gaps(files, servers, services)
    if tonic.evidence and not tonic.parsed:
        gaps.append(
            CoverageGap(
                system=GrpcFramework.TONIC,
                reason=f"tonic used but {grammar_missing('Rust', 'tree-sitter-rust')} — its "
                "service x interceptor matrix is UNENUMERATED",
                evidence=RepoPath(tonic.evidence),
            )
        )
    elif tonic.evidence and not tonic.servers and not tonic.services:
        gaps.append(
            CoverageGap(
                system=GrpcFramework.TONIC,
                reason="tonic used but no Server::builder chain found — its service x "
                "interceptor matrix is UNENUMERATED",
                evidence=RepoPath(tonic.evidence),
            )
        )
    return GrpcGuardFact(
        servers=tuple(servers),
        services=tuple(services),
        exposures=tuple(exposures),
        method_references=tuple(references),
        coverage_gaps=tuple(gaps),
    )


def _exposure(
    kind: GrpcExposureKind, src: _Source, m: re.Match[str], sites: list[GrpcServerSite]
) -> GrpcExposure:
    return GrpcExposure(
        kind=kind,
        registration=src.span(m.start()),
        server=m.group("server"),
        server_sites=tuple(s.location for s in sites),
        guarded=all(s.unary_guarded for s in sites) if sites else None,
        test_path=src.test_path,
    )


def _gaps(
    files: list[TreeFile], servers: list[GrpcServerSite], services: list[GrpcService]
) -> list[CoverageGap]:
    gaps = []
    hits: dict[str, str] = {}
    for f in files:
        for system, suffixes, rx in OTHER_LANGUAGES:
            if system not in hits and f.path.suffix in suffixes and rx.search(f.text):
                hits[system] = f.rel
    gaps += [
        CoverageGap(
            system=system,
            reason=f"{system} servers detected but this enumerator covers only Go gRPC — this "
            "family's service x interceptor matrix is UNENUMERATED",
            evidence=RepoPath(path),
        )
        for system, path in sorted(hits.items())
    ]
    if any(s.framework is GrpcFramework.GO for s in services) and not any(
        s.location.path.endswith(".go") for s in servers
    ):
        gaps.append(
            CoverageGap(
                system="go-grpc",
                reason="services are registered but no grpc.NewServer call was found — the "
                "servers' interceptors are UNENUMERATED",
                count=len(services),
            )
        )
    return gaps


class GrpcGuardMatrix:
    kind = CodeFactKind.GRPC_GUARD
    name = "grpc-guards"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        fact = grpc_guards(tree_files(request.checkout()))
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))
