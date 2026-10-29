"""tonic (Rust gRPC) servers for the gRPC service x interceptor matrix: each `Server::builder()`
chain, its tower layers, the services it adds and their own interceptors (`with_interceptor`,
`InterceptedService`), parsed with tree-sitter."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traust_core.v1.models.code_facts import (
    GrpcCallKind,
    GrpcExposure,
    GrpcExposureKind,
    GrpcFramework,
    GrpcInterceptor,
    GrpcServerSite,
    GrpcService,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.rust_routes import (
    _args,
    _callee,
    _chain,
    _Crate,
    _is_guard,
    _last,
    _names,
    _outermost,
    _Source,
    _unwrap,
)
from traust_core.v1.providers.syntax import Node, walk
from traust_core.v1.providers.syntax import rust_parser as parser
from traust_core.v1.providers.tree import TreeFile

TONIC_USE = re.compile(r"\btonic::")
_BUILDER = re.compile(r"(?:^|::)Server::builder$")
_TEST_DIR_PARTS = {"tests", "test", "examples", "example", "benches"}
_ADDS = ("add_service", "add_optional_service")
_UNGUARDED = "no auth-shaped layer or interceptor on the server or service"
_TLS = "TLS configured: whether it verifies client certificates is a judgement"


@dataclass
class TonicServices:
    servers: list[GrpcServerSite] = field(default_factory=list)
    services: list[GrpcService] = field(default_factory=list)
    exposures: list[GrpcExposure] = field(default_factory=list)
    evidence: str | None = None  # a file using tonic
    parsed: bool = True


def _span(src: _Source, node: Node) -> CodeSpan:
    return CodeSpan(path=RepoPath(src.file.rel), line=src.line(node))


def _intercepts(src: _Source, expr: Node) -> list[GrpcInterceptor]:
    """A guard-shaped or other interceptor, for both unary and streaming calls."""
    guard = bool(_names(src, expr)[0]) or _is_guard(src.text(expr))
    text, at = src.text(expr)[:200], _span(src, expr)
    return [
        GrpcInterceptor(kind=kind, expr=text, location=at, guard=guard)
        for kind in (GrpcCallKind.UNARY, GrpcCallKind.STREAM)
    ]


def _methods(crate: _Crate) -> dict[str, tuple[list[str], list[str]]]:
    """Each service trait's implemented methods, and which of them stream."""
    found: dict[str, tuple[list[str], list[str]]] = {}
    for src in crate.sources:
        for n in walk(src.root):
            if n.type != "impl_item" or n.child_by_field_name("trait") is None:
                continue
            trait = _last(src.text(n.child_by_field_name("trait")))
            body = n.child_by_field_name("body")
            fns = [f for f in (body.named_children if body else []) if f.type == "function_item"]
            names = [src.text(f.child_by_field_name("name")) for f in fns]
            streams = [
                src.text(f.child_by_field_name("name"))
                for f in fns
                if "Streaming<" in src.text(f.child_by_field_name("parameters"))
                or "Stream" in src.text(f.child_by_field_name("return_type"))
            ]
            found.setdefault(trait, (names, streams))
    return found


def _service(
    crate: _Crate, src: _Source, expr: Node | None, seen: int = 0
) -> tuple[str, str, list[GrpcInterceptor]] | None:
    """(generated server type, implementation, per-service interceptors) an added service is."""
    expr = _unwrap(expr)
    if expr is None or seen > 4:
        return None
    if expr.type == "identifier":
        return _service(crate, src, crate.binding(src, expr, src.text(expr)), seen + 1)
    callee = _callee(src, expr)
    args = _args(expr) if expr.type == "call_expression" else []
    if callee.endswith("InterceptedService::new") and len(args) == 2:
        inner = _service(crate, src, args[0], seen + 1)
        if inner is not None:
            return inner[0], inner[1], [*inner[2], *_intercepts(src, args[1])]
    if callee.endswith("::with_interceptor") and len(args) == 2:
        return callee.split("::")[-2], src.text(args[0])[:200], _intercepts(src, args[1])
    if callee.endswith(("::new", "::from_arc")) and args:
        return callee.split("::")[-2], src.text(args[0])[:200], []
    if _last(callee) == "enable" and args:  # tonic_web::enable(svc)
        return _service(crate, src, args[0], seen + 1)
    return None


def _exposure_kind(src: _Source, expr: Node, crate: _Crate) -> GrpcExposureKind | None:
    expr = _unwrap(expr)
    value = crate.binding(src, expr, src.text(expr)) if expr and expr.type == "identifier" else expr
    text = src.text(value) if value is not None else ""
    if "tonic_reflection" in text or "reflection" in src.text(expr).lower():
        return GrpcExposureKind.REFLECTION
    if "tonic_health" in text or "health" in src.text(expr).lower():
        return GrpcExposureKind.HEALTH
    return None


def tonic_services(files: list[TreeFile]) -> TonicServices:
    rust = [f for f in files if f.path.suffix == ".rs"]
    evidence = next((f.rel for f in rust if TONIC_USE.search(f.text)), None)
    if evidence is None:
        return TonicServices()
    available = parser()
    if available is None:
        return TonicServices(evidence=evidence, parsed=False)
    sources = []
    for f in rust:
        data = f.text.encode("utf-8")
        sources.append(_Source(f, available.parse(data).root_node, data))
    crate = _Crate(sources)
    methods = _methods(crate)
    found = TonicServices(evidence=evidence)
    for src in sources:
        test = any(p in _TEST_DIR_PARTS for p in src.file.parts[:-1])
        for n in walk(src.root):
            if n.type != "call_expression" or not _BUILDER.search(_callee(src, n)):
                continue
            outer = _outermost(n)
            _, steps = _chain(src, outer)
            layers = [a[0] for name, a in steps if name == "layer" and a]
            interceptors = [i for layer in layers for i in _intercepts(src, layer)]
            guarded = any(i.guard for i in interceptors)
            site = GrpcServerSite(
                location=_span(src, n),
                interceptors=tuple(interceptors),
                unary_guarded=guarded,
                stream_guarded=guarded,
                credentials=tuple(name for name, _ in steps if name == "tls_config"),
                test_path=test,
            )
            found.servers.append(site)
            for name, a in steps:
                if name not in _ADDS or not a:
                    continue
                kind = _exposure_kind(src, a[0], crate)
                added = _service(crate, src, a[0])
                if kind is not None and (added is None or not added[0].endswith("Server")):
                    found.exposures.append(
                        GrpcExposure(
                            kind=kind,
                            registration=_span(src, a[0]),
                            server="Server::builder",
                            server_sites=(site.location,),
                            guarded=guarded,
                            test_path=test,
                        )
                    )
                    continue
                if added is None:
                    continue
                server_type, implementation, own = added
                service = server_type.removesuffix("Server")
                names, streams = methods.get(service, ([], []))
                protected = guarded or any(i.guard for i in own)
                reasons = [] if protected else [_UNGUARDED]
                if not protected and site.credentials:
                    reasons.append(_TLS)
                if service not in methods:
                    reasons.append("service trait implementation not found: methods unknown")
                found.services.append(
                    GrpcService(
                        service=service,
                        registration=_span(src, a[0]),
                        implementation=implementation,
                        server="Server::builder",
                        server_sites=(site.location,),
                        methods=tuple(names),
                        streams=tuple(streams),
                        methods_known=service in methods,
                        judgement_required=not protected,
                        judgement_reasons=tuple(reasons),
                        test_path=test,
                        framework=GrpcFramework.TONIC,
                        interceptors=tuple(own),
                    )
                )
    return found
