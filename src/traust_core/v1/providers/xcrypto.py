"""golang.org/x/crypto usage in a checkout: first-party import lines and go.mod refs (vendored trees
skipped), and on request what each main package reaches through the go-callgraph tool, with a
witness chain. Raw signal for the x/crypto tracker, never a verdict."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping
from typing import Any

from traust_core.v1.errors import ConfigError, IntegrityError, ValidationError
from traust_core.v1.models.code_facts import (
    GO_CALLGRAPH,
    CodeFactDetail,
    CodeFactKind,
    GoCallgraph,
    GoEntrypoint,
    XcryptoEntrypoint,
    XcryptoImport,
    XcryptoModule,
    XcryptoReachable,
    XcryptoReplace,
    XcryptoUsageFact,
)
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, ProviderRegistry, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolProvider, ToolRequest
from traust_core.v1.providers.tree import TreeFile, tree_files

XCRYPTO = "golang.org/x/crypto"
_SKIP = frozenset({"vendor", ".git", ".gomodcache", "node_modules"})
_IMPORT = re.compile(r'"golang\.org/x/crypto(?:/([a-zA-Z0-9_/]+))?"')
_REQUIRE = re.compile(r"^\s*(?:require\s+)?golang\.org/x/crypto\s+(v[\w.\-+]+)", re.M)
_REPLACE = re.compile(r"^\s*(?:replace\s+)?golang\.org/x/crypto\s*=>\s*(\S+)\s*(v[\w.\-+]+)?", re.M)


def package_of(function: str) -> str | None:
    """The x/crypto package of a callgraph function name (`pkg.F`, `(*pkg.T).M`), else None."""
    name = function.lstrip("(*")
    if not name.startswith(XCRYPTO + "/"):
        return None
    return f"{XCRYPTO}/{name.removeprefix(XCRYPTO + '/').split('.')[0]}"


def _imports(files: Iterable[TreeFile]) -> list[XcryptoImport]:
    return [
        XcryptoImport(
            package=f"{XCRYPTO}/{m.group(1) or ''}".rstrip("/"),
            location=CodeSpan(path=RepoPath(f.rel), line=lineno),
        )
        for f in files
        if f.name.endswith(".go")
        for lineno, line in enumerate(f.text.splitlines(), 1)
        if (m := _IMPORT.search(line))
    ]


def _modules(files: Iterable[TreeFile]) -> list[XcryptoModule]:
    found = []
    for f in files:
        if f.name != "go.mod":
            continue
        require, replace = _REQUIRE.findall(f.text), _REPLACE.findall(f.text)
        if require or replace:
            found.append(
                XcryptoModule(
                    path=RepoPath(f.rel),
                    require=tuple(sorted(set(require))),
                    replace=tuple(XcryptoReplace(target=t, version=v or None) for t, v in replace),
                )
            )
    return found


def _parents(graph: Mapping[str, list[str]], root: str) -> dict[str, str | None]:
    """Breadth-first from `root`: each node's caller on a shortest chain."""
    parent: dict[str, str | None] = {root: None} if root in graph else {}
    queue = deque(parent)
    while queue:
        node = queue.popleft()
        for callee in graph.get(node, ()):
            if callee not in parent:
                parent[callee] = node
                queue.append(callee)
    return parent


def _chain(parent: Mapping[str, str | None], target: str) -> tuple[str, ...]:
    if target not in parent:
        return ()
    path = [target]
    while (up := parent[path[-1]]) is not None:
        path.append(up)
    return tuple(reversed(path))


def reachable(entry: GoEntrypoint) -> XcryptoEntrypoint:
    """The x/crypto functions in one main package's call graph, each with a witness chain."""
    if entry.error is not None:
        return XcryptoEntrypoint(
            entrypoint=entry.entrypoint, package=entry.package, error=entry.error
        )
    graph: dict[str, list[str]] = {}
    for caller, callee in entry.edges:
        graph.setdefault(caller, []).append(callee)
    nodes = {n for edge in entry.edges for n in edge}
    roots = [_parents(graph, f"{entry.package}.{root}") for root in ("main", "init")]
    return XcryptoEntrypoint(
        entrypoint=entry.entrypoint,
        package=entry.package,
        reachable=tuple(
            XcryptoReachable(
                function=fn,
                package=pkg,
                witness=next((c for p in roots if (c := _chain(p, fn))), ()),
            )
            for fn in sorted(nodes)
            if (pkg := package_of(fn)) is not None
        ),
    )


class XcryptoUsage:
    kind = CodeFactKind.XCRYPTO
    name = "xcrypto-usage"

    def __init__(self, clock: Clock, tools: ProviderRegistry[ToolProvider[Any]]) -> None:
        self._clock = clock
        self._tools = tools

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        """`params.callgraph` true also runs the go-callgraph tool; ConfigError when it can't."""
        callgraph = request.params.get("callgraph", False)
        if not isinstance(callgraph, bool):
            raise ValidationError(f"params.callgraph is a boolean, not {callgraph!r}")
        files = tree_files(request.checkout(), _SKIP)
        fact = XcryptoUsageFact(
            imports=tuple(_imports(files)),
            modules=tuple(_modules(files)),
            callgraph=self._callgraph(request) if callgraph else None,
        )
        return Result([fact], Acquisition(provider=self.name, acquired_at=self._clock.now()))

    def _callgraph(self, request: ToolRequest) -> tuple[XcryptoEntrypoint, ...]:
        tool = self._tools.get(GO_CALLGRAPH)
        if not (readiness := tool.check()).ready:
            raise ConfigError(f"{GO_CALLGRAPH} is not ready: {readiness.detail}")
        found = tool.acquire(ToolRequest(workspace=request.checkout())).data
        if not isinstance(found, GoCallgraph):
            raise IntegrityError(f"{GO_CALLGRAPH} returned {type(found).__name__}, not GoCallgraph")
        return tuple(reachable(e) for e in found.entrypoints)
