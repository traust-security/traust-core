"""Sanitizer discovery: Python functions shaped like a sanitizer (by name) that take one required
value. Static only; probing them executes target code, which the probe tool does, not core."""

from __future__ import annotations

import ast
import re

from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind, SanitizerFact
from traust_core.v1.models.common import RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools import ToolRequest
from traust_core.v1.providers.tree import SKIP_DIRS, TreeFile, tree_files

SANITIZER_NAME_RX = re.compile(
    r"(?i)^_?(sanitize|sanitise|escape|clean|scrub|strip|filter|"
    r"validate|normalize|normalise|safe|quote|redact|mask)"
)
_TEST_NAME = re.compile(r"(^|[._-])(test|spec|mock|fixture|conftest)s?([._-]|$)")
_SKIP = SKIP_DIRS | {"site-packages"}


def _candidates(f: TreeFile) -> list[SanitizerFact]:
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not SANITIZER_NAME_RX.match(node.name):
            continue
        positional = node.args.args + node.args.posonlyargs
        names = [a.arg for a in positional]
        bound = bool(names) and names[0] in ("self", "cls")
        names = names[1:] if bound else names
        if names and len(names) - len(node.args.defaults) <= 1:
            found.append(
                SanitizerFact(
                    function=node.name,
                    path=RepoPath(f.rel),
                    line=node.lineno,
                    arg=names[0],
                    is_method=bound,
                )
            )
    return found


def sanitizers(files: list[TreeFile]) -> list[SanitizerFact]:
    return [
        c
        for f in files
        if f.path.suffix == ".py" and not _TEST_NAME.search(f.name.lower())
        for c in _candidates(f)
    ]


class SanitizerDiscovery:
    kind = CodeFactKind.SANITIZER
    name = "sanitizer-discovery"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        facts: list[CodeFactDetail] = list(sanitizers(tree_files(request.workspace, _SKIP)))
        return Result(facts, Acquisition(provider=self.name, acquired_at=self._clock.now()))
