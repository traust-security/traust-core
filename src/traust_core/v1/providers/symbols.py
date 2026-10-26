"""Symbol definitions and textual references in a checkout.

An accelerator, not a gatekeeper: a symbol the extractors miss is not evidence it doesn't exist.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.code_facts import CodeFactDetail, CodeFactKind, SymbolFact
from traust_core.v1.models.common import CodeSpan, RepoPath
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools import ToolRequest

CTAGS_BINARIES = ("ctags", "uctags", "universal-ctags")
CONTEXT_LINES = 3

SKIP_DIRS = frozenset(
    {
        ".git",
        "vendor",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        "testdata",
        ".idea",
        ".vscode",
    }
)

LANGUAGE_BY_SUFFIX = {
    ".go": "Go",
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".sh": "Sh",
    ".bash": "Sh",
}

_TS = [
    (
        re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$]\w*)"),
        "function",
    ),
    (re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$]\w*)"), "class"),
    (re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$]\w*)"), "interface"),
    (re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$]\w*)\s*="), "type"),
    (
        re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)"
            r"\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\()"
        ),
        "function",
    ),
    (re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)\s*="), "variable"),
]

# Conservative on purpose: a missed definition costs a grep, a false one misdirects a reviewer.
_PATTERNS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "Go": [
        (re.compile(r"^func\s+([A-Za-z_]\w*)\s*[(\[]"), "func"),
        (re.compile(r"^func\s+\(\s*\w+\s+\*?([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*\("), "method"),
        (re.compile(r"^type\s+([A-Za-z_]\w*)\s"), "type"),
        (re.compile(r"^(?:var|const)\s+([A-Za-z_]\w*)\s"), "variable"),
    ],
    "Python": [
        (re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\("), "function"),
        (re.compile(r"^\s*class\s+([A-Za-z_]\w*)\s*[(:]"), "class"),
        (re.compile(r"^([A-Z_][A-Z0-9_]{2,})\s*="), "constant"),
    ],
    "TypeScript": _TS,
    "JavaScript": _TS,
    "Sh": [(re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{"), "function")],
}
_GO_GROUP = re.compile(r"^(?:var|const)\s*\($")
_GO_GROUP_MEMBER = re.compile(r"^\s+([A-Za-z_]\w*)\s*(?:=|\s)")


@dataclass(frozen=True, slots=True)
class SymbolReference:
    symbol: str
    path: str
    line: int
    context: str  # the line and CONTEXT_LINES either side, numbered


def source_files(root: Path) -> Iterator[tuple[str, Path, str]]:
    """(relative path, path, language) of each indexable file; never follows a symlink out."""
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = Path(top) / name
            language = LANGUAGE_BY_SUFFIX.get(path.suffix)
            if language and not path.is_symlink() and path.is_file():
                yield path.relative_to(root).as_posix(), path, language


def _builtin(root: Path) -> Iterator[SymbolFact]:
    for rel, path, language in source_files(root):
        in_group = False
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
            if language == "Go" and (in_group or _GO_GROUP.match(line.strip())):
                if not in_group:
                    in_group = True
                elif line.strip() == ")":
                    in_group = False
                elif m := _GO_GROUP_MEMBER.match(line):
                    yield _fact(m.group(1), rel, n, "variable", language)
                continue
            for pattern, kind in _PATTERNS[language]:
                if m := pattern.match(line):
                    if kind == "method":
                        yield _fact(m.group(1), rel, n, "type-receiver", language)
                        yield _fact(m.group(2), rel, n, "method", language)
                    else:
                        yield _fact(m.group(1), rel, n, kind, language)
                    break


def _fact(name: str, path: str, line: int, kind: str | None, language: str | None) -> SymbolFact:
    return SymbolFact(
        name=name,
        location=CodeSpan(path=RepoPath(path), line=line, symbol=name),
        kind=kind or None,
        language=language or None,
    )


class SymbolIndex:
    """Universal Ctags when installed and allowlisted (macOS's BSD ctags is not), else the builtin
    extractors."""

    kind = CodeFactKind.SYMBOL
    name = "symbol-index"

    def __init__(self, runner: ProcessRunner, clock: Clock) -> None:
        self._runner = runner
        self._clock = clock

    def check(self) -> Readiness:
        return Readiness(ready=True, detail=f"engine: {'ctags' if self._ctags() else 'builtin'}")

    def _ctags(self) -> str | None:
        for name in CTAGS_BINARIES:
            path = shutil.which(name) if self._runner.allows(name) else None
            if path and "Universal Ctags" in self._runner.run(
                [path, "--version"], check=False
            ).stdout.decode(errors="replace"):
                return path
        return None

    def enumerate(self, request: ToolRequest) -> Result[list[CodeFactDetail]]:
        root = request.checkout()
        if not root.is_dir():
            raise ValidationError(f"symbol index: workspace is not a directory: {root}")
        ctags = self._ctags()
        facts: list[CodeFactDetail] = list(
            self._from_ctags(root, ctags) if ctags else _builtin(root)
        )
        return Result(
            facts,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                source="ctags" if ctags else "builtin",
            ),
        )

    def _from_ctags(self, root: Path, ctags: str) -> Iterator[SymbolFact]:
        # --options=NONE: never load ./.ctags.d from the untrusted checkout.
        argv = [ctags, "--options=NONE", "--output-format=json", "--fields=+nKl", "-R", "-f", "-"]
        argv += [f"--exclude={d}" for d in sorted(SKIP_DIRS)]
        result = self._runner.run([*argv, "."], cwd=root, check=False)
        if result.returncode != 0:
            raise ServiceError(f"ctags exited {result.returncode} over {root}")
        for raw in result.stdout.decode(errors="replace").splitlines():
            try:
                tag = json.loads(raw)
            except json.JSONDecodeError:
                continue
            name, path, line = tag.get("name"), tag.get("path"), tag.get("line")
            if tag.get("_type") == "tag" and name and path and line:
                yield _fact(
                    name, path.removeprefix("./"), int(line), tag.get("kind"), tag.get("language")
                )

    def references(self, root: Path, names: Collection[str]) -> list[SymbolReference]:
        """Word-boundary mentions of each name in the indexable files, comments and strings
        included; one pass over the checkout."""
        if not names:
            return []
        pattern = re.compile(rf"\b(?:{'|'.join(map(re.escape, sorted(names)))})\b")
        found = []
        for rel, path, _ in source_files(root):
            lines = path.read_text(errors="replace").splitlines()
            for i, line in enumerate(lines):
                for name in dict.fromkeys(pattern.findall(line)):
                    found.append(SymbolReference(name, rel, i + 1, _around(lines, i)))
        return found


def _around(lines: list[str], i: int) -> str:
    lo, hi = max(0, i - CONTEXT_LINES), min(len(lines), i + CONTEXT_LINES + 1)
    return "\n".join(f"{n + 1}: {lines[n]}" for n in range(lo, hi))
