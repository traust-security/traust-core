"""An advisory's fix commits, read from its references, and the functions their diffs touch.

Facts only: nothing here classifies. A release-tag SHA in an OSV GIT range is release plumbing,
not the patch, so only commit references count.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from traust_core.v1.models.base import Model
from traust_core.v1.models.dependencies import SymbolConfidence, SymbolSource, VulnerableSymbol

# GitHub, GitLab, and the cgit/gitweb shapes C projects use (glibc, gnutls, sqlite).
_COMMIT = re.compile(
    r"(?:github|gitlab)\.com/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+?)/-?/?commit/([0-9a-f]{7,40})"
)
_CGIT = re.compile(
    r"https?://([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.~-]+)*?)[/?]?(?:[?;&](?:id|h)=)([0-9a-f]{7,40})"
)
_PULL = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(\d+)")

_JAVA = re.compile(
    r"\b(?:public|protected|private)\s+(?:static\s+|final\s+|synchronized\s+|"
    r"abstract\s+|native\s+)*[\w<>\[\],.\s?]+?\s+(\w+)\s*\("
)
_PYTHON = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")
_JS = re.compile(
    r"(?:^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\()"
    r"|(?:^\s*(\w+)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>))"
)
_C = re.compile(r"^[A-Za-z_][\w\s*]*?\b(\w+)\s*\([^;]*$")
_DECLARATIONS = {"java": _JAVA, "python": _PYTHON, "js": _JS, "c": _C}
_LANGUAGES = {
    ".java": "java",
    ".py": "python",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
}
_NOT_A_FUNCTION = frozenset({"if", "for", "while", "switch", "catch", "return", "sizeof", "else"})
_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|testdata|__tests__|spec)(/|$)", re.I)
_HUNK = re.compile(r"^@@[^@]*@@\s*(.+)$", re.M)


class FixCommit(Model):
    host: str
    repo: str
    sha: str
    url: str


def fix_commits(urls: Iterable[str]) -> tuple[list[FixCommit], list[str]]:
    """(commit references, pull-request URLs) among an advisory's reference URLs."""
    commits: dict[tuple[str, str], FixCommit] = {}
    pulls: list[str] = []
    for url in urls:
        if m := _COMMIT.search(url):
            host = "gitlab.com" if "gitlab.com" in url else "github.com"
            commits.setdefault((m[1], m[2]), FixCommit(host=host, repo=m[1], sha=m[2], url=url))
        elif m := _CGIT.search(url):
            host, _, repo = m[1].partition("/")
            commits.setdefault((m[1], m[2]), FixCommit(host=host, repo=repo, sha=m[2], url=url))
        elif _PULL.search(url):
            pulls.append(url)
    return list(commits.values()), pulls


def changed_functions(url: str, files: Sequence[tuple[str, str]]) -> list[VulnerableSymbol]:
    """Functions a commit's diff touches, package-qualified where the path allows (Java, Python):
    a changed declaration line is `high` confidence, an enclosing hunk header `medium`. Test
    paths are skipped."""
    found: dict[str, VulnerableSymbol] = {}
    for path, patch in files:
        language = _LANGUAGES.get("." + path.rsplit(".", 1)[-1] if "." in path else "")
        if (
            language is None
            or _TEST_PATH.search(path)
            or path.endswith(("Test.java", "Tests.java"))
        ):
            continue
        declaration = _DECLARATIONS[language]
        changed = [
            line[1:] for line in patch.splitlines() if line[:1] in "+-" and line[1:2] not in "+-"
        ]
        sightings = [(h, SymbolConfidence.MEDIUM) for h in _HUNK.findall(patch)] + [
            (line, SymbolConfidence.HIGH) for line in changed
        ]
        for text, confidence in sightings:
            if (m := declaration.search(text)) and (
                name := next((g for g in m.groups() if g), None)
            ):
                if name in _NOT_A_FUNCTION:
                    continue
                symbol = _qualified(path, language, name)
                if symbol not in found or confidence == SymbolConfidence.HIGH:
                    found[symbol] = VulnerableSymbol(
                        symbol=symbol,
                        source=SymbolSource.FIX_COMMIT,
                        confidence=confidence,
                        reference=url,
                        file=path,
                    )
    return list(found.values())


def _qualified(path: str, language: str, name: str) -> str:
    # javasrc2cpg names are package-qualified (org.example.Foo#bar): a bare name never matches.
    parts = path.split("/")
    if language == "java":
        owner = parts[-1].rsplit(".", 1)[0]
        anchor = next(
            (
                len(parts) - 1 - parts[::-1].index(a)
                for a in ("java", "kotlin", "scala")
                if a in parts
            ),
            None,
        )
        package = ".".join(parts[anchor + 1 : -1]) if anchor is not None else ""
        return f"{package}.{owner}#{name}" if package else f"{owner}#{name}"
    if language == "python":
        package = ".".join(p for p in parts[:-1] if p not in ("src", "lib"))
        return f"{package}.{name}" if package else name
    return name
