from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    use_instead: str
    calls: frozenset[str] = field(default_factory=frozenset)
    import_modules: frozenset[str] = field(default_factory=frozenset)
    env_subscript: bool = False
    json_write: bool = False
    allowed: tuple[str, ...] = ()


# AST-based, so a comment or docstring that mentions one of these never counts.
RULES: tuple[Rule, ...] = (
    Rule(
        "connect",
        "a repository on SqlUnitOfWork",
        calls=frozenset({"sqlite3.connect", "psycopg.connect"}),
        allowed=("*/repositories/*", "*/repos/*"),
    ),
    Rule(
        "subprocess",
        "ProcessRunner or a tool provider",
        import_modules=frozenset({"subprocess"}),
    ),
    Rule(
        "env",
        "a field on Config / Context",
        calls=frozenset({"os.getenv", "os.environ.get"}),
        env_subscript=True,
        allowed=("*/context/*",),
    ),
    Rule(
        "json-write",
        "ObjectStore / ArtifactPublisher",
        calls=frozenset({"json.dump"}),
        json_write=True,
        allowed=("*/repositories/*",),
    ),
    Rule("clock", "an injected Clock", calls=frozenset({"datetime.now", "datetime.utcnow"})),
    Rule(
        "http",
        "HttpClient / a service client",
        import_modules=frozenset({"requests", "httpx", "urllib.request"}),
    ),
)

_USE = {rule.kind: rule.use_instead for rule in RULES}


@dataclass(frozen=True, slots=True)
class Hit:
    path: str
    line: int
    kind: str


@dataclass(frozen=True, slots=True)
class Result:
    new: tuple[Hit, ...]
    shrinkable: tuple[tuple[str, str, int, int], ...]

    @property
    def ok(self) -> bool:
        return not self.new and not self.shrinkable


Counts = dict[str, dict[str, int]]


def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _aliases(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolve(dotted: str, aliases: dict[str, str]) -> str:
    head, _, rest = dotted.partition(".")
    if head not in aliases:
        return dotted
    return f"{aliases[head]}.{rest}" if rest else aliases[head]


def _imports(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.lineno, node.module))
            found += [(node.lineno, f"{node.module}.{a.name}") for a in node.names]
    return found


def _module_match(name: str, modules: frozenset[str]) -> bool:
    return any(name == m or name.startswith(f"{m}.") for m in modules)


def scan_source(source: str) -> list[tuple[int, str]]:
    """Return (line, kind) hits for one module's source, before path exemptions."""
    tree = ast.parse(source)
    aliases = _aliases(tree)
    hits: list[tuple[int, str]] = []

    for rule in RULES:
        if rule.import_modules:
            hits += [
                (line, rule.kind)
                for line, mod in _imports(tree)
                if _module_match(mod, rule.import_modules)
            ]

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            target = _dotted(node.value)
            if target and _resolve(target, aliases) == "os.environ":
                hits.append((node.lineno, "env"))
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"now", "utcnow"}:
            recv = _dotted(func.value)
            if recv and _resolve(recv, aliases).endswith("datetime"):
                hits.append((node.lineno, "clock"))
        if isinstance(func, ast.Attribute) and func.attr == "write_text" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Call):
                inner = _dotted(first.func)
                if inner and _resolve(inner, aliases) == "json.dumps":
                    hits.append((node.lineno, "json-write"))
        dotted = _dotted(func)
        if dotted is None:
            continue
        qname = _resolve(dotted, aliases)
        for rule in RULES:
            if qname in rule.calls:
                hits.append((node.lineno, rule.kind))
    return hits


def _exempt(path_posix: str, kind: str) -> bool:
    patterns = next((r.allowed for r in RULES if r.kind == kind), ())
    return any(fnmatch.fnmatch(path_posix, pat) for pat in patterns)


def scan(roots: Sequence[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for root in roots:
        files = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for file in files:
            if "__pycache__" in file.parts:
                continue
            posix = file.as_posix()
            for line, kind in scan_source(file.read_text()):
                if not _exempt(posix, kind):
                    hits.append(Hit(posix, line, kind))
    return hits


def counts(hits: Sequence[Hit]) -> Counts:
    out: Counts = {}
    for hit in hits:
        out.setdefault(hit.path, {}).setdefault(hit.kind, 0)
        out[hit.path][hit.kind] += 1
    return out


def compare(hits: Sequence[Hit], baseline: Counts) -> Result:
    actual = counts(hits)
    new: list[Hit] = []
    for hit in hits:
        allowed = baseline.get(hit.path, {}).get(hit.kind, 0)
        if actual[hit.path][hit.kind] > allowed:
            new.append(hit)
    shrinkable: list[tuple[str, str, int, int]] = []
    for path, kinds in baseline.items():
        for kind, base_n in kinds.items():
            now_n = actual.get(path, {}).get(kind, 0)
            if now_n < base_n:
                shrinkable.append((path, kind, base_n, now_n))
    return Result(tuple(new), tuple(sorted(shrinkable)))


def load_baseline(path: Path) -> Counts:
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def write_baseline(path: Path, hits: Sequence[Hit]) -> None:
    path.write_text(json.dumps(counts(hits), indent=2, sort_keys=True) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m traust_core.v1.checks.ratchet")
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--baseline", type=Path, default=Path(".ratchet.json"))
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    hits = scan(args.roots)

    if args.write_baseline:
        write_baseline(args.baseline, hits)
        print(f"wrote baseline {args.baseline} ({len(hits)} entries)")
        return 0

    result = compare(hits, load_baseline(args.baseline))
    for hit in result.new:
        print(f"{hit.path}:{hit.line} {hit.kind} → use {_USE[hit.kind]}")
    for path, kind, base_n, now_n in result.shrinkable:
        print(f"baseline can shrink: {path} {kind} {base_n}→{now_n}")
    if args.summary:
        print(f"{len(hits)} hits across {len(counts(hits))} files")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
