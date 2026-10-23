"""Drift ratchet over common hand-wiring forms (AST-based).

A finite checker, not a prohibition: it catches the frequent shapes -
direct calls, keyword arguments, simple concatenation - and the baseline
only shrinks when CI passes --reference (the base branch's baseline).
Novel forms are caught by review; add them here when they appear.
"""

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
    import_except: frozenset[str] = field(default_factory=frozenset)
    # (path glob, modules): imports of these modules are fine only in files matching the glob
    import_except_in: tuple[tuple[str, frozenset[str]], ...] = ()
    literal_suffixes: tuple[str, ...] = ()
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
        calls=frozenset({"os.getenv", "os.environ.get", "os.environ.copy"}),
        allowed=("*/context/*",),
    ),
    Rule(
        "json-write",
        "ObjectStore / ArtifactPublisher",
        calls=frozenset({"json.dump"}),
        # the ratchet writes its own baseline; that is the sanctioned writer
        allowed=("*/repositories/*", "*/checks/ratchet.py"),
    ),
    Rule("clock", "an injected Clock", calls=frozenset({"datetime.now", "datetime.utcnow"})),
    Rule(
        "http",
        "a core provider (SourceProvider, FeedProvider, tool provider)",
        import_modules=frozenset({"requests", "httpx", "urllib.request"}),
        # Outbound HTTP lives in providers; add the REST adapter path when it lands.
        allowed=("*/providers/*",),
    ),
)

_SERVICES = "core's domain services through Context.services()"

# Repos that consume traust-core (traust, traust-engine): `--rules consumer`.
CONSUMER_RULES: tuple[Rule, ...] = (
    Rule("contracts", _SERVICES, import_modules=frozenset({"traust_contracts"})),
    Rule(
        "core-internal",
        _SERVICES,
        import_modules=frozenset({"traust_core"}),
        import_except=frozenset(
            {"traust_core.v1.context", "traust_core.v1.models", "traust_core.v1.errors"}
        ),
        # the engine's tool adapters implement core's provider protocols (ToolProvider)
        import_except_in=(("*/traust_engine/adapters/*", frozenset({"traust_core.v1.providers"})),),
    ),
    Rule("database", _SERVICES, import_modules=frozenset({"sqlite3", "sqlalchemy", "psycopg"})),
    Rule(
        "engine-internal",
        _SERVICES,
        import_modules=frozenset({"traust_engine"}),
        import_except=frozenset({"traust_engine.adapters"}),
        # the engine's own modules import each other
        allowed=("*/traust_engine/*",),
    ),
    Rule(
        "state-file",
        _SERVICES,
        literal_suffixes=(
            "findings.db",
            "portfolio-graph.db",
            "repo-graph.json",
            "-findings-layer.json",
            "-findings-current.json",
        ),
    ),
)

RULE_SETS: dict[str, tuple[Rule, ...]] = {"core": RULES, "consumer": CONSUMER_RULES}

_USE = {rule.kind: rule.use_instead for rules in RULE_SETS.values() for rule in rules}


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


def _imports(tree: ast.AST) -> list[tuple[int, list[str]]]:
    """One entry per import statement, with every name it binds."""
    found: list[tuple[int, list[str]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.append((node.lineno, [a.name for a in node.names]))
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.append((node.lineno, [f"{node.module}.{a.name}" for a in node.names]))
    return found


def _module_match(name: str, modules: frozenset[str]) -> bool:
    return any(name == m or name.startswith(f"{m}.") for m in modules)


def _import_hit(names: list[str], rule: Rule, path: str) -> bool:
    excepted = rule.import_except.union(
        *(modules for glob, modules in rule.import_except_in if fnmatch.fnmatch(path, glob))
    )
    return any(
        _module_match(n, rule.import_modules) and not _module_match(n, excepted) for n in names
    )


def _docstrings(tree: ast.AST) -> set[int]:
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }


def _dumps_inside(expr: ast.expr, aliases: dict[str, str]) -> bool:
    """json.dumps as the written value, alone or concatenated (x + "\n")."""
    if isinstance(expr, ast.Call):
        inner = _dotted(expr.func)
        return inner is not None and _resolve(inner, aliases) == "json.dumps"
    if isinstance(expr, ast.BinOp):
        return _dumps_inside(expr.left, aliases) or _dumps_inside(expr.right, aliases)
    return False


def scan_source(
    source: str, rules: Sequence[Rule] = RULES, path: str = ""
) -> list[tuple[int, str]]:
    """Return (line, kind) hits for one module's source (at `path`), before path exemptions."""
    tree = ast.parse(source)
    aliases = _aliases(tree)
    hits: list[tuple[int, str]] = []

    for rule in rules:
        if rule.import_modules:
            hits += [
                (line, rule.kind)
                for line, names in _imports(tree)
                if _import_hit(names, rule, path)
            ]
        if rule.literal_suffixes:
            skip = _docstrings(tree)
            hits += [
                (node.lineno, rule.kind)
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in skip
                and node.value.endswith(rule.literal_suffixes)
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
        if isinstance(func, ast.Attribute) and func.attr == "write_text":
            args = list(node.args[:1]) + [kw.value for kw in node.keywords]
            if any(_dumps_inside(arg, aliases) for arg in args):
                hits.append((node.lineno, "json-write"))
        dotted = _dotted(func)
        if dotted is None:
            continue
        qname = _resolve(dotted, aliases)
        for rule in rules:
            if qname in rule.calls:
                hits.append((node.lineno, rule.kind))
    kinds = {rule.kind for rule in rules}
    return [hit for hit in hits if hit[1] in kinds]


def _exempt(path_posix: str, kind: str, rules: Sequence[Rule]) -> bool:
    patterns = next((r.allowed for r in rules if r.kind == kind), ())
    return any(fnmatch.fnmatch(path_posix, pat) for pat in patterns)


def scan(roots: Sequence[Path], rules: Sequence[Rule] = RULES) -> list[Hit]:
    hits: list[Hit] = []
    for root in roots:
        files = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for file in files:
            if "__pycache__" in file.parts:
                continue
            posix = file.as_posix()
            for line, kind in scan_source(file.read_text(), rules, posix):
                if not _exempt(posix, kind, rules):
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


def baseline_growth(baseline: Counts, reference: Counts) -> list[tuple[str, str, int, int]]:
    """Where a baseline rose above the reference (the base branch's)."""
    growth: list[tuple[str, str, int, int]] = []
    for path, kinds in baseline.items():
        for kind, n in kinds.items():
            ref_n = reference.get(path, {}).get(kind, 0)
            if n > ref_n:
                growth.append((path, kind, ref_n, n))
    return sorted(growth)


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
    parser.add_argument(
        "--rules",
        choices=sorted(RULE_SETS),
        default="core",
        help="consumer: the fence for repos that use traust-core (traust, traust-engine)",
    )
    parser.add_argument(
        "--reference",
        type=Path,
        help="the base branch's baseline; the PR baseline may not grow past it",
    )
    args = parser.parse_args(argv)

    hits = scan(args.roots, RULE_SETS[args.rules])

    if args.write_baseline:
        write_baseline(args.baseline, hits)
        print(f"wrote baseline {args.baseline} ({len(hits)} entries)")
        return 0

    baseline = load_baseline(args.baseline)
    result = compare(hits, baseline)
    for hit in result.new:
        print(f"{hit.path}:{hit.line} {hit.kind} → use {_USE[hit.kind]}")
    for path, kind, base_n, now_n in result.shrinkable:
        print(f"baseline can shrink: {path} {kind} {base_n}→{now_n}")
    failed = not result.ok
    if args.reference is not None:
        reference = load_baseline(args.reference)
        for path, kind, ref_n, now_n in baseline_growth(baseline, reference):
            print(f"baseline grew over reference: {path} {kind} {ref_n}→{now_n}")
            failed = True
    if args.summary:
        print(f"{len(hits)} hits across {len(counts(hits))} files")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
