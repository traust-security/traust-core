"""Joern call-site facts for JVM and C/C++ code: every first-party call whose callee matches the
vulnerable symbols or package prefixes under investigation. Facts only; impact analysis judges.

A found call path is promoting evidence; an absent one is never proof of safety (dependency
injection, reflection and MethodHandles hide edges from any static analyzer). Every result says
so in its `soundness` block."""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.adapter import adapter_result

SCAN_TIMEOUT = 1200
VERSION_TIMEOUT = 120
DEFAULT_JAVA_OPTS = "-Xmx8g"

# Runs inside joern; TSV out (SITE/COUNT rows) so the Scala side needs no JSON library.
QUERY_SC = r"""
@main def exec(cpgFile: String, symbolsFile: String, outFile: String) = {
  importCpg(cpgFile)
  val patterns = scala.io.Source.fromFile(symbolsFile).getLines().filter(_.nonEmpty).toList
  val sb = new StringBuilder
  for (p <- patterns) {
    val exact = p.startsWith("=")
    val contains = p.startsWith("~")
    val q = if (exact || contains) p.drop(1) else p
    // Exact mode compares the CALLEE NAME, not the whole methodFullName.
    // c2cpg emits "<unresolvedNamespace>.ConsumeFieldMessage:<unresolvedSig>"
    // for C++ member calls and never qualifies with "::", so comparing the
    // whole string made every C++ member query fail by construction, while
    // still matching plain C where the name IS the whole prefix. Measured
    // 2026-08-14 on protobuf text_format.cc: 3325 calls, 0 matches.
    def calleeName(fn: String): String = {
      val base = fn.split(":").headOption.getOrElse(fn)
      base.split('.').lastOption.getOrElse(base)
    }
    val calls = (if (exact) cpg.call.filter(c => calleeName(c.methodFullName) == q)
                 else if (contains) cpg.call.filter(_.methodFullName.contains(q))
                 else cpg.call.filter(_.methodFullName.startsWith(q))).l
    for (c <- calls.take(500)) {
      val file = c.location.filename
      val line = Option(c.lineNumber).flatten.map(_.toString).getOrElse("-1")
      sb.append(List("SITE", p, file, line, c.method.fullName, c.methodFullName)
        .mkString("\t")).append("\n")
    }
    sb.append(List("COUNT", p, calls.size.toString).mkString("\t")).append("\n")
  }
  val w = new java.io.PrintWriter(outFile)
  w.write(sb.toString)
  w.close()
}
"""

_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|testdata|it)(/|$)", re.I)

# Explicit per language: joern-parse's auto-detection picks jimple2cpg (the bytecode frontend)
# for a Java tree with compiled artifacts present, and every pattern then silently misses.
_FRONTEND = {"java": "JAVASRC", "c": "NEWC"}

# Coordinate tokens with no package identity: they appear in half of all Maven artifact ids.
_GENERIC_TOKENS = frozenset(
    {
        "core",
        "api",
        "apis",
        "starter",
        "common",
        "commons",
        "util",
        "utils",
        "client",
        "server",
        "impl",
        "lib",
        "libs",
        "java",
        "javax",
        "base",
        "bom",
        "parent",
        "all",
        "main",
        "runtime",
        "support",
        "extension",
        "extensions",
        "plugin",
        "plugins",
        "module",
        "modules",
        "spi",
        "sdk",
        "com",
        "org",
        "io",
        "net",
        "ch",
        "me",
    }
)
_IMPORT_RX = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.M)

SOUNDNESS = {
    "found_path": "promoting evidence — first-party code invokes the "
    "matched API; cite the call site",
    "absent_path": "NEVER proof of safety — Java DI/reflection hide "
    "edges from static analysis; this tier upgrades "
    "classifications, never downgrades them",
    "line_numbers": "APPROXIMATE — javasrc2cpg line attribution "
    "drifts on some constructs; the "
    "file + caller method are authoritative. Anyone "
    "citing a site must verify the exact line by "
    "reading the file (citation-gate discipline).",
}


def derive_packages_from_imports(
    repo: Path, module: str, max_files: int = 4000
) -> list[dict[str, Any]]:
    """Package prefixes the repo actually imports that plausibly belong to `module`, each with
    the file that evidences it: a Maven group id is often not the package root."""
    group, _, artifact = module.partition(":")
    toks = {
        t.lower()
        for t in re.split(r"[.\-_]", group + "-" + artifact)
        if len(t) > 2 and t.lower() not in _GENERIC_TOKENS
    }
    if not toks:
        return []
    hits: dict[str, str] = {}
    score: dict[str, int] = {}
    scanned = 0
    for f in repo.rglob("*.java"):
        if scanned >= max_files:
            break
        scanned += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _IMPORT_RX.finditer(text):
            parts = m.group(1).split(".")
            low = [p.lower() for p in parts]
            idxs = [i for i, p in enumerate(low) if p in toks]
            if not idxs:
                continue
            pkg = ".".join(parts[: max(idxs) + 1])
            if pkg.count(".") < 1:
                continue
            hits.setdefault(pkg, str(f.relative_to(repo)))
            score[pkg] = max(score.get(pkg, 0), len(set(low[: max(idxs) + 1]) & toks))
    if not hits:
        return []
    best = max(score.values())
    out = []
    for pkg, ev in sorted(hits.items()):
        if score.get(pkg, 0) < best:
            continue
        if any(o != pkg and o.startswith(pkg + ".") and score.get(o, 0) >= best for o in hits):
            continue
        out.append(
            {
                "pattern": pkg + ".",
                "kind": "package",
                "source": f"import-derived:{pkg}",
                "evidence_file": ev,
                "tokens_matched": score.get(pkg, 0),
            }
        )
    return out[:12]


@dataclass(frozen=True, slots=True)
class PatternInput:
    symbols: tuple[str, ...] = ()
    packages: str = ""
    module: str | None = None
    language: str = "java"
    repo: Path | None = None


def patterns_from(inp: PatternInput) -> list[dict[str, Any]]:
    """methodFullName patterns, strongest first: the vulnerable symbols, package prefixes, then
    a bare Maven group as a recorded heuristic. A leading '=' asks the query for an exact callee
    name (C functions), a leading '~' for a substring (a class not fully qualified)."""
    pats: list[dict[str, Any]] = []
    for s in inp.symbols:
        if inp.language == "c":
            # c2cpg's methodFullName is the bare function name; a prefix over-matches short names
            pats.append({"pattern": "=" + s, "kind": "symbol", "source": s})
        elif "#" in s:
            cls, _, meth = s.partition("#")
            if "." in cls:
                pats.append({"pattern": f"{cls}.{meth}:", "kind": "symbol", "source": s})
            else:
                pats.append(
                    {
                        "pattern": f"~.{cls}.{meth}:",
                        "kind": "symbol",
                        "source": s,
                        "match": "contains (class not fully qualified)",
                    }
                )
        else:
            pats.append(
                {"pattern": s if s.endswith(".") else s + ".", "kind": "package", "source": s}
            )
    for raw in inp.packages.split(",") if inp.packages else []:
        if p := raw.strip():
            pats.append(
                {"pattern": p if p.endswith(".") else p + ".", "kind": "package", "source": p}
            )
    if not pats and inp.module:
        if inp.language == "java" and inp.repo is not None:
            with contextlib.suppress(OSError):
                pats.extend(derive_packages_from_imports(inp.repo, inp.module))
        if not pats:
            group = inp.module.partition(":")[0]
            if "." in group:
                pats.append(
                    {
                        "pattern": group + ".",
                        "kind": "group-heuristic",
                        "source": inp.module,
                        "match": "group id only approximates the "
                        "package root; no matching import "
                        "found in the tree",
                    }
                )
    seen: set[str] = set()
    out = []
    for p in pats:
        if p["pattern"] not in seen:
            seen.add(p["pattern"])
            out.append(p)
    return out


def with_soundness(doc: dict[str, Any]) -> dict[str, Any]:
    """`doc` with the evidence asymmetry stated, as every joern artifact carries it."""
    return {**doc, "soundness": doc.get("soundness", SOUNDNESS)}


def run_scan(
    repo: Path,
    *,
    runner: ProcessRunner,
    symbols: tuple[str, ...] = (),
    timeout: int = SCAN_TIMEOUT,
    max_sites: int = 200,
    language: str = "java",
    packages: str = "",
    module: str = "",
    java_opts: str = DEFAULT_JAVA_OPTS,
) -> dict[str, Any]:
    """The call-site facts document; its status is "ran", "skipped: <why>" or "error: <why>"."""
    base: dict[str, Any] = {
        "tool": "joern",
        "repo": str(repo),
        "language": language,
        "module": module or None,
    }
    joern = shutil.which("joern")
    parse = shutil.which("joern-parse")
    if not (joern and parse):
        return {**base, "status": "skipped: joern not on PATH"}
    exts = ("*.java",) if language == "java" else ("*.c", "*.h", "*.cc", "*.cpp", "*.hpp")
    if not any(f for pat in exts for f in repo.rglob(pat)):
        return {**base, "status": f"skipped: no {language} sources"}
    pats = patterns_from(
        PatternInput(
            symbols=symbols,
            packages=packages,
            module=module or None,
            language=language,
            repo=repo,
        )
    )
    if not pats:
        return {**base, "status": "skipped: no symbol/package patterns derivable"}

    try:
        ver = runner.run(
            [joern, "--version"], stdin=b"", check=False, timeout_seconds=VERSION_TIMEOUT
        )
        m = re.search(rb"\b(\d+\.\d+\.\d+)\b", ver.stdout + ver.stderr)
        base["version"] = m.group(1).decode() if m else "unknown"
    except ServiceError:
        base["version"] = "unknown"

    java = {"JAVA_OPTS": java_opts}
    with tempfile.TemporaryDirectory(prefix="joern-reach-") as td:
        tdp = Path(td)
        cpg = tdp / "cpg.bin"
        frontend = _FRONTEND[language]
        base["frontend"] = frontend
        built = runner.run(
            [parse, str(repo), "--language", frontend, "--output", str(cpg)],
            stdin=b"",
            env=java,
            check=False,
            timeout_seconds=timeout,
        )
        if built.returncode != 0 or not cpg.is_file():
            raw = (built.stderr or built.stdout).decode(errors="replace").strip()
            return {
                **base,
                "status": "error: joern-parse failed",
                "detail_head": raw[:400],
                "detail": raw[-400:],
            }
        script = tdp / "query.sc"
        script.write_text(QUERY_SC, encoding="utf-8")
        symfile = tdp / "patterns.txt"
        symfile.write_text("\n".join(p["pattern"] for p in pats) + "\n", encoding="utf-8")
        tsv = tdp / "sites.tsv"
        q = runner.run(
            [
                joern,
                "--script",
                str(script),
                "--param",
                f"cpgFile={cpg}",
                "--param",
                f"symbolsFile={symfile}",
                "--param",
                f"outFile={tsv}",
            ],
            stdin=b"",
            env=java,
            check=False,
            timeout_seconds=timeout,
        )
        if q.returncode != 0 or not tsv.is_file():
            return {
                **base,
                "status": "error: joern query failed",
                "detail": (q.stderr or q.stdout).decode(errors="replace").strip()[-400:],
            }
        by_pattern = _sites(tsv.read_text(encoding="utf-8"), pats, repo, max_sites)

    targets = []
    for p in pats:
        entry = by_pattern[p["pattern"]]
        entry["call_sites"].sort(key=lambda s: (s["file"], s["line"]))
        nontest = [s for s in entry["call_sites"] if not s["test_path"]]
        capped = entry["total_calls"] > len(entry["call_sites"])
        targets.append(
            {
                "source": entry["source"],
                "kind": entry["kind"],
                "pattern": entry["pattern"],
                "referenced": bool(nontest),
                "referenced_test_only": bool(entry["call_sites"]) and not nontest,
                "total_calls": entry["total_calls"],
                "call_sites": entry["call_sites"],
                **({"sites_capped_at": max_sites} if capped else {}),
            }
        )
    return {**base, "status": "ran", "targets": targets}


def _sites(
    tsv: str, pats: list[dict[str, Any]], repo: Path, max_sites: int
) -> dict[str, dict[str, Any]]:
    """The query's SITE/COUNT rows by pattern, call sites repo-relative and capped."""
    by_pattern = {p["pattern"]: {**p, "call_sites": [], "total_calls": 0} for p in pats}
    repo_prefix = str(repo.resolve()) + os.sep
    for row in tsv.splitlines():
        parts = row.split("\t")
        if parts[0] == "COUNT" and len(parts) == 3:
            if parts[1] in by_pattern:
                by_pattern[parts[1]]["total_calls"] = int(parts[2])
        elif parts[0] == "SITE" and len(parts) == 6:
            _, pat, fname, line, caller, callee = parts
            if pat not in by_pattern:
                continue
            rel = fname[len(repo_prefix) :] if fname.startswith(repo_prefix) else fname
            sites = by_pattern[pat]["call_sites"]
            if len(sites) < max_sites:
                sites.append(
                    {
                        "file": rel,
                        "line": int(line),
                        "caller": caller,
                        "callee": callee,
                        "test_path": bool(_TEST_PATH.search(rel)),
                    }
                )
    return by_pattern


def _findings(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"joern/{target['pattern']}:{site['file']}:{site['line']}",
            "title": f"Call to {target['source']} at {site['file']}",
            "severity": "high" if target.get("referenced") else "medium",
            "locations": [
                {
                    "path": site["file"],
                    "lines": str(site.get("line", "")),
                    "description": site.get("caller", ""),
                }
            ],
            "description": (
                f"callee={site.get('callee')} pattern={target['pattern']} kind={target.get('kind')}"
            ),
            "category": target.get("kind", ""),
        }
        for target in targets
        for site in target.get("call_sites", [])
    ]


def scan(
    repo: Path,
    *,
    runner: ProcessRunner,
    clock: Clock,
    symbols: tuple[str, ...] = (),
    timeout: int = SCAN_TIMEOUT,
    java_opts: str = DEFAULT_JAVA_OPTS,
) -> AdapterResultArtifact:
    """The call sites of `symbols` in a Java checkout as an adapter result; a skip or an error is
    a RuntimeError naming the status."""
    repo = repo.resolve()
    doc = run_scan(repo, runner=runner, symbols=symbols, timeout=timeout, java_opts=java_opts)
    if doc.get("status") != "ran":
        raise RuntimeError(doc.get("status", "joern scan failed"))
    return adapter_result(
        str(repo),
        "joern",
        _findings(doc.get("targets", [])),
        scanned_at=clock.now(),
        scanner_version=doc.get("version", ""),
    )
