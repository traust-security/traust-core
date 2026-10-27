"""Dependency-CVE reachability candidates from `govulncheck -json ./...`, one per OSV advisory,
at the most specific level govulncheck observed. A candidate generator, never a verdict:
`not_observed` means static analysis saw no call path, not that the code is unreachable."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.candidate_formats import govulncheck_records
from traust_core.v1.models.vocabulary import ImpactGovulncheck
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.tools.adapter import adapter_result
from traust_core.v1.providers.tools.safe_exec import SafeExec
from traust_core.v1.providers.tools.toolchain import freeze_env

REACH_ORDER = (
    ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED,
    ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED,
    ImpactGovulncheck.SYMBOL_REACHABLE,
)
PROFILE = "go-scan"

_SEVERITY = {
    ImpactGovulncheck.SYMBOL_REACHABLE: "high",
    ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED: "medium",
    ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED: "low",
}


def classify(finding: dict[str, Any]) -> ImpactGovulncheck:
    """One govulncheck finding record's reachability level, from its innermost frame."""
    trace = finding.get("trace") or []
    frame = trace[0] if trace else {}
    if frame.get("function"):
        return ImpactGovulncheck.SYMBOL_REACHABLE
    if frame.get("package"):
        return ImpactGovulncheck.PACKAGE_IMPORTED_NOT_OBSERVED
    return ImpactGovulncheck.MODULE_REQUIRED_NOT_OBSERVED


def trace_symbols(trace: list[dict[str, Any]]) -> list[str]:
    """A govulncheck trace as compact call-path strings, caller first."""
    out = []
    for frame in reversed(trace):
        fn = frame.get("function")
        if not fn:
            continue
        recv = frame.get("receiver") or ""
        name = f"{recv}.{fn}" if recv else fn
        pkg = frame.get("package") or ""
        pos = frame.get("position") or {}
        loc = f" ({pos['filename']}:{pos['line']})" if pos.get("filename") else ""
        out.append(f"{pkg}.{name}{loc}" if pkg else f"{name}{loc}")
    return out


def parse_stream(text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The scanner's config (empty when it printed none) and its per-OSV candidates, the most
    reachable first."""
    osv_meta: dict[str, dict[str, Any]] = {}
    candidates: dict[str, dict[str, Any]] = {}
    tool: dict[str, Any] = {}
    for rec in govulncheck_records(text):
        if not isinstance(rec, dict):
            continue
        if "config" in rec:
            cfg = rec["config"]
            tool = {
                "name": cfg.get("scanner_name", "govulncheck"),
                "version": cfg.get("scanner_version"),
                "go_version": cfg.get("go_version"),
                "db": cfg.get("db"),
                "db_last_modified": cfg.get("db_last_modified"),
                "scan_level": cfg.get("scan_level"),
            }
        elif "osv" in rec:
            osv = rec["osv"]
            osv_meta[osv.get("id")] = {
                "aliases": osv.get("aliases") or [],
                "summary": osv.get("summary") or osv.get("details", "")[:200],
            }
        elif "finding" in rec:
            f = rec["finding"]
            if not (osv_id := f.get("osv")):
                continue
            level = classify(f)
            trace = f.get("trace") or []
            frame = trace[0] if trace else {}
            cand = candidates.setdefault(
                osv_id,
                {
                    "osv_id": osv_id,
                    "reachability": level,
                    "module": frame.get("module"),
                    "found_version": frame.get("version"),
                    "fixed_version": f.get("fixed_version"),
                    "packages": [],
                    "example_trace": [],
                },
            )
            if REACH_ORDER.index(level) > REACH_ORDER.index(cand["reachability"]):
                cand["reachability"] = level
            pkg = frame.get("package")
            if pkg and pkg not in cand["packages"]:
                cand["packages"].append(pkg)
            if level == ImpactGovulncheck.SYMBOL_REACHABLE:
                symbols = trace_symbols(trace)
                # the shortest observed call path is the example
                if symbols and (
                    not cand["example_trace"] or len(symbols) < len(cand["example_trace"])
                ):
                    cand["example_trace"] = symbols
    for osv_id, cand in candidates.items():
        meta = osv_meta.get(osv_id, {})
        cand["aliases"] = meta.get("aliases", [])
        cand["summary"] = meta.get("summary", "")
    rank = {level: i for i, level in enumerate(reversed(REACH_ORDER))}
    ranked = sorted(candidates.values(), key=lambda c: (rank[c["reachability"]], c["osv_id"]))
    return tool, ranked


def go_mods(repo: Path) -> list[Path]:
    """The checkout's own go.mod, else those one directory down."""
    return [repo / "go.mod"] if (repo / "go.mod").is_file() else sorted(repo.glob("*/go.mod"))


def requiring_go_mod(repo: Path, module: str | None) -> str:
    """The repo-relative go.mod that names `module`, else the first."""
    mods = go_mods(repo)
    named = [
        m for m in mods if module and module in m.read_text(encoding="utf-8", errors="replace")
    ]
    return str((named or mods)[0].relative_to(repo))


def _findings(candidates: list[dict[str, Any]], repo: Path) -> list[dict[str, Any]]:
    findings = []
    for cand in candidates:
        locations = [{"path": site, "description": "call path"} for site in cand["example_trace"]]
        locations += [{"path": pkg, "description": "imported package"} for pkg in cand["packages"]]
        if not locations:
            # PENDING(contracts: module-only findings): the schema needs a location; engine had none
            module, version = cand.get("module"), cand.get("found_version")
            required = f"{module}@{version}" if version else str(module)
            locations = [
                {
                    "path": requiring_go_mod(repo, module),
                    "description": f"requires {required} ({cand['reachability']})",
                }
            ]
        findings.append(
            {
                "id": cand["osv_id"],
                "title": cand.get("summary") or cand["osv_id"],
                "severity": _SEVERITY[cand["reachability"]],
                "locations": locations,
                "description": (
                    f"module={cand.get('module')} "
                    f"version={cand.get('found_version')} "
                    f"reachability={cand['reachability']}"
                ),
                "category": cand["reachability"],
            }
        )
    return findings


def command(govulncheck_bin: str = "govulncheck") -> list[str]:
    """The argv a govulncheck scan runs, from inside the checkout."""
    return [govulncheck_bin, "-json", "./..."]


def run_govulncheck(
    repo: Path,
    timeout: int,
    govulncheck_bin: str,
    *,
    safe_exec: SafeExec,
    freeze: bool = True,
) -> tuple[int, str, str, dict[str, Any], list[dict[str, Any]]]:
    """govulncheck under the `go-scan` safe-exec profile: (exit code, stdout, stderr, config,
    candidates)."""
    extra_env = freeze_env("govulncheck") if freeze else {}
    rc, out, err = safe_exec.run(
        command(govulncheck_bin), PROFILE, timeout=timeout, cwd=repo, extra_env=extra_env or None
    )
    tool, candidates = parse_stream(out)
    return rc, out, err, tool, candidates


def scan(
    repo: Path,
    *,
    safe_exec: SafeExec,
    clock: Clock,
    timeout: int = 600,
    govulncheck_bin: str = "govulncheck",
    freeze: bool = True,
) -> AdapterResultArtifact:
    """govulncheck's candidates as an adapter result; `freeze` keeps its database from updating."""
    repo = repo.resolve()
    if not go_mods(repo):
        raise ValueError(f"no go.mod under {repo}")
    rc, _out, err, tool, candidates = run_govulncheck(
        repo, timeout, govulncheck_bin, safe_exec=safe_exec, freeze=freeze
    )
    if not tool:
        raise RuntimeError(f"govulncheck produced no scan output (exit {rc}): {err.strip()[:500]}")
    return adapter_result(
        str(repo),
        "govulncheck",
        _findings(candidates, repo),
        scanned_at=clock.now(),
        scanner_version=tool.get("version") or "",
    )
