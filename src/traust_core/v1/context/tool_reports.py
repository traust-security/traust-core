"""The documents `traust adapters <tool>` and `traust util elf` write, each tool run on the binary
and timeout the caller passes. Interim: the tool execution API reshapes them."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from traust_core.v1.context.documents import yaml_documents_with_lines
from traust_core.v1.context.tools import (
    gitleaks_config,
    load_rule_allowlist,
    osv_lookup,
    yara_engine,
)
from traust_core.v1.errors import ConfigError, TraustError, ValidationError
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import (
    govulncheck,
    joern,
    k8s_hardening,
    opengrep,
    osv,
    osv_sbom,
)
from traust_core.v1.providers.tools.elf import ElfAnalyzer
from traust_core.v1.providers.tools.gitleaks import Gitleaks, parse_report
from traust_core.v1.providers.tools.toolchain import (
    POPULATABLE_TOOLS,
    ToolCheck,
    preflight_failures,
)
from traust_core.v1.providers.tools.yara import YARA_TIMEOUT
from traust_core.v1.services.provider_catalog import ToolStamp

if TYPE_CHECKING:
    from traust_core.v1.context.context import Context

Doc = dict[str, Any]
HEAD_SECONDS = 15.0
# osv-scanner exits 0 (no vulnerabilities), 1 (found) or 128 (no packages); anything else is an
# error even with JSON: a missing offline database exits 127 with a clean-looking result.
OSV_SCANNER_OK_EXITS = (0, 1, 128)
OSV_AIR_GAPPED_HELP = (
    "air-gapped OSV scanning needs osv-scanner and an offline OSV database, both "
    "provided by you (the harness installs neither) — see docs/setup.md "
    '"Air-gapped OSV scanning"'
)
GOVULNCHECK_ROLE = (
    "candidate generator — context for audit/triage agents; never a finding or verdict of "
    "record. 'not_observed' is not 'unreachable'."
)


def opengrep_report(
    ctx: Context,
    target: Path,
    rules: Sequence[str],
    *,
    pack: Path | None = None,
    rule_allow: str | None = None,
    timeout: int = opengrep.SCAN_TIMEOUT,
    binary: str = "opengrep",
) -> Doc:
    """opengrep's facts report over `target`, on `pack` (default: the registered one) and, on a
    default run, its supplements; ConfigError for a pack that isn't a directory."""
    chosen = pack or ctx.rule_pack
    if not chosen.is_dir():
        raise ConfigError(f"opengrep rule pack is not a directory: {chosen}")
    return opengrep.execute_scan(
        target,
        rules,
        pack=chosen,
        runner=_runner(ctx, ("opengrep", "git", binary), max(timeout, opengrep.SCAN_TIMEOUT)),
        checkouts=ctx.checkouts,
        supplements=ctx.rule_pack_supplements,
        rule_allow=load_rule_allowlist(rule_allow),
        timeout=timeout,
        opengrep_bin=binary,
    )


def govulncheck_report(
    ctx: Context, repo: Path, *, timeout: int, binary: str, harness_version: str
) -> Doc:
    """govulncheck's reachability candidates under the `go-scan` safe-exec profile; RuntimeError
    when it printed no scan config."""
    rc, _out, err, tool, candidates = govulncheck.run_govulncheck(
        repo, timeout, binary, safe_exec=ctx.safe_exec
    )
    if not tool:
        raise RuntimeError(
            f"govulncheck produced no scan output (exit {rc}):\n{err.strip()[:2000]}"
        )
    summary = {str(level): 0 for level in govulncheck.REACH_ORDER}
    for c in candidates:
        summary[c["reachability"]] += 1
    return {
        "metadata": {
            "artifact": "govulncheck-reachability-candidates",
            "role": GOVULNCHECK_ROLE,
            "harness_version": harness_version,
            "tool": tool,
            "repository": str(repo),
            "commit": _head(ctx, repo),
            "generated_at": ctx.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "invocation": " ".join(govulncheck.command(binary)),
        },
        "summary": {"osv_total": len(candidates), **summary},
        "candidates": candidates,
    }


def gitleaks_report(
    ctx: Context, repo: Path, *, mode: str, config: Path | None, timeout: int, binary: str
) -> Doc:
    """gitleaks' secret-free candidates over `repo`'s working tree (`dir`) or history; the rules
    are `config`, else `locations.gitleaks_config` (ConfigError when neither is a file)."""
    try:
        rules = config if config is not None else gitleaks_config(ctx.config.locations)
    except ValueError as e:
        raise ConfigError(str(e)) from e
    if not rules.is_file():
        raise ConfigError(f"gitleaks config is not a file: {rules}")
    _require(binary, "gitleaks")
    scanner = Gitleaks(_runner(ctx, (binary, "git"), timeout), ctx.clock, binary)
    with _timed("gitleaks", timeout):
        raw = scanner.run(repo, mode, rules, timeout)
    return {
        "metadata": {
            "artifact": "gitleaks-secret-candidates",
            "mode": mode,
            "repository": str(repo),
            "head": scanner.repo_head(repo),
            "gitleaks_version": scanner.version(),
        },
        "candidates": parse_report(raw, repo, mode),
    }


def yara_report(
    ctx: Context,
    target: Path,
    rules: Sequence[str],
    *,
    timeout: int,
    binary: str,
    max_file_mb: int,
) -> Doc:
    """YARA's known-malware-family facts over `target`, on the pinned default pack when `rules`
    names none; ValidationError for a rules source that isn't pinned https or a local path."""
    _require(binary, "yara")
    engine = yara_engine(ctx, _runner(ctx, (binary, "git"), max(timeout, YARA_TIMEOUT)))
    with _timed("yara", timeout):
        try:
            return engine.execute(
                target, rules, timeout=timeout, yara_bin=binary, max_file_mb=max_file_mb
            )
        except TraustError:
            raise
        except ValueError as e:
            raise ValidationError(str(e)) from e


def k8s_hardening_report(target: Path) -> Doc:
    """The KHS-* manifest checks and tenancy signals over every YAML and Go file under `target`."""
    scanner = k8s_hardening.Scanner(target, yaml_documents_with_lines)
    scanner.run()
    return scanner.report()


def joern_report(
    ctx: Context,
    repo: Path,
    *,
    symbols: Sequence[str],
    language: str,
    packages: str,
    module: str,
    timeout: int,
    max_sites: int,
) -> Doc:
    """Joern's call-site facts for `symbols` (or derived package patterns), soundness stated."""
    return joern.with_soundness(
        joern.run_scan(
            repo,
            runner=_runner(ctx, ("joern", "joern-parse"), max(timeout, joern.SCAN_TIMEOUT)),
            symbols=tuple(symbols),
            timeout=timeout,
            max_sites=max_sites,
            language=language,
            packages=packages,
            module=module,
            java_opts=os.environ.get("JOERN_JAVA_OPTS", joern.DEFAULT_JAVA_OPTS),
        )
    )


def osv_report(
    ctx: Context, repo: Path, *, scanner: str | None = None, timeout: float, freeze: bool = True
) -> Doc:
    """A checkout's dependency advisories (`provenance`, `candidates`): the OSV API through the
    registry's lookup, deps.dev resolving manifests without a lockfile, or offline osv-scanner
    when `scanner` names its binary (`freeze` adds `--offline`)."""
    if scanner is None:
        return osv.scan_api(repo, osv_lookup(ctx), ctx.clock, resolver=ctx.deps_dev)
    process = _runner(ctx, (scanner,), timeout)

    def run() -> Doc:
        done, invocation = osv.run_scanner(process, scanner, repo, timeout, freeze=freeze)
        scan = _scanner_json(done, json_first=True)
        return {
            "provenance": {
                "source": "osv-scanner",
                "tool_version": (scan.get("experimental_config") or {}).get("version")
                or osv.scanner_version(process, scanner)
                or "",
                "invocation": invocation,
                "status": "complete",
            },
            "candidates": osv.parse_output(scan, repo),
        }

    return _offline(scanner, run)


def osv_sbom_report(
    ctx: Context,
    sbom: Path,
    *,
    scanner: str | None = None,
    timeout: float,
    grype: Mapping[str, Any] | None = None,
) -> Doc:
    """An image's syft-JSON language packages not installed by an OS package, looked up in OSV
    or by offline osv-scanner when `scanner` names its binary. With `grype`'s JSON for the same
    SBOM: grype's matches on OS-installed packages (`grype_os_installed`), duplicates tagged."""
    doc = osv_sbom.load_syft(sbom)
    if scanner is None:
        body = osv_sbom.scan_sbom(doc, osv_lookup(ctx), ctx.clock)
    else:
        packages, stats = osv_sbom.collect_sbom_packages(doc)

        def run() -> Doc:
            done, invocation = osv_sbom.run_offline(
                _runner(ctx, (scanner,), timeout), scanner, packages, timeout
            )
            return {
                "provenance": {
                    "source": "osv-scanner",
                    "invocation": invocation,
                    "status": "complete",
                },
                "candidates": osv_sbom.parse_offline(_scanner_json(done), packages),
            }

        body = _offline(scanner, run)
        osv_sbom.with_stats(body["provenance"], stats, doc)
    if grype is not None:
        grype_doc = dict(grype)
        matches = osv_sbom.grype_os_installed_matches(grype_doc, doc)
        prov = body["provenance"]
        prov["grype_os_installed_matches"] = len(matches)
        if prov.get("status") != "failed":
            prov["grype_dedupe"] = osv_sbom.mark_grype_duplicates(body["candidates"], grype_doc)
        body["grype_os_installed"] = matches
    return body


def elf_report(path: Path, symbols: Sequence[str], *, max_scan: int) -> Doc | None:
    """An ELF binary's header, linked libraries and (with `symbols`) where each name appears in its
    first `max_scan` bytes; None for anything that isn't an ELF."""
    analyzer = ElfAnalyzer(path)
    meta = analyzer.metadata()
    if meta is None:
        return None
    out: Doc = {
        "path": str(path),
        "metadata": {"arch": meta.arch, "elf_class": meta.elf_class, "endian": meta.endian},
        "linked_libraries": [lib.name for lib in analyzer.linked_libraries()],
    }
    if symbols:
        patterns = [(s, re.compile(s.encode("ascii", errors="ignore"))) for s in symbols]
        out["string_matches"] = [
            {"pattern_id": m.pattern_id, "matched": m.matched, "offset": m.offset}
            for m in analyzer.scan_strings(patterns, max_scan=max_scan)
        ]
    return out


def populatable_tools() -> frozenset[str]:
    """The pinned tools whose vulnerability database `Toolchain.populate` refreshes."""
    return POPULATABLE_TOOLS


def toolchain_failures(checks: Sequence[ToolCheck]) -> list[str]:
    """One message per check that should stop a run."""
    return preflight_failures(checks)


def tool_stamp(check: ToolCheck) -> str:
    """`grype 0.115.0 (db built 2026-08-24, schema 5)`: what a ready tool reports."""
    return ToolStamp(tool=check.name, version=check.version, database=check.database).render()


def _offline(scanner: str, run: Callable[[], Doc]) -> Doc:
    """An osv-scanner run, or a failed body naming the air-gapped setup when the binary is
    missing, times out or fails: never a clean-looking scan."""
    if not shutil.which(scanner):
        return _failed_body(f"osv-scanner not found ({scanner}): {OSV_AIR_GAPPED_HELP}")
    try:
        return run()
    except ProcessTimeout as e:
        return _failed_body(f"{e.__cause__} — {OSV_AIR_GAPPED_HELP}")
    except RuntimeError as e:
        return _failed_body(f"{e} — {OSV_AIR_GAPPED_HELP}")


def _failed_body(detail: str) -> Doc:
    return {
        "provenance": {
            "source": "osv-scanner",
            "status": "failed",
            "failure": {"status": "error", "detail": detail},
        },
        "candidates": [],
    }


def _scanner_json(done: ProcessResult, *, json_first: bool = False) -> Doc:
    stdout = done.stdout.decode(errors="replace")
    stderr = done.stderr.decode(errors="replace")
    printed_json = stdout.strip().startswith("{")
    if json_first and not printed_json:
        raise RuntimeError(
            f"osv-scanner produced no JSON (exit {done.returncode}):\n"
            f"{(stderr or stdout).strip()[:2000]}"
        )
    if done.returncode not in OSV_SCANNER_OK_EXITS or not printed_json:
        errors = [ln for ln in stderr.splitlines() if "rror" in ln or "unable" in ln]
        raise RuntimeError(
            f"osv-scanner failed (exit {done.returncode}): "
            + ("; ".join(errors[:3]) or stderr.strip()[-500:])
        )
    return json.loads(stdout)


def _runner(ctx: Context, binaries: Sequence[str], timeout: float) -> ProcessRunner:
    return ProcessRunner(
        {Path(b).name for b in binaries},
        keep_env=ctx.config.process.keep_env,
        timeout_seconds=timeout,
    )


def _head(ctx: Context, repo: Path) -> str | None:
    """The checkout's HEAD; None when it isn't a git checkout."""
    try:
        return GitCheckout(_runner(ctx, ("git",), HEAD_SECONDS)).head(repo)
    except TraustError:
        return None


def _require(binary: str, tool: str) -> None:
    if not shutil.which(binary):
        raise FileNotFoundError(f"{tool} not found on PATH ({binary})")


@contextmanager
def _timed(tool: str, timeout: int) -> Iterator[None]:
    try:
        yield
    except ProcessTimeout as e:
        raise TimeoutError(f"{tool} timed out after {timeout}s") from e
