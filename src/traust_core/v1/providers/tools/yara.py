"""Known-malware-family signature candidates from YARA over a materialized blob tree.

A match says a known family's byte pattern is present, not that the tree is compromised: the audit
judges real implant against benign carrier. A clean scan is absence of known families only.
Rule packs are a run-time input, never vendored: a local path, or an https git repo pinned to a
40-hex commit (a workspace from the checkout service, never a clone of our own); the default is
the ReversingLabs pack at a reviewed pin (drift-watched).
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout
from traust_core.v1.providers.sources import CheckoutRequest, Checkouts, Workspace
from traust_core.v1.providers.tools.adapter import adapter_result

YARA_TIMEOUT = 600
MAX_FILE_MB = 64
RL_RULES_REPO = "https://github.com/reversinglabs/reversinglabs-yara-rules"
RL_RULES_SHA = "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84"  # develop @ 2026-08
RL_RULES_LICENSE = (
    "ReversingLabs YARA rules: MIT (permissive, "
    "redistributable) — see docs/external-dependencies.md"
)
DEFAULT_SEVERITY_HINT = "high"
# `rule <id>` at line start, after optional global/private modifiers; comments never match.
RULE_DECL_RE = re.compile(r"^\s*(?:global\s+|private\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
# Trees whose hits are almost always a tool's own signature corpus or fixtures: tagged, not dropped.
CARRIER_PATH_RE = re.compile(
    r"(^|/)(testdata|test|tests|fixtures?|samples?|examples?|"
    r"yara[-_]?rules?|signatures?|clamav|rules)(/|$)",
    re.IGNORECASE,
)


class Yara:
    """The YARA engine over a directory tree, with the rule packs it resolves through the
    checkout service."""

    def __init__(
        self, process: ProcessRunner, clock: Clock, *, checkouts: Checkouts, harness_version: str
    ) -> None:
        self._process = process
        self._clock = clock
        self._checkouts = checkouts
        self._harness_version = harness_version

    def scan(
        self, target: Path, rules: Sequence[str] = (), timeout: int = YARA_TIMEOUT
    ) -> AdapterResultArtifact:
        target = target.resolve()
        if not target.is_dir():
            raise ValueError(f"not a directory: {target}")
        if not shutil.which("yara"):
            raise FileNotFoundError("yara not found on PATH (yara)")
        try:
            report = self.execute(target, rules, timeout=timeout)
        except ProcessTimeout as e:
            raise TimeoutError(f"yara timed out after {timeout}s") from e
        return adapter_result(
            str(target),
            "yara",
            facts_to_findings(report["facts"]),
            scanned_at=self._clock.now(),
            scanner_version=report.get("yara_version", ""),
        )

    def execute(
        self,
        target: Path,
        rule_sources: Sequence[str],
        *,
        timeout: int,
        yara_bin: str = "yara",
        max_file_mb: int = MAX_FILE_MB,
    ) -> dict[str, Any]:
        """The scan report: the facts, the rule packs used and the scan's stats and errors."""
        yara_version = (
            self._process.run([yara_bin, "--version"], check=False).stdout.decode().strip()
        )
        rules, held = self.resolve_rules(rule_sources)
        try:
            rule_files = [f for r in rules for f in discover_rule_files(Path(r["root"]))]
            if not rule_files:
                raise RuntimeError("no .yar/.yara rule files found")
            index = build_rule_index(rule_files)
            with tempfile.TemporaryDirectory(prefix="run_yara_") as tmp:
                index_file = generate_include_index(rule_files, Path(tmp))
                argv = [yara_bin, "-r", "-w", "-N", "-z", str(max_file_mb * 1024 * 1024)]
                done = self._process.run(
                    [*argv, str(index_file), str(target)], check=False, timeout_seconds=timeout
                )
            stdout = done.stdout.decode(errors="replace")
            stderr = done.stderr.decode(errors="replace")
            errors = [ln for ln in stderr.splitlines() if ln.strip()]
            if done.returncode != 0 and not stdout.strip():
                raise RuntimeError(f"yara failed (exit {done.returncode}): {stderr[-500:]}")
            facts = parse_matches(stdout, target, index)
            return {
                "tool": "run_yara",
                "version": self._harness_version,
                "yara_version": yara_version,
                "target": str(target),
                "rules": rules,
                "stats": {
                    "facts": len(facts),
                    "rules_compiled": len(index),
                    "rule_files": len(rule_files),
                    "files_considered": count_regular_files(target),
                    "carrier_facts": sum(1 for f in facts if f["carrier_path"]),
                    "engine_errors": len(errors),
                },
                "facts": facts,
                "errors": errors[:100],
            }
        finally:
            for workspace in held:
                self._checkouts.release(workspace)

    def resolve_rules(self, sources: Sequence[str]) -> tuple[list[dict[str, Any]], list[Workspace]]:
        """Each source as {source, root, sha, license_note} with the workspaces to release when
        the scan is done: https only, pinned to an immutable commit (a read-only checkout at that
        commit, never a clone of the default branch)."""
        resolved, held = [], []
        try:
            for src in sources or [f"{RL_RULES_REPO}@{RL_RULES_SHA}"]:
                if src.startswith(("http://", "https://", "git@")):
                    resolved.append(self._remote(src, held))
                    continue
                path = Path(src).expanduser().resolve()
                if not path.exists():
                    raise ValueError(f"rules source not found: {src}")
                resolved.append(
                    {
                        "source": src,
                        "root": str(path),
                        "sha": None,
                        "license_note": "local rules — license per author",
                    }
                )
        except BaseException:
            for workspace in held:
                self._checkouts.release(workspace)
            raise
        return resolved, held

    def _remote(self, src: str, held: list[Workspace]) -> dict[str, Any]:
        m = re.match(
            r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
            src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
        )
        if m and "/" not in m.group("ref"):
            url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
            ref = m.group("ref")
        else:
            url, ref = src, "HEAD"
        # A movable ref silently changes what a "pinned" scan reports.
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise ValueError(
                f"rules source {src!r}: ref must be a 40-hex commit SHA "
                "(movable refs change scan results silently)"
            )
        if not url.startswith("https://"):
            raise ValueError(f"rules source {src!r}: https:// URLs only")
        workspace = self._checkouts.checkout(
            CheckoutRequest(
                repo=HttpsRepoUrl.parse(url, [urlsplit(url).hostname or ""]), ref=GitSha.parse(ref)
            )
        ).data
        held.append(workspace)
        license_note = (
            RL_RULES_LICENSE
            if url.rstrip("/") == RL_RULES_REPO
            else "verify upstream license before redistribution"
        )
        return {
            "source": src,
            "root": str(workspace.path),
            "sha": ref,
            "license_note": license_note,
        }


def discover_rule_files(root: Path) -> list[Path]:
    """Every .yar/.yara file under `root`, or `root` itself when it is one."""
    if root.is_file():
        return [root] if root.suffix in (".yar", ".yara") else []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in (".yar", ".yara"))


def build_rule_index(rule_files: Sequence[Path]) -> dict[str, dict[str, str]]:
    """rule id -> {source_file, category (the rule file's directory), family (the id's last
    `_` segment)}: YARA's output names only the rule, so this is how a fact finds its family."""
    index: dict[str, dict[str, str]] = {}
    for f in rule_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if m := RULE_DECL_RE.match(line):
                rid = m.group(1)
                index[rid] = {
                    "source_file": str(f),
                    "category": f.parent.name,
                    "family": rid.split("_")[-1] if "_" in rid else rid,
                }
    return index


def generate_include_index(rule_files: Sequence[Path], workdir: Path) -> Path:
    """One `.yar` including every rule file by absolute path, so one run compiles the pack."""
    index_path = workdir / "index.yar"
    lines = [f'include "{f.as_posix()}"' for f in rule_files]
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index_path


def parse_matches(
    stdout: str, target: Path, index: Mapping[str, Mapping[str, str]]
) -> list[dict[str, Any]]:
    """`yara -r` output (`<rule id> <path>` per line, ids never contain a space) as facts."""
    facts = []
    for line in stdout.splitlines():
        if " " not in line.strip():
            continue
        rule_id, path = line.split(" ", 1)
        if not rule_id or not path.strip():
            continue
        try:
            rel = str(Path(path).resolve().relative_to(target))
        except ValueError:
            rel = path
        meta = index.get(rule_id, {})
        facts.append(
            {
                "rule_id": rule_id,
                "family": meta.get("family"),
                "category": meta.get("category"),
                "source_rule_file": meta.get("source_file"),
                "file": rel,
                "severity_hint": DEFAULT_SEVERITY_HINT,
                "match_type": "yara_signature",
                "carrier_path": bool(CARRIER_PATH_RE.search(rel)),
            }
        )
    return facts


def count_regular_files(target: Path) -> int:
    """Regular files under `target`, symlinks not followed: the tree `yara -N` walks."""
    return sum(
        1
        for root, _dirs, files in os.walk(target, followlinks=False)
        for f in files
        if not (Path(root) / f).is_symlink()
    )


def facts_to_findings(facts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"yara/{fact['rule_id']}",
            "title": f"YARA match: {fact['rule_id']}"
            + (f" ({fact['family']})" if fact.get("family") else ""),
            "severity": fact.get("severity_hint", "high"),
            "locations": [{"path": fact["file"]}],
            "description": (
                f"category={fact.get('category')} "
                f"family={fact.get('family')} "
                f"carrier_path={fact.get('carrier_path')}"
            ),
            "category": fact.get("category") or "",
        }
        for fact in facts
    ]
