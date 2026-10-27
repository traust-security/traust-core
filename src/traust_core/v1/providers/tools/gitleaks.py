"""Committed-credential candidates from gitleaks: secret-free, never a verdict.

The matched secret never leaves this module; the liveness verifier re-reads it from the checkout.
A target's own `gitleaks:allow` comments are data under audit, not exemptions: the scan ignores
them and the candidate carries `inline_allow` for the judge to weigh.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.adapter import adapter_result, format_lines

GITLEAKS_TIMEOUT = 900
PROBE_TIMEOUT = 15.0
INLINE_ALLOW_MARKER = "gitleaks:allow"
# gitleaks rule id -> the credential class the liveness verifier probes read-only; unmapped is
# untestable by design, so this grows only with the probe registry.
LIVENESS_CLASSES = {
    "aws-access-token": "aws",
    "github-pat": "github",
    "github-fine-grained-pat": "github",
    "github-oauth": "github",
    "github-app-token": "github",
    "gitlab-pat": "gitlab",
    "gitlab-ptt": "gitlab",
    "gitlab-rrt": "gitlab",
    "slack-bot-token": "slack",
    "slack-user-token": "slack",
    "traust-openshift-sha256-token": "openshift",
}


class Gitleaks:
    """gitleaks over a checkout's working tree (`dir`) or its full git history (`history`)."""

    def __init__(self, process: ProcessRunner, clock: Clock, binary: str = "gitleaks") -> None:
        self._process = process
        self._clock = clock
        self._binary = binary

    def scan(
        self, repo: Path, config: Path, mode: str = "dir", timeout: int = GITLEAKS_TIMEOUT
    ) -> AdapterResultArtifact:
        repo = repo.resolve()
        if not config.is_file():
            raise ValueError(f"gitleaks config is not a file: {config}")
        if not repo.is_dir():
            raise ValueError(f"not a directory: {repo}")
        candidates = parse_report(self.run(repo, mode, config, timeout), repo, mode)
        return adapter_result(
            str(repo),
            "gitleaks",
            candidates_to_findings(candidates),
            scanned_at=self._clock.now(),
            scanner_version=self.version() or "",
        )

    def run(self, repo: Path, mode: str, config: Path, timeout: int) -> list[dict[str, Any]]:
        """gitleaks' raw findings, secrets redacted and the target's own allow comments ignored."""
        with tempfile.TemporaryDirectory(prefix="gitleaks-") as tmp:
            report = Path(tmp) / "report.json"
            argv = [
                self._binary,
                "git" if mode == "history" else "dir",
                str(repo),
                "--config",
                str(config),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--redact=100",
                "--ignore-gitleaks-allow",
                "--exit-code",
                "0",
                "--no-banner",
                "--log-level",
                "error",
            ]
            done = self._process.run(argv, check=False, timeout_seconds=timeout)
            if done.returncode != 0:
                stderr = done.stderr.decode(errors="replace").strip()[:500]
                raise RuntimeError(f"gitleaks failed (exit {done.returncode}): {stderr}")
            return json.loads(report.read_text(encoding="utf-8")) or []

    def repo_head(self, repo: Path) -> str | None:
        try:
            done = self._process.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], timeout_seconds=PROBE_TIMEOUT
            )
        except ServiceError:
            return None
        return done.stdout.decode().strip()

    def version(self) -> str | None:
        """The first line `gitleaks version` prints; None when it doesn't run or prints nothing."""
        try:
            done = self._process.run(
                [self._binary, "version"], check=False, timeout_seconds=PROBE_TIMEOUT
            )
        except ServiceError:
            return None
        out = done.stdout.decode(errors="replace").strip()
        return out.splitlines()[0] if out else None


def parse_report(
    findings: Sequence[Mapping[str, Any]], repo: Path, mode: str
) -> list[dict[str, Any]]:
    """gitleaks' findings as secret-free candidates, sorted by location."""
    candidates = []
    for f in findings:
        rule = f.get("RuleID") or ""
        path = f.get("File") or ""
        with contextlib.suppress(ValueError):
            path = str(Path(path).resolve().relative_to(repo.resolve()))
        candidate = {
            "rule_id": rule,
            "description": f.get("Description") or "",
            "path": path,
            "start_line": f.get("StartLine"),
            "end_line": f.get("EndLine"),
            "entropy": f.get("Entropy"),
            # commit:file:rule:line, gitleaks' own identity: no secret material, the dedup key
            "fingerprint": f.get("Fingerprint") or "",
            "liveness_class": LIVENESS_CLASSES.get(rule),
            "evidence": "secret_pattern_match",
            "inline_allow": _has_inline_allow(f, repo, path, mode),
        }
        if mode == "history":
            candidate["commit"] = f.get("Commit") or None
            candidate["commit_date"] = f.get("Date") or None
            # the author routes ownership; the commit message is repository content, kept out
            candidate["author_email"] = f.get("Email") or None
        candidates.append(candidate)
    candidates.sort(key=lambda c: (c["path"], c["start_line"] or 0, c["rule_id"], c["fingerprint"]))
    return candidates


def candidates_to_findings(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"gitleaks/{c['rule_id']}",
            "title": c.get("description") or c["rule_id"],
            "severity": "high",
            "locations": [
                {"path": c["path"], "lines": format_lines(c.get("start_line"), c.get("end_line"))}
            ],
            "description": _describe(c),
            "category": c.get("rule_id", ""),
        }
        for c in candidates
    ]


def _has_inline_allow(finding: Mapping[str, Any], repo: Path, path: str, mode: str) -> bool:
    """Whether the matched line carries the target's own suppression marker. gitleaks redacts only
    the secret, so the marker survives in `Line`/`Match`; dir mode also reads the checkout line."""
    if any(INLINE_ALLOW_MARKER in (finding.get(key) or "") for key in ("Line", "Match")):
        return True
    start = finding.get("StartLine")
    if mode != "dir" or not path or not isinstance(start, int) or start < 1:
        return False
    end = finding.get("EndLine") if isinstance(finding.get("EndLine"), int) else start
    try:
        with (repo / path).open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno > end:
                    break
                if lineno >= start and INLINE_ALLOW_MARKER in line:
                    return True
    except OSError:
        return False
    return False


def _describe(candidate: Mapping[str, Any]) -> str:
    text = candidate.get("description", "")
    if candidate.get("inline_allow"):
        note = (
            "The target marks this line gitleaks:allow; a suppression shipped "
            "by the audited repo is not an exemption, judge the candidate."
        )
        text = f"{text} ({note})" if text else note
    return text
