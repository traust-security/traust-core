"""grype's vulnerability candidates over an SBOM or a directory: one per (CVE, package), never a
verdict (the code path may be unreachable or the package unused)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.providers.tools.adapter import adapter_result
from traust_core.v1.providers.tools.toolchain import freeze_env

SCAN_SECONDS = 600.0
_CWE = re.compile(r"CWE-(\d+)")


def command(target: str, grype_bin: str = "grype", output_format: str = "json") -> list[str]:
    """The argv a grype scan of `target` runs."""
    return [grype_bin, target, "-o", output_format]


def parse_matches(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """grype JSON's matches as adapter findings."""
    findings: list[dict[str, Any]] = []
    for match in doc.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related = match.get("relatedVulnerabilities", [])
        vuln_id = vuln.get("id", "UNKNOWN")
        description = vuln.get("description", "")
        if not description and related:
            description = related[0].get("description", "")
        fixed_in = (
            ", ".join(fix.get("version", "?") for fix in vuln.get("fix", {}).get("versions", []))
            or None
        )
        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        locations = [{"path": loc.get("path", "")} for loc in artifact.get("locations", [])]
        findings.append(
            {
                "id": f"{vuln_id}:{pkg_name}@{pkg_version}",
                "title": f"{vuln_id} in {pkg_name} {pkg_version}",
                "severity": vuln.get("severity", "unknown").lower() or "low",
                "cwes": [
                    f"CWE-{m.group(1)}"
                    for url in vuln.get("urls", [])
                    if "cwe.mitre.org" in url and (m := _CWE.search(url))
                ],
                "locations": locations or [{"path": f"{artifact.get('type', '')}:{pkg_name}"}],
                "description": description[:2000],
                "remediation": f"Upgrade {pkg_name} to {fixed_in}" if fixed_in else "",
                "category": "dependency_vulnerability",
            }
        )
    return findings


def scan(
    target: Path,
    process: ProcessRunner,
    clock: Clock,
    *,
    scanner_version: str,
    freeze: bool = True,
) -> AdapterResultArtifact:
    """grype over `target`; `freeze` (the default) stops it updating its database mid-scan.
    Exit 1 means matches were found, anything else above it is a failure."""
    done = process.run(
        command(str(target)),
        env=freeze_env("grype") if freeze else None,
        check=False,
        timeout_seconds=SCAN_SECONDS,
    )
    if done.returncode not in (0, 1):
        err = done.stderr.decode(errors="replace").strip()[:500]
        raise RuntimeError(f"grype failed (exit {done.returncode}): {err}")
    return adapter_result(
        str(target),
        "grype",
        parse_matches(json.loads(done.stdout)),
        scanned_at=clock.now(),
        scanner_version=scanner_version,
    )
