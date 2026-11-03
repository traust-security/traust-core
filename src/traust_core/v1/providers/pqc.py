from __future__ import annotations

import hashlib
import re
import tempfile
from pathlib import Path
from typing import Protocol

from pydantic import Field

from traust_core.v1.errors import (
    ConfigError,
    IntegrityError,
    ServiceError,
    TraustError,
    ValidationError,
)
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.pqc import PqcScan, PqcScanFinding, PqcStamps
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner


class PqcScanner(Protocol):
    """The pinned Layer-1 scanner: raw rule hits over a checkout, stamped with its pack."""

    name: str

    def check(self) -> Readiness: ...

    def stamps(self) -> PqcStamps:
        """What a scan by the current binary and rules pack would be stamped with."""
        ...

    def scan(self, request: ToolRequest) -> Result[PqcScan]: ...


class ScannerSummary(Dto):
    scanned_files: int = Field(ge=0, strict=True)
    skipped_files: int = Field(ge=0, strict=True)


class ScannerReport(Dto):
    summary: ScannerSummary
    findings: tuple[dict[str, object], ...]


class PqcScanTool:
    name = "pqc-scan"

    def __init__(
        self,
        process: ProcessRunner,
        clock: Clock,
        binary: Path,
        rules: Path,
        *,
        adapter_version: str,
        scan_commit: str,
    ) -> None:
        self._process, self._clock = process, clock
        self._binary, self._rules = binary.resolve(), rules.resolve()
        self._adapter_version, self._scan_commit = adapter_version, scan_commit

    def check(self) -> Readiness:
        if not self._process.allows(str(self._binary)):
            return Readiness(ready=False, detail="pqc-scan is not in process.allowed_binaries")
        try:
            if self.stamps().binary_sha256 is None:
                return Readiness(ready=False, detail=f"pqc-scan binary is missing: {self._binary}")
        except (OSError, TraustError) as exc:
            return Readiness(ready=False, detail=str(exc))
        return Readiness(ready=True)

    def stamps(self) -> PqcStamps:
        files = sorted(self._rules.glob("*.yml"))
        if not files:
            raise ConfigError(f"pqc-scan rules pack is empty: {self._rules}")
        digest = hashlib.sha256()
        for file in files:
            digest.update(file.name.encode())
            digest.update(file.read_bytes())
        binary_sha = None
        if self._binary.is_file():
            with self._binary.open("rb") as stream:
                binary_sha = hashlib.file_digest(stream, "sha256").hexdigest()
            recorded = self._binary.with_suffix(".sha256").read_text().split()
            if not recorded or recorded[0] != binary_sha:
                raise IntegrityError("pqc-scan binary does not match its recorded checksum")
        return PqcStamps(
            adapter_version=self._adapter_version,
            pqc_scan_commit=self._scan_commit,
            rules_sha256=digest.hexdigest(),
            binary_sha256=binary_sha,
        )

    def scan(self, request: ToolRequest) -> Result[PqcScan]:
        stamps = self.stamps()
        if stamps.binary_sha256 is None:
            raise ConfigError(f"pqc-scan binary is missing: {self._binary}")
        rules = sum(
            len(re.findall(r"(?m)^- id:", file.read_text())) for file in self._rules.glob("*.yml")
        )
        if rules == 0:
            raise ConfigError("pqc-scan pack has no rules")
        with tempfile.TemporaryDirectory(prefix="pqc-scan-") as directory:
            output = Path(directory)
            done = self._process.run(
                [
                    str(self._binary),
                    "scan",
                    str(request.checkout()),
                    "--rules-dir",
                    str(self._rules),
                    "--format",
                    "all",
                    "--out-dir",
                    str(output),
                ],
                check=False,
                timeout_seconds=1800,
            )
            if done.returncode != 0:
                raise ServiceError(f"pqc-scan failed (exit {done.returncode})")
            try:
                raw = ScannerReport.model_validate_json((output / "report.json").read_bytes())
                findings = tuple(_finding(item) for item in raw.findings)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise ValidationError("pqc-scan produced a missing or malformed report") from exc
            if self.stamps() != stamps:
                raise IntegrityError("pqc-scan binary or rules changed while scanning")
            cbom = output / "cbom.json"
            scan = PqcScan(
                findings=findings,
                scanned_files=raw.summary.scanned_files,
                skipped_files=raw.summary.skipped_files,
                rules_in_pack=rules,
                stamps=stamps,
                cbom=cbom.read_bytes() if cbom.is_file() else None,
            )
        return Result(scan, Acquisition(provider=self.name, acquired_at=self._clock.now()))


def _finding(item: dict[str, object]) -> PqcScanFinding:
    location = item.get("location") or {}
    evidence = item.get("evidence") or {}
    if not isinstance(location, dict) or not isinstance(evidence, dict):
        raise ValidationError("pqc-scan finding has invalid location or evidence")
    return PqcScanFinding.model_validate(
        {
            "rule_id": item["rule_id"],
            "file": location.get("file", ""),
            "line": location.get("line"),
            "finding_id": item.get("finding_id"),
            "severity": item.get("severity"),
            "risk": item.get("risk"),
            "confidence": item.get("confidence"),
            "detail": str(item.get("description") or "")[:200],
            "match": str(evidence.get("match") or item.get("source_snippet") or "")[:120],
        }
    )
