"""grype's candidates: the scan's argv and env, its exit codes, and the matches as findings.
Ported from traust-engine's test_adapter_contract_boundary grype cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.v1.providers.tools.osv_support import CLOCK, STAMP
from traust_core.v1.errors import DocumentError
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import grype

MATCHES = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2026-0001",
                "severity": "High",
                "urls": [
                    "https://cwe.mitre.org/CWE-79",
                    "https://cwe.mitre.org/x",
                    "https://x.test",
                ],
                "fix": {"versions": [{"version": "1.1"}, {"version": "1.2"}]},
            },
            "relatedVulnerabilities": [{"description": "from the related record"}],
            "artifact": {
                "name": "example-package",
                "type": "rpm",
                "version": "1.0",
                "locations": [{"path": "usr/lib/example.so"}],
            },
        },
        {
            "vulnerability": {"id": "CVE-2026-0002", "severity": "Low", "description": "own"},
            "artifact": {"name": "lib", "type": "npm", "version": "2.0"},
        },
    ]
}


class Runner:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.result = (returncode, stdout, stderr)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(self, argv: list[str], **kw: Any) -> ProcessResult:
        self.calls.append((list(argv), kw))
        return ProcessResult(tuple(argv), *self.result, 0.1)


def test_the_command_scans_the_target_as_json() -> None:
    assert grype.command("/sbom.json") == ["grype", "/sbom.json", "-o", "json"]


def test_matches_become_findings_with_cwes_fix_and_locations() -> None:
    first, second = grype.parse_matches(MATCHES)
    assert first == {
        "id": "CVE-2026-0001:example-package@1.0",
        "title": "CVE-2026-0001 in example-package 1.0",
        "severity": "high",
        "cwes": ["CWE-79"],
        "locations": [{"path": "usr/lib/example.so"}],
        "description": "from the related record",
        "remediation": "Upgrade example-package to 1.1, 1.2",
        "category": "dependency_vulnerability",
    }
    assert second["locations"] == [{"path": "npm:lib"}]  # no locations: the package itself
    assert (second["description"], second["remediation"], second["cwes"]) == ("own", "", [])
    assert grype.parse_matches({}) == []


def test_package_locations_survive_conversion(tmp_path: Path) -> None:
    runner = Runner(1, json.dumps(MATCHES).encode())
    result = grype.scan(tmp_path, runner, CLOCK, scanner_version="0.115.0")  # type: ignore[arg-type]
    assert result.findings[0].locations[0].path == "usr/lib/example.so"
    assert result.metadata.tool == "grype" and result.metadata.scanner_version == "0.115.0"
    doc = json.loads(result.payload)
    assert (doc["target"], doc["scanned_at"]) == (str(tmp_path), STAMP)
    assert doc["summary"] == {"total": 2, "by_severity": {"high": 1, "low": 1}}


def test_the_scan_freezes_the_database_by_default(tmp_path: Path) -> None:
    runner = Runner(0, b'{"matches": []}')
    grype.scan(tmp_path, runner, CLOCK, scanner_version="")  # type: ignore[arg-type]
    grype.scan(tmp_path, runner, CLOCK, scanner_version="", freeze=False)  # type: ignore[arg-type]
    (argv, frozen), (_, thawed) = runner.calls
    assert argv == ["grype", str(tmp_path), "-o", "json"]
    assert frozen == {
        "env": {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"},
        "check": False,
        "timeout_seconds": grype.SCAN_SECONDS,
    }
    assert thawed["env"] is None


def test_an_exit_above_one_is_a_tool_failure(tmp_path: Path) -> None:
    runner = Runner(2, b"", b"db is stale " * 100)
    with pytest.raises(RuntimeError, match=r"grype failed \(exit 2\): db is stale") as raised:
        grype.scan(tmp_path, runner, CLOCK, scanner_version="")  # type: ignore[arg-type]
    assert len(str(raised.value)) < 600


def test_output_that_is_not_json_is_a_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        grype.scan(tmp_path, Runner(0, b"oops"), CLOCK, scanner_version="")  # type: ignore[arg-type]


@pytest.mark.parametrize("severity", ["Unknown", "urgent"])
def test_native_unknown_scanner_severity_cannot_be_relabelled_as_low(
    tmp_path: Path, severity: str
) -> None:
    raw = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2026-0001", "severity": severity},
                "artifact": {"name": "fixture", "type": "rpm", "version": "1"},
            }
        ]
    }
    with pytest.raises(DocumentError):
        grype.scan(tmp_path, Runner(1, json.dumps(raw).encode()), CLOCK, scanner_version="")  # type: ignore[arg-type]


def test_an_empty_severity_reads_as_low() -> None:
    raw = {"matches": [{"vulnerability": {"id": "X", "severity": ""}, "artifact": {}}]}
    assert grype.parse_matches(raw)[0]["severity"] == "low"


def test_a_fix_listed_as_grype_prints_it_still_fails_as_in_the_engine() -> None:
    # grype prints fix versions as strings; the engine read dicts and failed on them. Kept as is
    raw = {"matches": [{"vulnerability": {"id": "X", "fix": {"versions": ["1.1"]}}}]}
    with pytest.raises(AttributeError):
        grype.parse_matches(raw)
