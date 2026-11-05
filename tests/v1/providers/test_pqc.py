from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ConfigError, IntegrityError, ServiceError, ValidationError
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.pqc import PqcScanTool
from traust_core.v1.providers.process import ProcessRunner

AT = datetime(2026, 10, 24, tzinfo=UTC)


def scanner(tmp_path: Path, report: object, *, code: int = 0) -> PqcScanTool:
    binary = tmp_path / "pqc-scan"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--out-dir') + 1])\n"
        f"(output / 'report.json').write_text({json.dumps(report)!r})\n"
        "(output / 'cbom.json').write_bytes(b'cbom-fixture')\n"
        f"sys.exit({code})\n"
    )
    binary.chmod(0o700)
    binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "one.yml").write_text("- id: API_RSA\n  pattern: rsa\n")
    return PqcScanTool(
        ProcessRunner(["pqc-scan"]),
        FixedClock(AT),
        binary,
        rules,
        adapter_version="1.4.0",
        scan_commit="be5c760",
    )


def test_real_process_output_becomes_stamped_facts_not_a_readiness_score(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 2, "skipped_files": 1},
            "findings": [
                {
                    "rule_id": "API_RSA",
                    "description": "RSA signing",
                    "location": {"file": "keys.go", "line": 4},
                    "evidence": {"match": "rsa.GenerateKey"},
                }
            ],
        },
    )
    result = provider.scan(ToolRequest(workspace=tmp_path))
    assert result.acquisition.acquired_at == AT
    assert (result.data.scanned_files, result.data.skipped_files, result.data.rules_in_pack) == (
        2,
        1,
        1,
    )
    assert [(f.rule_id, f.file, f.line, f.match) for f in result.data.findings] == [
        ("API_RSA", "keys.go", 4, "rsa.GenerateKey"),
    ]
    assert result.data.stamps == provider.stamps()
    assert result.data.cbom == b"cbom-fixture"
    assert provider.check().ready


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"summary": {"scanned_files": 1, "skipped_files": 0}},
        {"summary": {"scanned_files": -1, "skipped_files": 0}, "findings": []},
        {"summary": {"scanned_files": 1, "skipped_files": 0}, "findings": [{}]},
    ],
)
def test_incomplete_output_cannot_masquerade_as_a_clean_scan(
    tmp_path: Path, report: object
) -> None:
    provider = scanner(tmp_path, report)
    with pytest.raises(ValidationError):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_nonzero_exit_is_not_accepted_even_with_a_report(tmp_path: Path) -> None:
    provider = scanner(
        tmp_path,
        {
            "summary": {"scanned_files": 1, "skipped_files": 0},
            "findings": [],
        },
        code=7,
    )
    with pytest.raises(ServiceError):
        provider.scan(ToolRequest(workspace=tmp_path))


def test_binary_checksum_and_empty_rules_are_hard_boundaries(tmp_path: Path) -> None:
    provider = scanner(tmp_path, {})
    (tmp_path / "pqc-scan").write_text("changed binary")
    with pytest.raises(IntegrityError):
        provider.stamps()
    (tmp_path / "rules/one.yml").unlink()
    with pytest.raises(ConfigError):
        provider.stamps()
    assert not provider.check().ready
