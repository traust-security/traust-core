from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CheckoutForge, NoCheckouts
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ConfigError, NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.rule_calibration import RuleCalibrationRequest
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools import rule_calibration
from traust_core.v1.providers.tools.rule_calibration import OpengrepCalibration

RULE = """rules:
  - id: demo
    languages: [python]
    message: synthetic calibration sink
    severity: WARNING
    pattern: danger($X)
    metadata:
      cwe: [CWE-78]
"""


class ScannerProcess(ProcessRunner):
    def __init__(self, raw: bytes | None = None, returncode: int = 0) -> None:
        super().__init__(["opengrep"])
        self.raw = (
            raw
            if raw is not None
            else json.dumps({"results": [], "paths": {"scanned": ["a.py"]}, "errors": []}).encode()
        )
        self.returncode = returncode
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
        self.calls.append(tuple(argv))
        return ProcessResult(
            tuple(argv), self.returncode, b"1.2.3\n" if "--version" in argv else self.raw, b"", 0
        )


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    root = tmp_path / "pack"
    root.mkdir()
    (root / "demo.yaml").write_text(RULE)
    return root


def provider(pack: Path, runner: ProcessRunner | None = None) -> OpengrepCalibration:
    return OpengrepCalibration(
        pack, lambda: (), NoCheckouts(), runner or ScannerProcess(), yaml_documents
    )


@pytest.fixture
def ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rule_calibration, "on_path", lambda _: Readiness(ready=True))


def test_fixture_sanity_scans_external_tests_without_any_corpus(pack: Path, ready: None) -> None:
    (pack / "tests").mkdir()
    (pack / "tests" / "a.py").write_text("danger(user_input)\n")
    scanner = provider(pack)
    request = RuleCalibrationRequest(fixtures=True, rules=str(pack))
    with scanner.prepare(request) as prepared:
        result = scanner.fixtures(prepared, request)
    assert result.target == pack / "tests"
    assert result.scan.complete
    assert result.scan.files_scanned == 1


def test_colocated_annotated_fixtures_are_supported(pack: Path, ready: None) -> None:
    (pack / "demo.py").write_text("# ruleid: demo\ndanger(user_input)\n")
    scanner = provider(pack)
    request = RuleCalibrationRequest(fixtures=True, rules=str(pack / "demo.yaml"))
    with scanner.prepare(request) as prepared:
        assert tuple(r.id for r in prepared.pack.rules) == ("demo",)
        assert scanner.fixtures(prepared, request).scan.complete


@pytest.mark.parametrize("tree", ["absent", "empty", "readme-only"])
def test_missing_fixture_tree_is_not_a_green_sanity_scan(
    pack: Path, ready: None, tree: str
) -> None:
    if tree == "empty":
        (pack / "tests").mkdir()
    if tree == "readme-only":
        (pack / "README.md").write_text("Use # ruleid: demo in a fixture")
    scanner = provider(pack)
    request = RuleCalibrationRequest(fixtures=True)
    with scanner.prepare(request) as prepared, pytest.raises(NotFoundError, match="fixture"):
        scanner.fixtures(prepared, request)


@pytest.mark.parametrize(
    ("raw", "returncode"),
    [
        ({"results": [], "paths": {"scanned": []}}, 0),
        ({"results": [], "paths": {"scanned": ["a.py"]}}, 2),
        ({"results": [], "paths": {"scanned": ["a.py"]}, "errors": [{"message": "parse"}]}, 0),
        ({"results": [], "paths": {"scanned": ["a.py"]}, "skipped_rules": ["demo"]}, 0),
    ],
)
def test_incomplete_scans_never_claim_success(
    pack: Path, ready: None, raw: dict[str, Any], returncode: int
) -> None:
    scanner = provider(pack, ScannerProcess(json.dumps(raw).encode(), returncode))
    request = RuleCalibrationRequest()
    with scanner.prepare(request) as prepared:
        assert not scanner.scan(prepared, pack, request).complete


def test_non_json_scanner_output_is_a_meaningful_failure(pack: Path, ready: None) -> None:
    scanner = provider(pack, ScannerProcess(b"scanner failed"))
    request = RuleCalibrationRequest()
    with scanner.prepare(request) as prepared, pytest.raises(ServiceError, match="no JSON"):
        scanner.scan(prepared, pack, request)


def test_missing_scanner_is_refused_before_preparing_rules(
    pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        rule_calibration, "on_path", lambda _: Readiness(ready=False, detail="missing")
    )
    with (
        pytest.raises(ConfigError),
        provider(pack).prepare(RuleCalibrationRequest(fixtures=True)),
    ):
        pytest.fail("unavailable scanner was admitted")


def test_external_rules_checkout_is_commit_pinned_and_released(
    pack: Path, tmp_path: Path, ready: None
) -> None:
    forge = CheckoutForge(tmp_path)
    sha = forge.commit({"rules/demo.yaml": RULE, "tests/a.py": "danger(user_input)\n"})
    checkouts = forge.service()
    scanner = OpengrepCalibration(pack, lambda: (), checkouts, ScannerProcess(), yaml_documents)
    request = RuleCalibrationRequest(rules=f"{forge.url}@{sha}", fixtures=True)
    with scanner.prepare(request) as prepared:
        assert prepared.pack.version == str(sha)
        path = prepared.root
        assert scanner.fixtures(prepared, request).scan.complete
    assert not path.exists()


def test_movable_external_rules_source_is_rejected(pack: Path, ready: None) -> None:
    request = RuleCalibrationRequest(rules="https://github.com/example/rules@main")
    with pytest.raises(ValidationError, match="40-hex"), provider(pack).prepare(request):
        pytest.fail("movable source admitted")


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep is not installed")
def test_real_opengrep_fixture_scan_is_runnable(pack: Path) -> None:
    (pack / "tests").mkdir()
    (pack / "tests" / "a.py").write_text("danger(user_input)\n")
    scanner = provider(pack, ProcessRunner(["opengrep"]))
    request = RuleCalibrationRequest(fixtures=True)
    with scanner.prepare(request) as prepared:
        result = scanner.fixtures(prepared, request)
    assert result.scan.complete
    assert result.scan.files_scanned == 1
    assert [h.rule for h in result.scan.hits] == ["demo"]


def test_fixture_symlink_cannot_leave_the_checked_out_pack(
    pack: Path, tmp_path: Path, ready: None
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("danger(user_input)\n")
    (pack / "tests").symlink_to(outside, target_is_directory=True)
    scanner = provider(pack)
    request = RuleCalibrationRequest(fixtures=True)
    with scanner.prepare(request) as prepared, pytest.raises(ValidationError, match="leaves"):
        scanner.fixtures(prepared, request)


def test_explicit_rules_do_not_need_the_registered_pack_tree(
    pack: Path, tmp_path: Path, ready: None
) -> None:
    (pack / "tests").mkdir()
    (pack / "tests" / "a.py").write_text("danger(user_input)\n")
    scanner = provider(tmp_path / "missing-registered-pack")
    request = RuleCalibrationRequest(fixtures=True, rules=str(pack))
    with scanner.prepare(request) as prepared:
        assert scanner.fixtures(prepared, request).scan.complete


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep is not installed")
def test_real_opengrep_colocated_test_path_is_scanned(pack: Path) -> None:
    (pack / "go.yaml").write_text(RULE.replace("languages: [python]", "languages: [go]"))
    (pack / "demo_test.go").write_text(
        "package demo\n\nfunc example() {\n\t// ruleid: demo\n\tdanger(userInput)\n}\n"
    )
    scanner = provider(pack, ProcessRunner(["opengrep"]))
    request = RuleCalibrationRequest(fixtures=True, rules=str(pack / "go.yaml"))
    with scanner.prepare(request) as prepared:
        result = scanner.fixtures(prepared, request)
    assert result.scan.complete
    assert result.scan.files_scanned == 1
    [hit] = result.scan.hits
    assert hit.rule == "demo"
    assert hit.path == "demo_test.go"


def test_fixture_tree_without_supported_sources_is_refused(pack: Path, ready: None) -> None:
    (pack / "tests").mkdir()
    (pack / "tests" / "README.txt").write_text("Run the archived fixture source separately.")
    scanner = provider(pack)
    request = RuleCalibrationRequest(fixtures=True)
    with scanner.prepare(request) as prepared, pytest.raises(NotFoundError):
        scanner.fixtures(prepared, request)
