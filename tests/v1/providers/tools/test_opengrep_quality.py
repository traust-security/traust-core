from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import NoCheckouts
from tests.v1.providers.tools.opengrep_fixtures import native_output, write_rule
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ScannerError, ScannerFailure, ValidationError
from traust_core.v1.models.rule_mining import RuleFile, SweepRepo
from traust_core.v1.providers.process import (
    ProcessError,
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
)
from traust_core.v1.providers.tools import detection_quality as sweep_provider
from traust_core.v1.providers.tools.opengrep import SupplementalPack, execute_scan
from traust_core.v1.providers.tools.opengrep_quality import RuleQualityError, checked_rules


class NativeRunner:
    def __init__(self, failure: str = "") -> None:
        self.failure = failure
        self.scanned = False
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
        args = tuple(argv)
        self.calls.append(args)
        output = native_output(args)
        code = 0
        if args[1] == "validate":
            if self.failure == "validate-exit":
                code = 123
            elif self.failure == "validate-skipped":
                output = b"0 fatal errors, 1 skippable error(s)"
        elif args[1] == "test":
            if self.failure == "test-exit":
                code = 123
            data = json.loads(output)
            checks = next(iter(data["results"].values()))["checks"]
            check = next(iter(checks.values()))
            if self.failure == "test-empty":
                data["results"] = {}
            elif self.failure == "test-no-assertions":
                for match in check["matches"].values():
                    match["expected_lines"] = []
                    match["reported_lines"] = []
            elif self.failure == "test-unexpected":
                next(iter(check["matches"].values()))["reported_lines"].append(99)
            elif self.failure == "test-errors":
                check["errors"] = ["partial parse"]
            elif self.failure == "test-missing-fixture":
                data["config_missing_tests"] = ["rules.yaml"]
            elif self.failure == "test-wrong-type":
                check["passed"] = "true"
            output = json.dumps(data).encode()
        elif args[1] == "scan":
            self.scanned = True
            output = b'{"results":[],"errors":[],"paths":{"scanned":["app.py"]}}'
            if self.failure == "scan-exit":
                code = 7
            elif self.failure == "scan-malformed":
                output = b"PRIVATE_NATIVE_SENTINEL"
            elif self.failure == "scan-shape":
                output = b'{"results":"PRIVATE_NATIVE_SENTINEL"}'
            elif self.failure == "scan-timeout":
                raise ProcessTimeout(
                    args, subprocess.TimeoutExpired(args, 30, output=b"PRIVATE_NATIVE_SENTINEL")
                )
        elif args[1] == "--version":
            output = b"1.25.0"
        return ProcessResult(args, code, output or b"", b"", 0.01)


@pytest.mark.parametrize(
    "failure",
    [
        "validate-exit",
        "validate-skipped",
        "test-exit",
        "test-empty",
        "test-no-assertions",
        "test-unexpected",
        "test-errors",
        "test-missing-fixture",
        "test-wrong-type",
    ],
)
def test_failed_native_quality_never_scans_the_checkout(tmp_path: Path, failure: str) -> None:
    config = write_rule(tmp_path / "pack")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    runner = NativeRunner(failure)
    with pytest.raises(RuleQualityError):
        execute_scan(
            target,
            [],
            pack=config.parent,
            runner=runner,
            checkouts=NoCheckouts(),
            load=yaml_documents,
        )
    assert not runner.scanned


@pytest.mark.parametrize(
    "example",
    ["# ruleid: example-rule\ndangerous(value)\n", "# ok: example-rule\nsafe(value)\n"],
)
def test_native_success_without_both_behavior_directions_is_refused(
    tmp_path: Path, example: str
) -> None:
    config = write_rule(tmp_path / "pack")
    config.with_suffix(".py").write_text(example)
    with checked_rules([config.parent], NativeRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert "both ruleid: and ok:" in checked.report.checks[-1].detail


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
@pytest.mark.parametrize("negative_in_matching_fixture", [False, True])
def test_only_native_matching_fixtures_provide_negative_coverage(
    tmp_path: Path, negative_in_matching_fixture: bool
) -> None:
    config = write_rule(tmp_path / "pack", name="policy")
    negative = "# ok: example-rule\nsafe(value)\n"
    config.with_suffix(".py").write_text(
        "# ruleid: example-rule\ndangerous(value)\n"
        + (negative if negative_in_matching_fixture else "")
    )
    config.with_name("policy.fixed.py").write_text(negative)
    with checked_rules(
        [config.parent], ProcessRunner(("opengrep",)), load=yaml_documents
    ) as checked:
        assert checked.report.checks[0].passed
        assert checked.report.passed is negative_in_matching_fixture
        if not negative_in_matching_fixture:
            assert "native matching fixtures" in checked.report.checks[-1].detail


def test_duplicate_rule_ids_are_not_an_ambiguous_pack(tmp_path: Path) -> None:
    write_rule(tmp_path, name="first")
    write_rule(tmp_path, name="second")
    with checked_rules([tmp_path], NativeRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert "duplicate rule id" in checked.report.checks[0].detail


def test_a_fixture_cannot_read_outside_the_pack(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "pack")
    config.with_suffix(".py").unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("private = 1\n")
    config.with_suffix(".py").symlink_to(outside)
    with (
        pytest.raises(ValidationError, match="leaves its source directory"),
        checked_rules([config.parent], NativeRunner(), load=yaml_documents),
    ):
        pass


def test_an_abnormal_scan_exit_is_not_accepted_because_json_exists(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "pack")
    with pytest.raises(ScannerError, match="exited 7") as caught:
        execute_scan(
            tmp_path,
            [],
            pack=config.parent,
            runner=NativeRunner("scan-exit"),
            checkouts=NoCheckouts(),
            load=yaml_documents,
        )
    assert caught.value.reason is ScannerFailure.EXIT
    assert caught.value.exit_code == 7


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
def test_real_native_gate_enables_a_namespaced_local_adopter_rule(tmp_path: Path) -> None:
    builtin = write_rule(tmp_path / "builtin", "builtin-rule")
    custom = write_rule(tmp_path / "custom", "acme.security.rule")
    custom.write_text("# Adopted rule — UTF-8 source\n" + custom.read_text(), encoding="utf-8")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\nsafe(value)\n")
    result = execute_scan(
        target,
        [],
        pack=builtin.parent,
        runner=ProcessRunner(("opengrep",), keep_env=("PATH", "HOME")),
        checkouts=NoCheckouts(),
        load=yaml_documents,
        supplements=(SupplementalPack("acme", str(custom.parent), ("acme.security.rule",)),),
    )
    assert {fact["rule_id"] for fact in result["facts"]} == {"builtin-rule", "acme.security.rule"}
    assert result["supplemental_packs"]["applied"] == ["acme"]
    assert all(check["passed"] for check in result["quality_checks"])


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
def test_invalid_adopter_behavior_does_not_fall_back_to_builtin_rules(tmp_path: Path) -> None:
    builtin = write_rule(tmp_path / "builtin", "builtin-rule")
    custom = write_rule(tmp_path / "custom", "acme-rule")
    fixture = custom.with_suffix(".py")
    fixture.write_text(fixture.read_text().replace("safe(value)", "dangerous(value)"))
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    with pytest.raises(RuleQualityError):
        execute_scan(
            target,
            [],
            pack=builtin.parent,
            runner=ProcessRunner(("opengrep",)),
            checkouts=NoCheckouts(),
            load=yaml_documents,
            supplements=(SupplementalPack("acme", str(custom.parent), ("acme-rule",)),),
        )


@pytest.mark.parametrize("phase", ["validate", "test", "test-schema", "validate-process"])
def test_native_quality_diagnostics_never_disclose_process_contents(
    tmp_path: Path, phase: str
) -> None:
    sentinel = "PRIVATE_NATIVE_SENTINEL"

    class SensitiveRunner(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            result = super().run(argv, **kwargs)
            if argv[1] != phase.split("-")[0]:
                return result
            sensitive = ProcessResult(tuple(argv), 7, sentinel.encode(), sentinel.encode(), 0.01)
            if phase.endswith("-process"):
                raise ProcessError(sensitive)
            if phase.endswith("-schema"):
                return ProcessResult(
                    tuple(argv), 0, json.dumps({"results": sentinel}).encode(), b"", 0.01
                )
            return sensitive

    config = write_rule(tmp_path)
    with checked_rules([config], SensitiveRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert sentinel not in checked.report.model_dump_json()
        assert sentinel not in str(RuleQualityError(checked.report))


def test_yaml_parser_diagnostics_never_disclose_rule_contents(tmp_path: Path) -> None:
    config = tmp_path / "rule.yaml"
    config.write_text("rules: [PRIVATE_NATIVE_SENTINEL\n")
    with checked_rules([config], NativeRunner(), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert "PRIVATE_NATIVE_SENTINEL" not in checked.report.model_dump_json()


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("scan-exit", ScannerFailure.EXIT),
        ("scan-malformed", ScannerFailure.OUTPUT),
        ("scan-shape", ScannerFailure.OUTPUT),
        ("scan-timeout", ScannerFailure.TIMEOUT),
    ],
)
def test_scan_failures_preserve_real_quality_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, reason: ScannerFailure
) -> None:
    config = write_rule(tmp_path / "pack")
    runner = NativeRunner(failure)
    monkeypatch.setattr(sweep_provider, "ProcessRunner", lambda *args, **kwargs: runner)
    sweeper = sweep_provider.OpengrepRuleSweep(
        config.parent, (), NoCheckouts(), load=yaml_documents
    )
    found = sweeper.scan(
        SweepRepo(slug="repo", url=f"dir:{tmp_path}"),
        RuleFile(path=config, ids=("example-rule",), unauthored=False),
        "opengrep",
        30,
    )
    assert found.error == reason
    assert {check.name for check in found.quality_checks} == {"validate", "test"}
    assert all(check.passed for check in found.quality_checks)
    assert "PRIVATE_NATIVE_SENTINEL" not in found.model_dump_json()
    assert runner.scanned


def test_bad_rule_quality_raises_before_any_remote_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_rule(tmp_path / "pack")
    config.with_suffix(".py").write_text("# ruleid: example-rule\ndangerous(value)\n")
    runner = NativeRunner()
    monkeypatch.setattr(sweep_provider, "ProcessRunner", lambda *args, **kwargs: runner)
    sweeper = sweep_provider.OpengrepRuleSweep(
        config.parent, (), NoCheckouts(), load=yaml_documents
    )
    with pytest.raises(RuleQualityError):
        sweeper.scan(
            SweepRepo(slug="remote", url="https://github.com/example/repo", sha="a" * 40),
            RuleFile(path=config, ids=("example-rule",), unauthored=False),
            "opengrep",
            30,
        )
    assert not runner.scanned


def test_a_batch_uses_only_its_checked_snapshot_and_rechecks_changed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_rule(tmp_path / "pack")
    runner = NativeRunner()
    monkeypatch.setattr(sweep_provider, "ProcessRunner", lambda *args, **kwargs: runner)
    sweeper = sweep_provider.OpengrepRuleSweep(
        config.parent, (), NoCheckouts(), load=yaml_documents
    )
    rule = RuleFile(path=config, ids=("example-rule",), unauthored=False)
    original = config.read_text()
    with sweeper.batch(rule, "opengrep", 30) as batch:
        digest = batch.rule_digest
        config.write_text("rules: [PRIVATE_NATIVE_SENTINEL\n")
        for slug in ("first", "second"):
            assert batch.scan(SweepRepo(slug=slug, url=f"dir:{tmp_path}")).error is None
        scanned_configs = [
            Path(call[call.index("--config") + 1]) for call in runner.calls if call[1] == "scan"
        ]
        assert len(scanned_configs) == 2
        assert all(path.read_text() == original for path in scanned_configs)
        assert all(path != config for path in scanned_configs)
    assert [call[1] for call in runner.calls] == ["validate", "test", "scan", "scan"]
    with pytest.raises(RuleQualityError), sweeper.batch(rule, "opengrep", 30):
        pytest.fail("changed invalid input cannot reuse a prior native receipt")
    config.write_text(original)
    fixture = config.with_suffix(".py")
    fixture.write_text(fixture.read_text() + "\n# a changed but valid fixture\n")
    with sweeper.batch(rule, "opengrep", 30) as changed:
        assert changed.rule_digest != digest


def test_snapshot_digest_is_independent_of_temporary_directory_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_rule(tmp_path / "pack")
    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(temporary_root, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(alias))
    with checked_rules([config], NativeRunner(), load=yaml_documents) as aliased:
        assert aliased.report.passed
        digest = aliased.digest
    monkeypatch.setattr(tempfile, "tempdir", str(temporary_root))
    with checked_rules([config], NativeRunner(), load=yaml_documents) as direct:
        assert direct.report.passed
        assert direct.digest == digest


def test_unrelated_runtime_errors_are_not_reported_as_scanner_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BuggyRunner(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if argv[1] == "scan":
                raise RuntimeError("unrelated application defect")
            return super().run(argv, **kwargs)

    config = write_rule(tmp_path)
    monkeypatch.setattr(sweep_provider, "ProcessRunner", lambda *args, **kwargs: BuggyRunner())
    sweeper = sweep_provider.OpengrepRuleSweep(tmp_path, (), NoCheckouts(), load=yaml_documents)
    with pytest.raises(RuntimeError, match="unrelated application defect"):
        sweeper.scan(
            SweepRepo(slug="repo", url=f"dir:{tmp_path}"),
            RuleFile(path=config, ids=("example-rule",), unauthored=False),
            "opengrep",
            30,
        )


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
@pytest.mark.parametrize("failure", ["validate", "test"])
def test_real_native_rule_failures_never_serialize_private_fixture_text(
    tmp_path: Path, failure: str
) -> None:
    sentinel = "PRIVATE_NATIVE_SENTINEL"
    config = write_rule(tmp_path)
    if failure == "validate":
        config.write_text(config.read_text().replace("dangerous($X)", f"{sentinel}("))
    else:
        config.with_suffix(".py").write_text(
            f"# ruleid: example-rule\n{sentinel}(value)\n# ok: example-rule\nsafe(value)\n"
        )
    with checked_rules([config], ProcessRunner(["opengrep"]), load=yaml_documents) as checked:
        assert not checked.report.passed
        assert sentinel not in checked.report.model_dump_json()


def test_version_output_cannot_serialize_private_native_text(tmp_path: Path) -> None:
    class SensitiveVersion(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if argv[1] == "--version":
                return ProcessResult(tuple(argv), 0, b"PRIVATE_NATIVE_SENTINEL", b"", 0.01)
            return super().run(argv, **kwargs)

    config = write_rule(tmp_path / "pack")
    with pytest.raises(ScannerError) as caught:
        execute_scan(
            tmp_path,
            [],
            pack=config.parent,
            runner=SensitiveVersion(),
            checkouts=NoCheckouts(),
            load=yaml_documents,
        )
    assert caught.value.reason is ScannerFailure.OUTPUT
    assert "PRIVATE_NATIVE_SENTINEL" not in str(caught.value)
