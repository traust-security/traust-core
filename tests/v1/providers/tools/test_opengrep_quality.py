from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import NoCheckouts
from tests.v1.providers.tools.opengrep_fixtures import native_output, write_rule
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ScannerError, ScannerFailure, ValidationError
from traust_core.v1.models.rule_mining import RuleFile, SweepRepo
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import (
    ProcessError,
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
)
from traust_core.v1.providers.tools import detection_quality as sweep_provider
from traust_core.v1.providers.tools import opengrep_additions as additions
from traust_core.v1.providers.tools import opengrep_quality as quality
from traust_core.v1.providers.tools.opengrep import SupplementalPack, execute_scan
from traust_core.v1.providers.tools.opengrep_quality import (
    NativeBudget,
    RuleQualityError,
    SourceBudgetError,
    SourceLimits,
    checked_rules,
)

FIXED_CLOCK = FixedClock(datetime(2026, 1, 1, tzinfo=UTC))


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
            clock=FIXED_CLOCK,
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
        pytest.raises(ValidationError, match="link or special file"),
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
            clock=FIXED_CLOCK,
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
        clock=FIXED_CLOCK,
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
            clock=FIXED_CLOCK,
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
            clock=FIXED_CLOCK,
        )
    assert caught.value.reason is ScannerFailure.OUTPUT
    assert "PRIVATE_NATIVE_SENTINEL" not in str(caught.value)


@pytest.mark.parametrize(
    "limit",
    ["files", "bytes", "rules", "fixtures", "entries", "staged_files", "staged_bytes"],
)
def test_shared_native_discovery_refuses_actual_source_breaches_before_native(
    tmp_path: Path, limit: str
) -> None:
    config = write_rule(tmp_path / "source")
    write_rule(config.parent, "second-rule", name="second")
    runner = NativeRunner()
    limits = replace(SourceLimits(), **{limit: 1})

    with (
        pytest.raises(SourceBudgetError, match=f"{limit} budget"),
        checked_rules([config.parent], runner, load=yaml_documents, limits=limits),
    ):
        pytest.fail("source budgets cannot silently omit rule inputs")

    assert not runner.calls


@pytest.mark.parametrize("limit", ["files", "bytes", "entries"])
def test_discovery_budget_is_enforced_before_parsing(tmp_path: Path, limit: str) -> None:
    config = write_rule(tmp_path / "source")
    limits = replace(SourceLimits(), **{limit: 0})

    def no_parsing(text: str) -> list[Any]:
        pytest.fail("an over-budget source must not reach YAML parsing")

    with (
        pytest.raises(SourceBudgetError, match=f"{limit} budget"),
        checked_rules([config.parent], NativeRunner(), load=no_parsing, limits=limits),
    ):
        pass


def test_optional_source_budget_failure_preserves_the_baseline_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = write_rule(tmp_path / "baseline", "baseline-rule").parent
    source = write_rule(tmp_path / "source", "optional-one").parent
    write_rule(source, "optional-two", name="second")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "app.py").write_text("dangerous(value)\n")
    limits = replace(SourceLimits(), files=2)
    monkeypatch.setattr(quality, "SourceLimits", lambda: limits)
    runner = NativeRunner()

    result = execute_scan(
        target,
        (),
        pack=baseline,
        runner=runner,
        checkouts=NoCheckouts(),
        load=yaml_documents,
        additive=[str(source)],
        clock=FIXED_CLOCK,
    )

    assert result["quality_checks"]
    assert all(check["passed"] for check in result["quality_checks"])
    assert result["additive_rules"]["applied"] == []
    assert {receipt["check"] for receipt in result["additive_rules"]["refused"]} == {"source"}
    assert [call[1] for call in runner.calls].count("validate") == 1
    assert runner.scanned


class SelectiveNativeRunner(NativeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.validated: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
        result = super().run(argv, **kwargs)
        if argv[1] == "validate":
            names = tuple(
                rule["id"]
                for path in sorted(Path(argv[-1]).rglob("*.yaml"))
                for rule in yaml_documents(path.read_text())[0]["rules"]
            )
            self.validated.append(names)
            if "rule-7" in names:
                return replace(result, returncode=1)
        return result


def test_native_bisection_keeps_valid_sibling_snapshots_alive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    for index in range(8):
        write_rule(source, f"rule-{index}", name=f"rule-{index}")
    runner = SelectiveNativeRunner()

    with additions.vet_rules(
        "optional",
        [source],
        runner,
        load=yaml_documents,
        binary="opengrep",
        timeout=30,
        protected={},
        languages=None,
        budget=NativeBudget(FixedClock(datetime(2026, 1, 1, tzinfo=UTC))),
    ) as batch:
        assert {receipt.rule_id for receipt in batch.applied} == {
            f"rule-{index}" for index in range(7)
        }
        assert [(receipt.rule_id, receipt.check) for receipt in batch.refused] == [
            ("rule-7", "validate")
        ]
        assert "native validate exited 1" in batch.refused[0].reason
        snapshots = batch.configs
        assert all(path.is_file() and not path.is_relative_to(source) for path in snapshots)
        assert len(snapshots) == 7
        assert [len(group) for group in runner.validated] == [8, 4, 4, 2, 2, 1, 1]
        assert [call[1] for call in runner.calls].count("test") == 3
        shutil.rmtree(source)
        assert all(path.is_file() for path in snapshots)

    assert all(not path.exists() for path in snapshots)


def test_native_bisection_work_budget_keeps_checked_siblings_and_refuses_the_rest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    for index in range(8):
        write_rule(source, f"rule-{index}", name=f"rule-{index}")
    runner = SelectiveNativeRunner()
    budget = NativeBudget(FixedClock(datetime(2026, 1, 1, tzinfo=UTC)), calls=4)

    with additions.vet_rules(
        "optional",
        [source],
        runner,
        load=yaml_documents,
        binary="opengrep",
        timeout=30,
        protected={},
        languages=None,
        budget=budget,
    ) as batch:
        assert {receipt.rule_id for receipt in batch.applied} == {
            f"rule-{index}" for index in range(4)
        }
        assert {receipt.rule_id for receipt in batch.refused} == {
            f"rule-{index}" for index in range(4, 8)
        }
        assert all(receipt.check is additions.AdditionCheck.BUDGET for receipt in batch.refused)
        assert len(runner.calls) == 4
        assert all(path.is_file() for path in batch.configs)


def test_optional_native_deadline_caps_process_timeout_and_stops_bisection(tmp_path: Path) -> None:
    source = write_rule(tmp_path / "source", "rule-7").parent
    write_rule(source, "valid-rule", name="valid")

    class AdvancingClock:
        at = datetime(2026, 1, 1, tzinfo=UTC)

        def now(self) -> datetime:
            return self.at

    clock = AdvancingClock()

    class SlowNative(SelectiveNativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            assert kwargs["timeout_seconds"] == 2
            result = super().run(argv, **kwargs)
            clock.at += timedelta(seconds=2)
            return result

    runner = SlowNative()
    budget = NativeBudget(clock, seconds=2)
    with additions.vet_rules(
        "optional",
        [source],
        runner,
        load=yaml_documents,
        binary="opengrep",
        timeout=30,
        protected={},
        languages=None,
        budget=budget,
    ) as batch:
        assert not batch.applied
        assert len(batch.refused) == 2
        assert all(receipt.check is additions.AdditionCheck.BUDGET for receipt in batch.refused)
        assert len(runner.calls) == 1


def test_rule_fixture_fanout_is_bounded_before_any_native_run(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "source")
    document = yaml_documents(config.read_text())[0]
    document["rules"].append({**document["rules"][0], "id": "second-rule"})
    config.write_text(json.dumps(document))
    fixture = config.with_suffix(".py")
    original = fixture.read_text() + "# " + "x" * 10_000 + "\n"
    fixture.write_text(original)
    runner = NativeRunner()
    limits = replace(SourceLimits(), staged_bytes=12_000)

    with additions.vet_rules(
        "optional",
        [config.parent],
        runner,
        load=yaml_documents,
        binary="opengrep",
        timeout=30,
        protected={},
        languages=None,
        budget=NativeBudget(FixedClock(datetime(2026, 1, 1, tzinfo=UTC))),
        limits=limits,
    ) as batch:
        assert not batch.applied
        assert not batch.configs
        assert len(batch.refused) == 1
        assert batch.refused[0].check is additions.AdditionCheck.SOURCE
        assert "staged_bytes budget" in batch.refused[0].reason
        assert not runner.calls
        assert fixture.read_text() == original


def test_input_growth_is_reaccounted_before_the_file_is_read(tmp_path: Path) -> None:
    source = tmp_path / "fixture.py"
    source.write_bytes(b"first\n")
    budget = quality.SourceBudget(replace(SourceLimits(), bytes=32))
    budget.file(source, source.stat().st_size)
    source.write_bytes(b"x" * 64)

    with pytest.raises(SourceBudgetError, match="bytes budget"):
        quality.read_rule_text(source, tmp_path, budget=budget)


def test_capture_directory_depth_has_a_typed_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_rule(source / "nested" / "deeper")
    destination = tmp_path / "accepted"

    with (
        pytest.raises(SourceBudgetError, match="depth budget"),
        additions.capture_rules([source], destination, limits=replace(SourceLimits(), depth=1)),
    ):
        pytest.fail("deep directory inputs cannot overflow recursive capture")

    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


@pytest.mark.parametrize(("ordinary_count", "fixture_count"), [(129, 2), (1, 130)])
def test_large_mixed_packs_plan_single_target_native_work(
    tmp_path: Path, ordinary_count: int, fixture_count: int
) -> None:
    source = tmp_path / "source"
    for index in range(ordinary_count):
        write_rule(source, f"ordinary-{index}", name=f"ordinary-{index}")
    directory = write_rule(source, "directory-rule", name="directory")
    original = directory.with_suffix(".py").read_text()
    directory.with_suffix(".py").unlink()
    cases = directory.with_suffix("") / "nested"
    cases.mkdir(parents=True)
    for index in range(fixture_count):
        (cases / f"case-{index}.py").write_text(original)

    class DirectoryRunner(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if "--config" not in argv:
                if argv[1] == "test":
                    assert len(argv) == 5
                return super().run(argv, **kwargs)
            assert len(argv) == 7
            self.calls.append(tuple(argv))
            config, fixture = Path(argv[-2]), Path(argv[-1])
            rule_id = yaml_documents(config.read_text())[0]["rules"][0]["id"]
            fire, _ = quality.example_lines(rule_id, fixture.read_text())
            check = {
                "passed": True,
                "errors": [],
                "matches": {
                    str(fixture): {
                        "expected_lines": sorted(fire),
                        "reported_lines": sorted(fire),
                    }
                },
            }
            data = {
                "results": {str(config): {"checks": {rule_id: check}}},
                "config_missing_tests": [],
                "config_missing_fixtests": [],
                "config_with_errors": [],
                "fixtest_results": {},
            }
            return ProcessResult(tuple(argv), 0, json.dumps(data).encode(), b"", 0.01)

    budget = NativeBudget(FixedClock(datetime(2026, 1, 1, tzinfo=UTC)))
    for _ in range(2):
        runner = DirectoryRunner()
        with additions.vet_rules(
            "optional",
            [source],
            runner,
            load=yaml_documents,
            binary="opengrep",
            timeout=30,
            protected={},
            languages=None,
            budget=budget,
        ) as batch:
            assert not batch.refused
            assert len(batch.applied) == ordinary_count + 1
            assert len(batch.configs) == ordinary_count + 1
            assert all(config.is_file() for config in batch.configs)
            assert len(runner.calls) == 2 + fixture_count
            assert sum(call[1] == "test" and "--config" not in call for call in runner.calls) == 1
            assert sum("--config" in call for call in runner.calls) == fixture_count
