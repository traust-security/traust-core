from __future__ import annotations

import errno
import json
import os
import shutil
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.v1.conftest import CheckoutForge, NoCheckouts
from tests.v1.providers.tools.opengrep_fixtures import write_rule
from tests.v1.providers.tools.test_opengrep_quality import NativeRunner
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.providers.tools import opengrep_additions as additions
from traust_core.v1.providers.tools import opengrep_quality as quality
from traust_core.v1.providers.tools.opengrep import (
    ARGUS_RULES_REPO,
    SupplementalPack,
    execute_scan,
    intake_rules,
)
from traust_core.v1.providers.tools.opengrep_quality import SourceLimits, checked_rules

FIXED_CLOCK = FixedClock(datetime(2026, 1, 1, tzinfo=UTC))


def admit(
    sources: Sequence[Path], destination: Path, runner: Any, *, pack: Path | None = None
) -> dict[str, Any]:
    baseline = pack or destination.parent / "baseline"
    baseline.mkdir(exist_ok=True)
    return intake_rules(
        [str(source) for source in sources],
        destination,
        pack=baseline,
        supplements=(),
        runner=runner,
        checkouts=NoCheckouts(),
        load=yaml_documents,
        timeout=30,
        binary="opengrep",
        clock=FIXED_CLOCK,
    )


def contents(root: Path) -> dict[Path, bytes]:
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_admission_preserves_checked_bytes_layout_credits_and_assets_without_vcs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    config = write_rule(source / "python" / "security", name="policy.skeleton")
    config.write_bytes(config.read_bytes().replace(b"\n", b"\r\n"))
    fixture = config.with_suffix(".py")
    fixture.write_bytes(fixture.read_bytes().replace(b"\n", b"\r\n"))
    (source / "LICENSE").write_bytes(b"Original license\r\n")
    (source / "NOTICE").write_bytes(b"Original author\n")
    (source / "assets").mkdir()
    (source / "assets" / "reference.bin").write_bytes(b"\x00\xff")
    (source / "tests").mkdir()
    (source / "tests" / "reference.py").write_bytes(b"safe(value)\n")
    original = contents(source)
    (source / ".git").mkdir()
    (source / ".git" / "config").symlink_to(tmp_path / "private")
    destination = tmp_path / "accepted"

    class InspectingRunner(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            assert not destination.exists()
            root = Path(argv[-1])
            assert next(root.rglob("*.yaml")).read_bytes() == config.read_bytes()
            assert next(root.rglob("*.py")).read_bytes() == fixture.read_bytes()
            return super().run(argv, **kwargs)

    runner = InspectingRunner()
    report = admit([source], destination, runner)

    assert report["admitted"] is True
    assert report["destination"] == str(destination)
    assert [receipt["rule_id"] for receipt in report["applied"]] == ["example-rule"]
    assert report["refused"] == []
    assert report["degraded"] == {}
    assert len(report["content_digest"]) == 64
    assert all(check["passed"] for check in report["quality_checks"])
    assert [call[1] for call in runner.calls] == ["validate", "test"]
    assert "--json" in runner.calls[1] and "--strict" in runner.calls[1]
    assert contents(destination) == original
    assert not (destination / ".git").exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


def test_file_admission_keeps_paired_fixtures_and_credits_not_neighbor_rules(
    tmp_path: Path,
) -> None:
    config = write_rule(tmp_path / "source", "selected-rule", name="selected")
    write_rule(config.parent, "neighbor-rule", name="neighbor")
    (config.parent / "LICENSE.txt").write_bytes(b"License\n")
    for name in ("LICENSE", "NOTICE.private", "AUTHORS"):
        unrelated = config.parent / name
        unrelated.mkdir()
        (unrelated / "private.txt").write_text("Unrelated private content\n")
    private = tmp_path / "private.txt"
    private.write_text("Private symlink target\n")
    (config.parent / "COPYING").symlink_to(private)
    (config.parent / "COPYRIGHT").symlink_to(config.parent / "LICENSE", target_is_directory=True)
    destination = tmp_path / "accepted"

    report = admit([config], destination, NativeRunner())

    assert report["admitted"] is True
    assert set(contents(destination)) == {
        Path("selected.yaml"),
        Path("selected.py"),
        Path("LICENSE.txt"),
    }
    assert (destination / "selected.yaml").read_bytes() == config.read_bytes()


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
def test_native_refusal_never_publishes_or_claims_installation(
    tmp_path: Path, failure: str
) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"
    runner = NativeRunner(failure)

    report = admit([config.parent], destination, runner)

    assert report["admitted"] is False
    assert report["applied"] == []
    assert report["refused"]
    assert "destination" not in report
    assert not all(check["passed"] for check in report["quality_checks"])
    assert not destination.exists()
    assert config.is_file()
    assert not list(tmp_path.glob(".opengrep-intake-*"))
    assert [call[1] for call in runner.calls] == (
        ["validate"] if failure.startswith("validate") else ["validate", "test"]
    )


@pytest.mark.parametrize(
    "fixture",
    ["# ruleid: example-rule\ndangerous(value)\n", "# ok: example-rule\nsafe(value)\n"],
)
def test_admission_needs_both_behavior_directions(tmp_path: Path, fixture: str) -> None:
    config = write_rule(tmp_path / "source")
    config.with_suffix(".py").write_text(fixture)
    destination = tmp_path / "accepted"

    report = admit([config.parent], destination, NativeRunner())

    assert not report["admitted"]
    assert report["quality_checks"][0]["passed"]
    assert not destination.exists()


@pytest.mark.parametrize(
    "missing", ["positive-line", "fixture", "unknown-fixture", "duplicate-rule"]
)
def test_native_success_cannot_hide_incomplete_or_fabricated_receipts(
    tmp_path: Path, missing: str
) -> None:
    config = write_rule(tmp_path / "source")
    config.with_suffix(".py").write_text(
        "# ruleid: example-rule\ndangerous(one)\n"
        "# ruleid: example-rule\ndangerous(two)\n# ok: example-rule\nsafe(value)\n"
    )
    if missing == "fixture":
        config.with_name("rules.extra.py").write_text("# ok: example-rule\nsafe(other)\n")

    class Incomplete(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            result = super().run(argv, **kwargs)
            if argv[1] != "test":
                return result
            data = json.loads(result.stdout)
            entry = next(iter(data["results"].values()))
            check = entry["checks"]["example-rule"]
            if missing == "positive-line":
                match = next(iter(check["matches"].values()))
                match["expected_lines"] = match["reported_lines"] = [2]
            elif missing == "fixture":
                name = next(name for name in check["matches"] if not name.endswith("extra.py"))
                del check["matches"][name]
            elif missing == "unknown-fixture":
                check["matches"][str(tmp_path / "fabricated.py")] = {
                    "expected_lines": [],
                    "reported_lines": [],
                }
            else:
                data["results"]["fabricated.yaml"] = entry
            return ProcessResult(tuple(argv), 0, json.dumps(data).encode(), b"", 0.01)

    destination = tmp_path / "accepted"
    report = admit([config.parent], destination, Incomplete())
    assert not report["admitted"]
    assert not destination.exists()


def test_source_changes_after_capture_cannot_change_published_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_rule(source / "nested")
    (source / "LICENSE").write_bytes(b"Original license\n")
    destination = tmp_path / "accepted"
    original = contents(source)

    class ChangingSource(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if argv[1] == "validate":
                shutil.rmtree(source)
                source.mkdir()
                (source / "replacement.yaml").write_text("rules: invalid\n")
                (source / "LICENSE").write_bytes(b"Changed license\n")
            return super().run(argv, **kwargs)

    assert admit([source], destination, ChangingSource())["admitted"]
    assert contents(destination) == original


@pytest.mark.parametrize("kind", ["directory", "file", "broken-link"])
def test_existing_destination_is_untouched(tmp_path: Path, kind: str) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"
    if kind == "directory":
        destination.mkdir()
        (destination / "keep").write_bytes(b"Existing pack\n")
    elif kind == "file":
        destination.write_bytes(b"Existing file\n")
    else:
        destination.symlink_to(tmp_path / "absent")
    runner = NativeRunner()

    with pytest.raises(ValidationError, match="destination already exists"):
        admit([config.parent], destination, runner)

    assert not runner.calls
    if kind == "directory":
        assert (destination / "keep").read_bytes() == b"Existing pack\n"
    elif kind == "file":
        assert destination.read_bytes() == b"Existing file\n"
    else:
        assert destination.is_symlink()
        assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("empty", [False, True])
def test_destination_creation_race_does_not_touch_the_winner(tmp_path: Path, empty: bool) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"

    class RacingDestination(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            if argv[1] == "test":
                destination.mkdir()
                if not empty:
                    (destination / "keep").write_bytes(b"Race winner\n")
            return super().run(argv, **kwargs)

    with pytest.raises(ValidationError, match="cannot admit rule pack") as refusal:
        admit([config.parent], destination, RacingDestination())

    assert isinstance(refusal.value.__cause__, FileExistsError)
    assert list(destination.iterdir()) == ([] if empty else [destination / "keep"])
    if not empty:
        assert (destination / "keep").read_bytes() == b"Race winner\n"
    assert not list(tmp_path.glob(".opengrep-intake-*"))


@pytest.mark.parametrize("destination_kind", ["same", "child", "ancestor"])
def test_source_destination_overlap_is_rejected(tmp_path: Path, destination_kind: str) -> None:
    source = tmp_path / "source"
    write_rule(source)
    destination = {"same": source, "child": source / "accepted", "ancestor": tmp_path}[
        destination_kind
    ]
    runner = NativeRunner()

    with pytest.raises(ValidationError):
        admit([source], destination, runner)

    assert not runner.calls
    assert (source / "rules.yaml").is_file()
    assert not (source / "accepted").exists()


@pytest.mark.parametrize(
    "kind", ["file-link", "directory-link", "broken-link", "fifo", "root-link", "root-file-link"]
)
def test_links_and_special_inputs_are_rejected_without_following_them(
    tmp_path: Path, kind: str
) -> None:
    source = tmp_path / "source"
    write_rule(source)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private").write_bytes(b"Do not copy\n")
    unsafe = source / "unsafe"
    if kind == "file-link":
        unsafe.symlink_to(outside / "private")
    elif kind == "directory-link":
        unsafe.symlink_to(outside, target_is_directory=True)
    elif kind == "broken-link":
        unsafe.symlink_to(outside / "missing")
    elif kind == "fifo":
        os.mkfifo(unsafe)
    elif kind == "root-link":
        alias = tmp_path / "alias"
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(source / "rules.yaml")
        source = alias
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    with pytest.raises(ValidationError, match="link or special file"):
        admit([source], destination, runner)

    assert not runner.calls
    assert not destination.exists()
    assert (outside / "private").read_bytes() == b"Do not copy\n"
    assert not list(tmp_path.glob(".opengrep-intake-*"))


@pytest.mark.parametrize("kind", ["missing", "missing-parent", "root-fifo"])
def test_invalid_paths_raise_typed_errors(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "accepted"
    if kind == "missing-parent":
        write_rule(source)
        destination = tmp_path / "missing" / "accepted"
    elif kind == "root-fifo":
        os.mkfifo(source)

    with pytest.raises(ValidationError):
        admit([source], destination, NativeRunner(), pack=tmp_path / "baseline")
    assert not destination.exists()


def test_failed_publication_removes_only_its_own_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"

    def fail(*args: object) -> int:
        destination.mkdir()
        (destination / "unrelated").write_bytes(b"Another writer\n")
        additions.ctypes.set_errno(errno.EIO)
        return -1

    library = SimpleNamespace(renameat2=fail, renameatx_np=fail)
    monkeypatch.setattr(additions.ctypes, "CDLL", lambda *args, **kwargs: library)

    with pytest.raises(ValidationError, match="cannot admit rule pack"):
        admit([config.parent], destination, NativeRunner())

    assert list(destination.iterdir()) == [destination / "unrelated"]
    assert (destination / "unrelated").read_bytes() == b"Another writer\n"
    assert config.is_file()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


def test_multiple_sources_use_separate_namespaces_and_one_native_gate(tmp_path: Path) -> None:
    first = write_rule(tmp_path / "first", "first-rule")
    second = write_rule(tmp_path / "second", "second-rule")
    (first.parent / "LICENSE").write_text("First author\n")
    (second.parent / "LICENSE").write_text("Second author\n")
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    report = admit([first.parent, second], destination, runner)

    assert report["admitted"]
    assert [call[1] for call in runner.calls] == ["validate", "test"]
    assert (destination / "source-0" / "rules.yaml").read_bytes() == first.read_bytes()
    assert (destination / "source-1" / "rules.yaml").read_bytes() == second.read_bytes()
    assert (destination / "source-0" / "LICENSE").read_text() == "First author\n"
    assert (destination / "source-1" / "LICENSE").read_text() == "Second author\n"


def test_cross_source_collision_refuses_every_source_without_native_runs(tmp_path: Path) -> None:
    first = write_rule(tmp_path / "first")
    second = write_rule(tmp_path / "second")
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    report = admit([first.parent, second.parent], destination, runner)

    assert not report["admitted"]
    assert report["applied"] == []
    assert {receipt["check"] for receipt in report["refused"]} == {"collision", "admission"}
    assert report["quality_checks"] == []
    assert not runner.calls
    assert not destination.exists()


def test_overlapping_sources_are_rejected(tmp_path: Path) -> None:
    config = write_rule(tmp_path / "source")
    with pytest.raises(ValidationError, match="sources must not overlap"):
        admit([config.parent, config], tmp_path / "accepted", NativeRunner())


@pytest.mark.parametrize("nested", [False, True])
def test_pinned_https_intake_preserves_fixtures_and_attribution(
    tmp_path: Path, nested: bool
) -> None:
    config = write_rule(tmp_path / "authored")
    forge = CheckoutForge(tmp_path, ARGUS_RULES_REPO if nested else "https://example.com/o/rules")
    prefix = "rules/languages/python/" if nested else ""
    sha = forge.commit(
        {
            prefix + "rules.yaml": config.read_bytes(),
            prefix + "rules.py": config.with_suffix(".py").read_bytes(),
            "LICENSE": "Original author\n",
        }
    )
    pack = tmp_path / "baseline"
    pack.mkdir()
    destination = tmp_path / "accepted"
    report = intake_rules(
        [f"{forge.url}@{sha}"],
        destination,
        pack=pack,
        supplements=(),
        runner=NativeRunner(),
        checkouts=forge.service(),
        load=yaml_documents,
        timeout=30,
        binary="opengrep",
        clock=FIXED_CLOCK,
    )
    assert report["admitted"]
    assert report["applied"][0]["source"] == f"{forge.url}@{sha}"
    captured = "python/" if nested else ""
    assert (destination / captured / "rules.yaml").read_bytes() == config.read_bytes()
    assert (destination / "LICENSE").read_text() == "Original author\n"
    assert not (destination / ".git").exists()


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
@pytest.mark.parametrize("valid", [True, False])
def test_real_native_admission_publishes_only_complete_behavioral_packs(
    tmp_path: Path, valid: bool
) -> None:
    config = write_rule(tmp_path / "source", name="policy.skeleton")
    if not valid:
        config.with_suffix(".py").write_text(
            "# ruleid: example-rule\nabsent(value)\n# ok: example-rule\nsafe(value)\n"
        )
    destination = tmp_path / "accepted"
    runner = ProcessRunner(("opengrep",))

    report = admit([config.parent], destination, runner)

    assert report["admitted"] is valid, report
    assert destination.exists() is valid
    assert all(check["passed"] for check in report["quality_checks"]) is valid
    if valid:
        with checked_rules([destination], runner, load=yaml_documents) as checked:
            assert checked.report.passed


@pytest.mark.skipif(not shutil.which("opengrep"), reason="real Opengrep integration")
@pytest.mark.parametrize("file_source", [False, True])
@pytest.mark.parametrize("valid", [False, True])
def test_real_native_directory_fixtures_survive_admission_and_additive_scanning(
    tmp_path: Path, file_source: bool, valid: bool
) -> None:
    config = write_rule(tmp_path / "source", "directory-rule", name="policy")
    write_rule(config.parent, "sibling-rule", name="sibling")
    write_rule(config.parent, "second-sibling-rule", name="second-sibling")
    cases = config.with_suffix("") / "nested" / "cases.py"
    cases.parent.mkdir(parents=True)
    config.with_suffix(".py").rename(cases)
    original = cases.read_bytes()
    second = cases.with_name("second.py")
    second.write_bytes(original.replace(b"value", b"second_value"))
    if not valid:
        second.write_text(
            "# ruleid: directory-rule\ndangerous(second_value)\n"
            "# ok: directory-rule\ndangerous(other_value)\n"
        )
    baseline = write_rule(tmp_path / "baseline", "baseline-rule").parent
    destination = tmp_path / "accepted"

    class RecordingRunner(ProcessRunner):
        def __init__(self) -> None:
            super().__init__(("opengrep",))
            self.calls: list[tuple[str, ...]] = []

        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            self.calls.append(tuple(argv))
            return super().run(argv, **kwargs)

    runner = RecordingRunner()

    report = admit([config if file_source else config.parent], destination, runner, pack=baseline)

    assert report["admitted"] is valid, report
    assert destination.exists() is valid
    native_tests = [call for call in runner.calls if call[1] == "test"]
    assert sum("--config" in call for call in native_tests) == 2
    assert sum("--config" not in call for call in native_tests) == (0 if file_source else 1)
    assert all(len(call) == (7 if "--config" in call else 5) for call in native_tests)
    if not valid:
        assert any(
            check["name"] == "test" and not check["passed"] for check in report["quality_checks"]
        )
        return
    assert {check["name"] for check in report["quality_checks"] if check["passed"]} == {
        "validate",
        "test",
    }
    assert (destination / "policy" / "nested" / "cases.py").read_bytes() == original
    assert (destination / "policy" / "nested" / "second.py").read_bytes() == second.read_bytes()
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "code.py").write_bytes(original)
    scan = execute_scan(
        target,
        (),
        pack=baseline,
        runner=runner,
        checkouts=NoCheckouts(),
        load=yaml_documents,
        additive=[str(destination)],
        clock=FIXED_CLOCK,
    )
    expected = {"baseline-rule", "directory-rule"}
    if not file_source:
        expected.update({"sibling-rule", "second-sibling-rule"})
    assert {fact["rule_id"] for fact in scan["facts"]} == expected
    assert scan["additive_rules"]["refused"] == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"pattern": "$X"}, "catch-all"),
        ({"paths": {"include": ["**/*"]}}, "paths"),
        ({"pattern-regex": "(?<=unsafe)dangerous"}, "regex"),
        ({"languages": []}, "structure"),
    ],
)
def test_admission_reuses_shared_static_policy_before_any_native_execution(
    tmp_path: Path, change: dict[str, Any], expected: str
) -> None:
    config = write_rule(tmp_path / "source")
    document = yaml_documents(config.read_text())[0]
    if "pattern-regex" in change:
        document["rules"][0].pop("pattern")
    document["rules"][0].update(change)
    config.write_text(json.dumps(document))
    runner = NativeRunner()
    destination = tmp_path / "accepted"

    report = admit([config.parent], destination, runner)

    assert not report["admitted"]
    assert report["applied"] == []
    assert [receipt["check"] for receipt in report["refused"]] == [expected]
    assert report["quality_checks"] == []
    assert not runner.calls
    assert not destination.exists()


def test_publication_failure_without_other_writers_leaves_no_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"

    def fail(*args: object) -> int:
        assert not destination.exists()
        additions.ctypes.set_errno(errno.EIO)
        return -1

    library = SimpleNamespace(renameat2=fail, renameatx_np=fail)
    monkeypatch.setattr(additions.ctypes, "CDLL", lambda *args, **kwargs: library)
    with pytest.raises(ValidationError, match="cannot admit rule pack"):
        admit([config.parent], destination, NativeRunner())
    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


@pytest.mark.parametrize("file_source", [False, True])
def test_admission_canonicalizes_parent_links_without_following_a_source_leaf(
    tmp_path: Path, file_source: bool
) -> None:
    config = write_rule(tmp_path / "actual" / "nested")
    alias = tmp_path / "alias"
    alias.symlink_to(
        config.parent if file_source else config.parent.parent, target_is_directory=True
    )
    source = alias / config.name if file_source else alias / "nested"
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    report = admit([source], destination, runner)

    assert report["admitted"]
    assert (destination / config.name).read_bytes() == config.read_bytes()
    assert [call[1] for call in runner.calls] == ["validate", "test"]
    assert config.is_file()


@pytest.mark.parametrize("support", ["platform", "native-symbol"])
def test_missing_atomic_publication_support_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, support: str
) -> None:
    config = write_rule(tmp_path / "source")
    destination = tmp_path / "accepted"
    if support == "platform":
        monkeypatch.setattr(additions, "sys", SimpleNamespace(platform="unsupported"))
    else:
        monkeypatch.setattr(additions.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace())

    with pytest.raises(ValidationError, match="atomic no-overwrite rule admission is unavailable"):
        admit([config.parent], destination, NativeRunner())
    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


@pytest.mark.parametrize("file_source", [False, True])
def test_capture_budgets_all_copied_bytes_including_credit_files(
    tmp_path: Path, file_source: bool
) -> None:
    config = write_rule(tmp_path / "source")
    (config.parent / "LICENSE").write_bytes(b"x" * 4096)
    destination = tmp_path / "accepted"
    limits = replace(SourceLimits(), bytes=2048)

    with (
        pytest.raises(quality.SourceBudgetError, match="bytes budget"),
        additions.capture_rules(
            [config if file_source else config.parent], destination, limits=limits
        ),
    ):
        pytest.fail("oversized credit files cannot be omitted or copied without a bound")

    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))
    assert (config.parent / "LICENSE").stat().st_size == 4096


@pytest.mark.parametrize("file_source", [False, True])
def test_admission_source_budget_refusal_is_a_result_without_native_or_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file_source: bool
) -> None:
    config = write_rule(tmp_path / "source")
    (config.parent / "LICENSE").write_bytes(b"x" * 4096)
    limits = replace(SourceLimits(), bytes=2048)
    monkeypatch.setattr(quality, "SourceLimits", lambda: limits)
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    report = admit([config if file_source else config.parent], destination, runner)

    assert not report["admitted"]
    assert not report["applied"]
    assert {receipt["check"] for receipt in report["refused"]} == {"source"}
    assert not runner.calls
    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


def test_empty_supplement_owner_still_reserves_its_ids_before_admission(tmp_path: Path) -> None:
    baseline = write_rule(tmp_path / "baseline", "baseline-rule").parent
    supplement = write_rule(tmp_path / "supplement", "reserved-rule").parent
    source = write_rule(tmp_path / "source", "reserved-rule").parent
    destination = tmp_path / "accepted"
    runner = NativeRunner()

    report = intake_rules(
        [str(source)],
        destination,
        pack=baseline,
        supplements=(SupplementalPack("", str(supplement), ("reserved-rule",)),),
        runner=runner,
        checkouts=NoCheckouts(),
        load=yaml_documents,
        timeout=30,
        binary="opengrep",
        clock=FIXED_CLOCK,
    )

    assert not report["admitted"]
    assert report["applied"] == []
    assert [receipt["check"] for receipt in report["refused"]] == ["collision"]
    assert report["refused"][0]["rule_id"] == "reserved-rule"
    assert not runner.calls
    assert not destination.exists()


@pytest.mark.parametrize("conflict", [False, True])
def test_selected_remote_subtree_keeps_root_credits_without_copying_unrelated_links(
    tmp_path: Path, conflict: bool
) -> None:
    repository = tmp_path / "repository"
    config = write_rule(repository / "rules" / "languages" / "python")
    (repository / "LICENSE").write_bytes(b"Repository license\n")
    (repository / "unrelated").symlink_to(tmp_path / "private")
    (repository / "unrelated.yaml").write_text("Not an Opengrep rule\n")
    (repository / "LICENSES").mkdir()
    (repository / "LICENSES" / "outside").symlink_to(tmp_path / "private")
    root = repository / "rules" / "languages"
    if conflict:
        (root / "LICENSE").write_bytes(b"Subtree license\n")
    destination = tmp_path / "accepted"

    with additions.capture_rules([root], destination, attribution_roots=[repository]) as (
        snapshot,
        inputs,
        _,
    ):
        assert inputs == (snapshot,)
        assert (snapshot / "python" / config.name).read_bytes() == config.read_bytes()
        assert not (snapshot / "unrelated").exists()
        assert not (snapshot / "unrelated.yaml").exists()
        assert not (snapshot / "LICENSES").exists()
        attribution = snapshot / ".repository-attribution" if conflict else snapshot
        assert (attribution / "LICENSE").read_bytes() == b"Repository license\n"
        if conflict:
            assert (snapshot / "LICENSE").read_bytes() == b"Subtree license\n"

    assert not destination.exists()


def test_root_attribution_bytes_share_the_source_capture_budget(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    config = write_rule(repository / "rules")
    (repository / "LICENSE").write_bytes(b"x" * 4096)
    destination = tmp_path / "accepted"

    with (
        pytest.raises(quality.SourceBudgetError, match="bytes budget"),
        additions.capture_rules(
            [config.parent],
            destination,
            attribution_roots=[repository],
            limits=replace(SourceLimits(), bytes=2048),
        ),
    ):
        pytest.fail("repository-root attribution cannot bypass the byte budget")

    assert not destination.exists()
    assert not list(tmp_path.glob(".opengrep-intake-*"))


def test_intake_uses_callers_deadline_before_publishing(tmp_path: Path) -> None:
    class AdvancingClock:
        instant = datetime(2026, 1, 1, tzinfo=UTC)

        def now(self) -> datetime:
            return self.instant

    clock = AdvancingClock()

    class SlowValidation(NativeRunner):
        def run(self, argv: Sequence[str], **kwargs: Any) -> ProcessResult:
            result = super().run(argv, **kwargs)
            if argv[1] == "validate":
                clock.instant += timedelta(seconds=3)
            return result

    config = write_rule(tmp_path / "source")
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    destination = tmp_path / "accepted"
    report = intake_rules(
        [str(config.parent)],
        destination,
        pack=baseline,
        supplements=(),
        runner=SlowValidation(),
        clock=clock,
        checkouts=NoCheckouts(),
        load=yaml_documents,
        timeout=2,
        binary="opengrep",
    )

    assert report["admitted"] is False
    assert any(item["check"] == "budget" for item in report["refused"])
    assert not destination.exists()
