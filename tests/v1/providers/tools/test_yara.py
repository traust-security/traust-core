"""YARA: ported from traust-engine tests/test_run_yara.py. The yara binary is never run: a
scripted ProcessRunner answers for it; a pinned rule pack is a workspace from the checkout
service over a local bare repository standing in for the forge."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CheckoutForge, NoCheckouts
from traust_core.v1.errors import NotFoundError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import (
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
)
from traust_core.v1.providers.tools import yara as yara_module
from traust_core.v1.providers.tools.yara import (
    RL_RULES_LICENSE,
    RL_RULES_REPO,
    RL_RULES_SHA,
    Yara,
    build_rule_index,
    count_regular_files,
    discover_rule_files,
    facts_to_findings,
    generate_include_index,
    parse_matches,
)

WHEN = datetime(2026, 10, 24, 12, tzinfo=UTC)
PIN = "a" * 40
TARGET = Path("/tmp/rootfs").resolve()
NEVER = NoCheckouts()


def pack(root: Path) -> Path:
    (root / "backdoor").mkdir(parents=True)
    (root / "ransomware").mkdir(parents=True)
    (root / "backdoor" / "Linux.Backdoor.BPFDoor.yara").write_text(
        'rule Linux_Backdoor_BPFDoor : tag1 tag2 {\n  strings: $a = "x"\n  condition: $a\n}\n',
        encoding="utf-8",
    )
    (root / "ransomware" / "Win.Ransom.Foo.yara").write_text(
        "private rule Win_Ransom_Foo\n{\n  condition: true\n}\n", encoding="utf-8"
    )
    (root / "README.md").write_text("rule NotARule {}\n")
    return root


def test_index_maps_id_to_category_and_family(tmp_path: Path) -> None:
    files = discover_rule_files(pack(tmp_path))
    assert len(files) == 2
    idx = build_rule_index([*files, tmp_path / "gone.yara"])
    assert idx["Linux_Backdoor_BPFDoor"] == {
        "source_file": str(files[0]),
        "category": "backdoor",
        "family": "BPFDoor",
    }
    assert idx["Win_Ransom_Foo"]["category"] == "ransomware"  # `private rule` is indexed too


def test_a_single_rule_file_is_its_own_pack(tmp_path: Path) -> None:
    rule = tmp_path / "one.yar"
    rule.write_text("rule Single { condition: true }\n")
    assert discover_rule_files(rule) == [rule]
    assert discover_rule_files(tmp_path / "notes.txt") == []
    assert build_rule_index([rule])["Single"]["family"] == "Single"


def test_include_index_lists_every_rule_file(tmp_path: Path) -> None:
    files = discover_rule_files(pack(tmp_path / "pack"))
    body = generate_include_index(files, tmp_path).read_text(encoding="utf-8")
    assert body.count("include ") == 2
    assert all(f.as_posix() in body for f in files)


def test_parse_matches_splits_rule_and_path_and_enriches() -> None:
    idx = {
        "Linux_Backdoor_BPFDoor": {
            "source_file": "/rules/backdoor/x.yara",
            "category": "backdoor",
            "family": "BPFDoor",
        }
    }
    (f,) = parse_matches(f"Linux_Backdoor_BPFDoor {TARGET}/usr/bin/implant\n", TARGET, idx)
    assert f == {
        "rule_id": "Linux_Backdoor_BPFDoor",
        "family": "BPFDoor",
        "category": "backdoor",
        "source_rule_file": "/rules/backdoor/x.yara",
        "file": "usr/bin/implant",
        "severity_hint": "high",
        "match_type": "yara_signature",
        "carrier_path": False,
    }


def test_carrier_path_flagged() -> None:
    out = f"Some_Rule {TARGET}/opt/clamav/testdata/eicar.bin\nOther_Rule {TARGET}/app/server\n"
    by_file = {f["file"]: f["carrier_path"] for f in parse_matches(out, TARGET, {})}
    assert by_file == {"opt/clamav/testdata/eicar.bin": True, "app/server": False}


def test_unknown_rule_id_has_null_family_and_an_outside_path_stays_as_given() -> None:
    (f,) = parse_matches("Mystery /elsewhere/x", TARGET, {})
    assert (f["family"], f["category"], f["file"]) == (None, None, "/elsewhere/x")


@pytest.mark.parametrize("out", ["\n   \nNoSpaceLine\n", " leading-space\n", "Rule \n"])
def test_blank_and_malformed_lines_skipped(out: str) -> None:
    assert parse_matches(out, TARGET, {}) == []


def test_facts_become_findings_naming_the_family() -> None:
    facts = parse_matches(
        f"Known {TARGET}/a\nMystery {TARGET}/b\n",
        TARGET,
        {"Known": {"family": "F", "category": "c"}},
    )
    known, mystery = facts_to_findings(facts)
    assert (known["id"], known["title"], known["category"]) == (
        "yara/Known",
        "YARA match: Known (F)",
        "c",
    )
    assert known["description"] == "category=c family=F carrier_path=False"
    assert (mystery["title"], mystery["category"]) == ("YARA match: Mystery", "")
    assert known["locations"] == [{"path": "a"}] and known["severity"] == "high"


def test_regular_files_are_counted_without_following_symlinks(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f").write_text("x")
    (tmp_path / "g").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "g")
    (tmp_path / "dlink").symlink_to(tmp_path / "d")
    assert count_regular_files(tmp_path) == 2


class YaraBin(ProcessRunner):
    """The yara binary, scripted: its version and its scan's output."""

    def __init__(
        self, scan: Callable[[list[str]], ProcessResult | BaseException] | None = None
    ) -> None:
        super().__init__(["yara"])
        self.scan = scan
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        args = list(argv)
        self.calls.append((args, kw))
        if args[1:] == ["--version"]:
            return ProcessResult(tuple(args), 0, b"4.5.8\n", b"", 0.0)
        answer = self.scan(args)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def argvs(self) -> list[list[str]]:
        return [a for a, _ in self.calls]


def yara(runner: ProcessRunner, checkouts: Any) -> Yara:
    return Yara(runner, FixedClock(WHEN), checkouts=checkouts, harness_version="9.9.9")


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (f"{RL_RULES_REPO}@develop", "ref must be a 40-hex commit SHA"),
        (f"{RL_RULES_REPO}@abc123", "ref must be a 40-hex commit SHA"),
        (RL_RULES_REPO, "ref must be a 40-hex commit SHA"),
        (f"http://example.com/rules@{PIN}", "https:// URLs only"),
        (f"git@github.com:org/rules@{PIN}", "https:// URLs only"),
        ("/no/such/rules/path/xyz", "rules source not found"),
    ],
)
def test_an_unpinned_insecure_or_missing_rules_source_is_refused(
    tmp_path: Path, source: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        yara(YaraBin(), NEVER).resolve_rules([source])


def test_local_path_used_as_is(tmp_path: Path) -> None:
    (tmp_path / "r.yara").write_text("rule R { condition: true }", encoding="utf-8")
    (resolved,), held = yara(YaraBin(), NEVER).resolve_rules([str(tmp_path)])
    assert resolved == {
        "source": str(tmp_path),
        "root": str(tmp_path.resolve()),
        "sha": None,
        "license_note": "local rules — license per author",
    }
    assert held == []


def test_default_pin_is_immutable_40hex() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", RL_RULES_SHA)
    assert RL_RULES_REPO.startswith("https://")


def test_no_source_asks_for_the_pinned_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = CheckoutForge(tmp_path, RL_RULES_REPO)
    sha = forge.commit({"backdoor/Linux.Backdoor.BPFDoor.yara": "rule X { condition: true }\n"})
    monkeypatch.setattr(yara_module, "RL_RULES_SHA", str(sha))
    (resolved,), held = yara(YaraBin(), forge.service()).resolve_rules([])
    assert resolved == {
        "source": f"{RL_RULES_REPO}@{sha}",
        "root": str(held[0].path),
        "sha": str(sha),
        "license_note": RL_RULES_LICENSE,
    }
    assert (held[0].path / "backdoor" / "Linux.Backdoor.BPFDoor.yara").is_file()
    forge.service().release(held[0])
    assert not held[0].path.exists()


def test_a_pinned_https_source_is_a_workspace_from_the_checkout_service(tmp_path: Path) -> None:
    forge = CheckoutForge(tmp_path, "https://example.com/org/rules")
    sha = forge.commit({"backdoor/x.yara": "rule X { condition: true }\n"})
    (resolved,), held = yara(YaraBin(), forge.service()).resolve_rules(
        [f"https://example.com/org/rules@{sha}"]
    )
    assert resolved == {
        "source": f"https://example.com/org/rules@{sha}",
        "root": str(held[0].path),
        "sha": str(sha),
        "license_note": "verify upstream license before redistribution",
    }
    forge.service().release(held[0])
    assert not held[0].path.exists()


def test_a_source_pinned_to_a_commit_the_forge_does_not_hold_is_refused(
    tmp_path: Path,
) -> None:
    forge = CheckoutForge(tmp_path, "https://example.com/org/rules")
    forge.commit({"x.yara": "rule X { condition: true }\n"})
    with pytest.raises(NotFoundError, match="is not in"):
        yara(YaraBin(), forge.service()).resolve_rules(
            [f"https://example.com/org/rules@{'e' * 40}"]
        )


def scanned(out: str, rc: int = 0, err: str = "") -> Callable[[list[str]], ProcessResult]:
    return lambda argv: ProcessResult(tuple(argv), rc, out.encode(), err.encode(), 0.0)


def rootfs(tmp_path: Path) -> Path:
    target = tmp_path / "rootfs"
    (target / "usr" / "bin").mkdir(parents=True)
    (target / "usr" / "bin" / "implant").write_text("x")
    (target / "tests").mkdir()
    (target / "tests" / "eicar").write_text("x")
    return target


def test_execute_reports_the_facts_rules_and_stats(tmp_path: Path) -> None:
    rules = pack(tmp_path / "pack")
    target = rootfs(tmp_path)
    out = f"Linux_Backdoor_BPFDoor {target}/usr/bin/implant\nWin_Ransom_Foo {target}/tests/eicar\n"
    runner = YaraBin(scan=scanned(out, err="warning: slow rule\n\n"))
    report = yara(runner, NEVER).execute(target, [str(rules)], timeout=60)
    scan_argv, scan_kw = runner.calls[-1]
    assert scan_argv[:6] == ["yara", "-r", "-w", "-N", "-z", str(64 * 1024 * 1024)]
    assert scan_argv[6].endswith("index.yar") and scan_argv[7] == str(target)
    assert scan_kw == {"check": False, "timeout_seconds": 60}
    assert {k: report[k] for k in ("tool", "version", "yara_version", "target")} == {
        "tool": "run_yara",
        "version": "9.9.9",
        "yara_version": "4.5.8",
        "target": str(target),
    }
    assert report["rules"][0]["root"] == str(rules.resolve())
    assert report["stats"] == {
        "facts": 2,
        "rules_compiled": 2,
        "rule_files": 2,
        "files_considered": 2,
        "carrier_facts": 1,
        "engine_errors": 1,
    }
    assert report["errors"] == ["warning: slow rule"]
    assert [f["family"] for f in report["facts"]] == ["BPFDoor", "Foo"]


def test_a_remote_pack_is_scanned_from_its_workspace_and_released(tmp_path: Path) -> None:
    forge = CheckoutForge(tmp_path, "https://example.com/org/rules")
    sha = forge.commit(
        {"backdoor/Linux.Backdoor.BPFDoor.yara": 'rule X { strings: $a = "x" condition: $a }\n'}
    )
    target = rootfs(tmp_path)
    out = f"X {target}/usr/bin/implant\n"
    report = yara(YaraBin(scan=scanned(out)), forge.service()).execute(
        target, [f"https://example.com/org/rules@{sha}"], timeout=30
    )
    (rule,) = report["rules"]
    assert (rule["sha"], rule["license_note"]) == (
        str(sha),
        "verify upstream license before redistribution",
    )
    assert report["stats"] == {
        "facts": 1,
        "rules_compiled": 1,
        "rule_files": 1,
        "files_considered": 2,
        "carrier_facts": 0,
        "engine_errors": 0,
    }


def test_a_custom_binary_and_size_cap_are_passed_through(tmp_path: Path) -> None:
    rules = pack(tmp_path / "pack")
    runner = YaraBin(scan=scanned(""))
    yara(runner, NEVER).execute(
        rootfs(tmp_path), [str(rules)], timeout=5, yara_bin="/opt/bin/yara", max_file_mb=1
    )
    assert runner.argvs()[0] == ["/opt/bin/yara", "--version"]
    assert runner.argvs()[-1][:6] == ["/opt/bin/yara", "-r", "-w", "-N", "-z", "1048576"]


def test_a_pack_with_no_rule_files_is_a_runtime_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RuntimeError, match=r"no \.yar/\.yara rule files found"):
        yara(YaraBin(), NEVER).execute(rootfs(tmp_path), [str(empty)], timeout=5)


def test_a_failed_scan_with_no_output_is_a_runtime_error_but_partial_output_counts(
    tmp_path: Path,
) -> None:
    rules = [str(pack(tmp_path / "pack"))]
    target = rootfs(tmp_path)
    with pytest.raises(RuntimeError, match=r"yara failed \(exit 1\): compile error"):
        yara(YaraBin(scan=scanned("", rc=1, err="compile error")), NEVER).execute(
            target, rules, timeout=5
        )
    partial = scanned(f"Win_Ransom_Foo {target}/usr/bin/implant\n", rc=1, err="read error")
    report = yara(YaraBin(scan=partial), NEVER).execute(target, rules, timeout=5)
    assert report["stats"]["facts"] == 1 and report["errors"] == ["read error"]


def test_scan_returns_the_adapter_result_with_the_yara_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    target = rootfs(tmp_path)
    out = f"Linux_Backdoor_BPFDoor {target}/usr/bin/implant\nMystery {target}/usr/bin/implant\n"
    runner = YaraBin(scan=scanned(out))
    monkeypatch.setattr(
        yara_module.Yara,
        "resolve_rules",
        lambda self, s: ([{"root": str(pack(tmp_path / "pack"))}], []),
    )
    result = yara(runner, NEVER).scan(target)
    assert result.metadata.tool == "yara" and result.metadata.scanner_version == "4.5.8"
    assert result.scanned_at == "2026-10-24T12:00:00Z"
    assert [f.id for f in result.findings] == ["yara/Linux_Backdoor_BPFDoor", "yara/Mystery"]
    assert [f.category for f in result.findings] == ["backdoor", ""]


def test_scan_refuses_a_missing_target_or_binary_and_names_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        yara(YaraBin(), NEVER).scan(tmp_path / "absent")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError, match=r"yara not found on PATH \(yara\)"):
        yara(YaraBin(), NEVER).scan(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    timeout = ProcessTimeout(("yara",), subprocess.TimeoutExpired("yara", 7))
    runner = YaraBin(scan=lambda argv: timeout)
    with pytest.raises(TimeoutError, match="yara timed out after 7s"):
        yara(runner, NEVER).scan(rootfs(tmp_path), [str(pack(tmp_path / "pack"))], timeout=7)
