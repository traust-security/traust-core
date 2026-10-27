"""YARA: ported from traust-engine tests/test_run_yara.py. The yara and git binaries are never
run: a scripted ProcessRunner answers for them."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import (
    ProcessError,
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


class Git(ProcessRunner):
    """Answers git (clone, checkout, rev-parse, status) and yara (version, scan)."""

    def __init__(
        self,
        *,
        head: str = PIN,
        dirty: str = "",
        scan: Callable[[list[str]], ProcessResult | BaseException] | None = None,
    ) -> None:
        super().__init__(["git", "yara"])
        self.head, self.dirty, self.scan = head, dirty, scan
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
        args = list(argv)
        self.calls.append((args, kw))
        out = b""
        if args[1:2] == ["clone"]:
            Path(args[-1]).mkdir(parents=True)
        elif "rev-parse" in args:
            out = self.head.encode()
        elif "status" in args:
            out = self.dirty.encode()
        elif args[1:] == ["--version"]:
            out = b"4.5.8\n"
        elif args[0].endswith("yara") and self.scan:
            answer = self.scan(args)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        return ProcessResult(tuple(args), 0, out, b"", 0.0)

    def argvs(self) -> list[list[str]]:
        return [a for a, _ in self.calls]


def yara(runner: ProcessRunner, cache: Path) -> Yara:
    return Yara(runner, FixedClock(WHEN), cache_root=cache, harness_version="9.9.9")


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
    runner = Git()
    with pytest.raises(ValueError, match=message):
        yara(runner, tmp_path).resolve_rules([source])
    assert runner.calls == []


def test_local_path_used_as_is(tmp_path: Path) -> None:
    (tmp_path / "r.yara").write_text("rule R { condition: true }", encoding="utf-8")
    (resolved,) = yara(Git(), tmp_path / "cache").resolve_rules([str(tmp_path)])
    assert resolved == {
        "source": str(tmp_path),
        "root": str(tmp_path.resolve()),
        "sha": None,
        "license_note": "local rules — license per author",
    }


def test_default_pin_is_immutable_40hex() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", RL_RULES_SHA)
    assert RL_RULES_REPO.startswith("https://")


def test_no_source_clones_the_pinned_default_pack_https_only(tmp_path: Path) -> None:
    runner = Git(head=RL_RULES_SHA)
    (resolved,) = yara(runner, tmp_path).resolve_rules([])
    dest = tmp_path / f"reversinglabs-yara-rules-{RL_RULES_SHA[:12]}"
    assert resolved == {
        "source": f"{RL_RULES_REPO}@{RL_RULES_SHA}",
        "root": str(dest),
        "sha": RL_RULES_SHA,
        "license_note": RL_RULES_LICENSE,
    }
    clone, checkout = runner.calls[:2]
    assert clone == (
        ["git", "clone", "--quiet", "--", RL_RULES_REPO, str(dest)],
        {"env": {"GIT_ALLOW_PROTOCOL": "https"}},
    )
    assert checkout[0] == ["git", "-C", str(dest), "checkout", "--quiet", RL_RULES_SHA]


def test_a_verified_cache_is_reused_and_another_repo_carries_a_license_caveat(
    tmp_path: Path,
) -> None:
    (tmp_path / f"rules-{PIN[:12]}").mkdir()
    runner = Git()
    (resolved,) = yara(runner, tmp_path).resolve_rules([f"https://example.com/org/rules@{PIN}"])
    assert resolved["license_note"] == "verify upstream license before redistribution"
    assert not [a for a in runner.argvs() if "clone" in a]


@pytest.mark.parametrize(("head", "dirty"), [("b" * 40, ""), (PIN, " M rule.yar\n")])
def test_a_cache_off_its_pin_or_dirty_is_recloned_then_refused_if_still_unverified(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, head: str, dirty: str
) -> None:
    dest = tmp_path / f"rules-{PIN[:12]}"
    dest.mkdir()
    (dest / "stale").write_text("x")
    runner = Git(head=head, dirty=dirty)
    with pytest.raises(ValueError, match="still fails pin/cleanliness verification"):
        yara(runner, tmp_path).resolve_rules([f"https://example.com/rules@{PIN}"])
    assert "discarding and re-cloning" in caplog.text
    assert not (dest / "stale").exists()
    assert [a for a in runner.argvs() if "clone" in a]


def test_a_failed_clone_is_a_typed_process_error(tmp_path: Path) -> None:
    class Offline(Git):
        def run(self, argv: Sequence[str], **kw: Any) -> ProcessResult:
            if "clone" in argv:
                raise ProcessError(ProcessResult(tuple(argv), 128, b"", b"no network", 0.0))
            return super().run(argv, **kw)

    with pytest.raises(ProcessError, match="no network"):
        yara(Offline(), tmp_path).resolve_rules([f"https://example.com/rules@{PIN}"])


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
    runner = Git(scan=scanned(out, err="warning: slow rule\n\n"))
    report = yara(runner, tmp_path / "cache").execute(target, [str(rules)], timeout=60)
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


def test_a_custom_binary_and_size_cap_are_passed_through(tmp_path: Path) -> None:
    rules = pack(tmp_path / "pack")
    runner = Git(scan=scanned(""))
    yara(runner, tmp_path).execute(
        rootfs(tmp_path), [str(rules)], timeout=5, yara_bin="/opt/bin/yara", max_file_mb=1
    )
    assert runner.argvs()[0] == ["/opt/bin/yara", "--version"]
    assert runner.argvs()[-1][:6] == ["/opt/bin/yara", "-r", "-w", "-N", "-z", "1048576"]


def test_a_pack_with_no_rule_files_is_a_runtime_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RuntimeError, match=r"no \.yar/\.yara rule files found"):
        yara(Git(), tmp_path).execute(rootfs(tmp_path), [str(empty)], timeout=5)


def test_a_failed_scan_with_no_output_is_a_runtime_error_but_partial_output_counts(
    tmp_path: Path,
) -> None:
    rules = [str(pack(tmp_path / "pack"))]
    target = rootfs(tmp_path)
    with pytest.raises(RuntimeError, match=r"yara failed \(exit 1\): compile error"):
        yara(Git(scan=scanned("", rc=1, err="compile error")), tmp_path).execute(
            target, rules, timeout=5
        )
    partial = scanned(f"Win_Ransom_Foo {target}/usr/bin/implant\n", rc=1, err="read error")
    report = yara(Git(scan=partial), tmp_path).execute(target, rules, timeout=5)
    assert report["stats"]["facts"] == 1 and report["errors"] == ["read error"]


def test_scan_returns_the_adapter_result_with_the_yara_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    target = rootfs(tmp_path)
    out = f"Linux_Backdoor_BPFDoor {target}/usr/bin/implant\nMystery {target}/usr/bin/implant\n"
    runner = Git(scan=scanned(out))
    monkeypatch.setattr(
        yara_module.Yara, "resolve_rules", lambda self, s: [{"root": str(pack(tmp_path / "pack"))}]
    )
    result = yara(runner, tmp_path).scan(target)
    assert result.metadata.tool == "yara" and result.metadata.scanner_version == "4.5.8"
    assert result.scanned_at == "2026-10-24T12:00:00Z"
    assert [f.id for f in result.findings] == ["yara/Linux_Backdoor_BPFDoor", "yara/Mystery"]
    assert [f.category for f in result.findings] == ["backdoor", ""]


def test_scan_refuses_a_missing_target_or_binary_and_names_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        yara(Git(), tmp_path).scan(tmp_path / "absent")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(FileNotFoundError, match=r"yara not found on PATH \(yara\)"):
        yara(Git(), tmp_path).scan(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    timeout = ProcessTimeout(("yara",), subprocess.TimeoutExpired("yara", 7))
    runner = Git(scan=lambda argv: timeout)
    with pytest.raises(TimeoutError, match="yara timed out after 7s"):
        yara(runner, tmp_path).scan(rootfs(tmp_path), [str(pack(tmp_path / "pack"))], timeout=7)
