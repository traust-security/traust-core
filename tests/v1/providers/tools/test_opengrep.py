from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import IntegrityError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import opengrep as R
from traust_core.v1.providers.tools.opengrep import RuleAllowlist, SupplementalPack

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
SHA = "a" * 40

RAW: dict[str, Any] = {
    "results": [
        {
            "check_id": "rules.go-sqli-taint",
            "path": "/repo/main.go",
            "start": {"line": 10},
            "end": {"line": 11},
            "extra": {
                "severity": "ERROR",
                "message": "tainted query",
                "lines": "db.Query(q)",
                "dataflow_trace": {"taint_source": []},
                "metadata": {"cwe": "CWE-89", "owasp": ["A03:2021"], "confidence": "HIGH"},
            },
        },
        {
            "check_id": "rules.llm-output-to-sql",
            "path": "/repo/ask.py",
            "start": {"line": 5},
            "end": {"line": 5},
            "extra": {
                "severity": "ERROR",
                "message": "model output to SQL",
                "metadata": {"cwe": ["CWE-1426", "CWE-89"], "owasp_llm": "LLM05"},
            },
        },
        {
            "check_id": "rules.open-encoding",
            "path": "/repo/test/util_test.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {"severity": "INFO", "message": "m", "metadata": {}},
        },
    ],
    "errors": [
        {"level": "warn", "type": "ParseError", "message": "x" * 500, "path": "/repo/gen.go"}
    ],
    "paths": {"scanned": ["/repo/main.go", "/repo/test/util_test.py"]},
    "skipped_rules": [],
}


def _rules(n: int, prefix: str) -> str:
    return "rules:\n" + "".join(
        f"  - id: {prefix}-{i}\n    languages: [x]\n    message: m\n    pattern: x\n"
        for i in range(n)
    )


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    root = tmp_path / "pack"
    for lang, n in {"go": 12, "python": 8, "bash": 3}.items():
        (root / lang).mkdir(parents=True)
        (root / lang / "rules.yaml").write_text(_rules(n, f"traust-{lang}"))
    return root


@pytest.fixture
def target(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.go").write_text("package main\n")
    return root


class Runner:
    """opengrep and git, scripted: opengrep's JSON, a clone that writes the pinned checkout."""

    def __init__(self, report: dict[str, Any] | bytes = RAW, *, head: str = SHA) -> None:
        self.report = report
        self.head = head
        self.dirty = ""
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(self, argv: Any, **kw: Any) -> ProcessResult:
        args = tuple(argv)
        self.calls.append((args, kw))
        out = b""
        if args[:2] == ("git", "clone"):
            dest = Path(args[-1])
            (dest / "go").mkdir(parents=True)
            (dest / "rules" / "languages" / "go").mkdir(parents=True)
        elif args[0] == "git" and args[3:] == ("rev-parse", "HEAD"):
            out = self.head.encode()
        elif args[0] == "git" and args[3:] == ("status", "--porcelain"):
            out = self.dirty.encode()
        elif args[1:] == ("--version",):
            out = b"warning\n1.25.0\n"
        elif args[1] == "scan":
            out = (
                self.report if isinstance(self.report, bytes) else json.dumps(self.report).encode()
            )
        return ProcessResult(args, 0, out, b"", 0.1)

    def argvs(self, head: str) -> list[tuple[str, ...]]:
        return [a for a, _ in self.calls if a[0] == head]


def runner(fake: Runner) -> ProcessRunner:
    return fake  # type: ignore[return-value]


def test_fact_shape_and_severity_mapping() -> None:
    facts, _ = R.normalize(RAW, Path("/repo"))
    assert len(facts) == 3
    f = facts[0]
    assert f["rule_id"] == "go-sqli-taint"
    assert f["severity_hint"] == "high"
    assert f["file"] == "main.go"
    assert (f["start_line"], f["end_line"]) == (10, 11)
    assert f["cwe"] == ["CWE-89"]
    assert f["owasp"] == ["A03:2021"]
    assert f["owasp_llm"] == []
    assert f["taint"] and not f["test_path"]


def test_test_path_tagged_and_info_is_low() -> None:
    facts, _ = R.normalize(RAW, Path("/repo"))
    assert facts[2]["test_path"]
    assert facts[2]["severity_hint"] == "low"
    assert not facts[2]["taint"]


def test_owasp_llm_carried_and_str_normalized() -> None:
    facts, _ = R.normalize(RAW, Path("/repo"))
    assert facts[1]["owasp_llm"] == ["LLM05"]
    assert facts[1]["cwe"] == ["CWE-1426", "CWE-89"]


@pytest.mark.parametrize(
    ("check_id", "bare"),
    [
        ("traust-go-ssrf-request-taint", "traust-go-ssrf-request-taint"),
        ("go.traust-go-ssrf-request-taint", "traust-go-ssrf-request-taint"),
        (
            "skills.secure-code-audit.opengrep-rules.bash.traust-bash-data-exposure-xtrace",
            "traust-bash-data-exposure-xtrace",
        ),
        ("", ""),
    ],
)
def test_bare_rule_id_strips_dotted_path_prefixes(check_id: str, bare: str) -> None:
    assert R.bare_rule_id(check_id) == bare


def test_errors_surfaced_and_trimmed() -> None:
    _, errors = R.normalize(RAW, Path("/repo"))
    assert len(errors) == 1 and len(errors[0]["message"]) <= 300


def test_a_path_outside_the_target_stays_as_reported() -> None:
    raw = {"results": [{"check_id": "r", "path": "/elsewhere/x.go", "extra": {}}]}
    [fact] = R.normalize(raw, Path("/repo"))[0]
    assert fact["file"] == "/elsewhere/x.go" and fact["start_line"] == 0


def test_a_nosem_comment_on_or_above_the_match_marks_the_fact(tmp_path: Path) -> None:
    (tmp_path / "a.go").write_text("x := 1\n// nosemgrep: r\nexec(c)\nclean()\n")
    raw = {
        "results": [
            {"check_id": "r", "path": "a.go", "start": {"line": 3}, "end": {"line": 3}},
            {"check_id": "r", "path": "a.go", "start": {"line": 4}, "end": {"line": 4}},
            {"check_id": "r", "path": "b.go", "extra": {"lines": "f() # NOSEM"}},
            {"check_id": "r", "path": "absent.go", "start": {"line": 2}},
        ]
    }
    facts, _ = R.normalize(raw, tmp_path)
    assert [f["nosem_marked"] for f in facts] == [True, False, True, False]


def test_auto_is_refused(pack: Path) -> None:
    with pytest.raises(ValidationError, match="refusing '--rules auto'"):
        R.resolve_rules(["auto"], Path(), pack, runner(Runner()))


def test_registry_shorthand_carries_license_note(pack: Path) -> None:
    [resolved] = R.resolve_rules(["p/golang"], Path(), pack, runner(Runner()))
    assert resolved["config"] == ["p/golang"] and "license" in resolved["license_note"].lower()


def test_local_path_used_as_is(tmp_path: Path, pack: Path) -> None:
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n")
    [resolved] = R.resolve_rules([str(rules)], Path(), pack, runner(Runner()))
    assert resolved["config"] == [str(rules.resolve())]


def test_missing_local_path_is_refused(pack: Path) -> None:
    with pytest.raises(ValidationError, match="rules source not found"):
        R.resolve_rules(["/nonexistent/rules.yaml"], Path(), pack, runner(Runner()))


def test_default_is_the_pack_language_filtered(pack: Path, target: Path) -> None:
    [resolved] = R.resolve_rules([], target, pack, runner(Runner()))
    assert resolved["source"] == "traust rule pack"
    assert resolved["config"] == [str(pack / "go")]
    assert "no external restrictions" in resolved["license_note"]


def test_a_target_in_no_pack_language_scans_with_the_whole_pack(pack: Path, tmp_path: Path) -> None:
    (tmp_path / "x.rs").write_text("fn main() {}\n")
    [resolved] = R.resolve_rules([], tmp_path, pack, runner(Runner()))
    assert resolved["config"] == [str(pack)]


def test_a_missing_pack_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        R.resolve_rules([], tmp_path, tmp_path / "absent", runner(Runner()))


def test_fork_supplement_pin_constants() -> None:
    assert "opengrep-rules" in R.FORK_RULES_REPO and len(R.FORK_RULES_SHA) == 40


@pytest.mark.parametrize(
    ("src", "pinned"),
    [
        (R.FORK_RULES_REPO, (R.FORK_RULES_REPO, R.FORK_RULES_SHA)),
        (f"https://example.com/rules@{SHA}", ("https://example.com/rules", SHA)),
    ],
)
def test_a_git_source_is_pinned_to_a_commit(src: str, pinned: tuple[str, str]) -> None:
    assert R.pinned_rules_source(src) == pinned


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ("https://example.com/rules@main", "40-hex commit"),
        ("https://example.com/rules", "40-hex commit"),
        (f"http://example.com/rules@{SHA}", "https:// URLs only"),
        (f"git@example.com:org/rules@{SHA}", "https:// URLs only"),
    ],
)
def test_a_movable_ref_or_insecure_transport_is_refused(src: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        R.pinned_rules_source(src)


def test_a_git_source_is_cloned_once_at_its_pin(
    pack: Path, target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R, "CACHE_ROOT", tmp_path / "cache")
    fake = Runner()
    src = f"{R.ARGUS_RULES_REPO}@{SHA}"
    [resolved] = R.resolve_rules([src], target, pack, runner(fake))
    dest = tmp_path / "cache" / f"argus-observe-rules-{SHA[:12]}"
    clone, kw = next((a, k) for a, k in fake.calls if a[:2] == ("git", "clone"))
    assert clone[-2:] == (R.ARGUS_RULES_REPO, str(dest))
    assert kw["env"] == {"GIT_ALLOW_PROTOCOL": "https"}
    assert ("git", "-C", str(dest), "checkout", "--quiet", SHA) in fake.argvs("git")
    assert resolved["config"] == [str(dest / "rules" / "languages" / "go")]
    assert resolved["sha"] == SHA and resolved["license_note"] == R.ARGUS_RULES_LICENSE
    fake.calls.clear()
    R.resolve_rules([src], target, pack, runner(fake))
    assert not [a for a in fake.argvs("git") if a[1] == "clone"]


def test_a_tampered_rule_cache_is_recloned_and_refused_if_it_stays_unverifiable(
    pack: Path, target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R, "CACHE_ROOT", tmp_path / "cache")
    src = f"https://example.com/rules@{SHA}"
    dest = R.rules_cache_dir("https://example.com/rules", SHA)
    dest.mkdir(parents=True)
    fake = Runner()
    fake.dirty = " M go/rules.yaml\n"
    with pytest.raises(IntegrityError, match="refusing to scan with unverifiable rules"):
        R.resolve_rules([src], target, pack, runner(fake))
    assert [a for a in fake.argvs("git") if a[1] == "clone"]
    fake.dirty = ""
    [resolved] = R.resolve_rules([src], target, pack, runner(fake))
    assert resolved["config"] == [str(dest)]
    assert resolved["license_note"] == "verify upstream license before redistribution"


def test_detects_languages_and_excludes_vendor(tmp_path: Path) -> None:
    (tmp_path / "a.go").write_text("package a")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "b.py").write_text("x=1")
    assert R.detect_language_dirs(tmp_path) == {"go"}


def test_thin_and_uncovered_languages(pack: Path, tmp_path: Path) -> None:
    for name, text in {"a.py": "x = 1\n", "b.rs": "fn main() {}\n", "c.yaml": "k: v\n"}.items():
        (tmp_path / name).write_text(text)
    (tmp_path / "d.sh").write_text("echo\n")
    cov = R.coverage_block(tmp_path, pack)
    assert cov["detected_languages"] == ["bash", "python", "rust"]
    assert cov["traust_rules_by_language"]["python"] >= R.THIN_RULE_THRESHOLD
    assert cov["thin_languages"] == ["bash"]
    assert cov["uncovered_languages"] == ["rust"]


def test_pack_rule_ids_and_counts(pack: Path) -> None:
    assert R.pack_rule_counts(pack) == {"bash": 3, "go": 12, "python": 8}
    ids = R.harness_pack_rule_ids(pack)
    assert len(ids) == 23 and all(i.startswith("traust-") for i in ids)


def _packs(**overrides: Any) -> dict[str, Any]:
    pack = {"enabled": True, "source": f"https://x/y@{SHA}", "rules": ["r1", "r2"]}
    return {"p": {**pack, **overrides}}


def test_reads_enabled_packs() -> None:
    assert R.supplemental_packs(_packs()) == [
        SupplementalPack("p", f"https://x/y@{SHA}", ("r1", "r2"))
    ]


@pytest.mark.parametrize(
    "packs",
    [_packs(enabled=False), _packs(rules=[]), _packs(source=None), {"p": "not a mapping"}, {}],
)
def test_a_disabled_ruleless_or_sourceless_pack_is_off(packs: dict[str, Any]) -> None:
    assert R.supplemental_packs(packs) == []


def test_the_scan_command_never_honours_the_targets_own_suppressions(
    pack: Path, target: Path
) -> None:
    fake = Runner()
    R.execute_scan(target, [], pack=pack, runner=runner(fake))
    [scan] = [a for a in fake.argvs("opengrep") if a[1] == "scan"]
    assert scan[:5] == ("opengrep", "scan", "--json", "--quiet", "--disable-nosem")
    assert scan[5:7] == ("--config", str(pack / "go"))
    assert scan[-1] == str(target)
    assert [scan[i + 1] for i, a in enumerate(scan) if a == "--exclude"] == list(R.EXCLUDES)


def test_the_report_carries_facts_rules_coverage_and_the_scanner_version(
    pack: Path, target: Path
) -> None:
    report = R.execute_scan(target, [], pack=pack, runner=runner(Runner()))
    assert report["tool"] == "run_opengrep" and report["opengrep_version"] == "1.25.0"
    assert report["rules"] == [
        {
            "source": "traust rule pack",
            "sha": None,
            "license_note": R.TRAUST_PACK_LICENSE,
            "config_paths": [str(pack / "go")],
        }
    ]
    assert report["stats"] == {
        "facts": 3,
        "files_scanned": 2,
        "errors": 1,
        "skipped_rules": 0,
        "suppressed_by_allowlist": 0,
    }
    assert report["rule_allowlist"] is None
    assert report["supplemental_packs"] == {"applied": [], "skipped": []}
    assert report["coverage"]["detected_languages"] == ["go"]


def test_a_supplements_allowlist_filters_only_the_supplement(
    pack: Path, target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R, "CACHE_ROOT", tmp_path / "cache")
    raw = {
        "results": [
            {"check_id": "traust-go-1", "path": "main.go", "extra": {}},
            {"check_id": "argus.go-tls-bypass", "path": "main.go", "extra": {}},
            {"check_id": "argus.go-reflection-basic-usage", "path": "main.go", "extra": {}},
        ]
    }
    supplements = (
        SupplementalPack("argus", f"https://example.com/argus@{SHA}", ("go-tls-bypass",)),
        SupplementalPack("broken", "https://example.com/broken@main", ("x",)),
    )
    report = R.execute_scan(
        target, [], pack=pack, runner=runner(Runner(raw)), supplements=supplements
    )
    assert [f["rule_id"] for f in report["facts"]] == ["traust-go-1", "go-tls-bypass"]
    assert report["supplemental_packs"]["applied"] == ["argus"]
    [skipped] = report["supplemental_packs"]["skipped"]
    assert skipped["pack"] == "broken" and "40-hex commit" in skipped["reason"]
    allowlist = report["rule_allowlist"]
    assert allowlist["source"] == (
        "rule-pack-allowlist.yaml (1 supplemental + 23 traust rule pack rules)"
    )
    assert allowlist["suppressed_facts"] == 1 and "traust-go-1" in allowlist["rules"]


def test_supplements_apply_only_to_a_default_run(pack: Path, target: Path, tmp_path: Path) -> None:
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n")
    fake = Runner()
    supplement = SupplementalPack("argus", f"https://example.com/argus@{SHA}", ("r",))
    report = R.execute_scan(
        target, [str(rules)], pack=pack, runner=runner(fake), supplements=(supplement,)
    )
    assert report["supplemental_packs"]["applied"] == [] and not fake.argvs("git")


def test_an_explicit_rule_allowlist_filters_every_fact(pack: Path, target: Path) -> None:
    allow = RuleAllowlist(frozenset({"go-sqli-taint"}), "inline")
    report = R.execute_scan(target, [], pack=pack, runner=runner(Runner()), rule_allow=allow)
    assert [f["rule_id"] for f in report["facts"]] == ["go-sqli-taint"]
    assert report["rule_allowlist"] == {
        "source": "inline",
        "rules": ["go-sqli-taint"],
        "suppressed_facts": 2,
    }


def test_a_scan_with_no_json_or_past_its_timeout_fails(pack: Path, target: Path) -> None:
    with pytest.raises(RuntimeError, match="opengrep produced no JSON"):
        R.execute_scan(target, [], pack=pack, runner=runner(Runner(b"")))

    class Slow(Runner):
        def run(self, argv: Any, **kw: Any) -> ProcessResult:
            if argv[1] == "scan":
                raise ProcessTimeout(tuple(argv), subprocess.TimeoutExpired(argv, 5))
            return super().run(argv, **kw)

    with pytest.raises(TimeoutError, match="opengrep timed out after 5s"):
        R.execute_scan(target, [], pack=pack, runner=runner(Slow()), timeout=5)


def test_scan_returns_typed_findings(
    pack: Path, target: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    raw = {
        "results": [
            {
                "check_id": "go.traust-go-tls",
                "path": str(target / "main.go"),
                "start": {"line": 1},
                "end": {"line": 2},
                "extra": {
                    "severity": "WARNING",
                    "message": "",
                    "lines": "tls() // nosem",
                    "metadata": {"cwe": ["CWE-295: Improper Certificate Validation", "TLS"]},
                },
            }
        ]
    }
    with caplog.at_level(logging.WARNING):
        result = R.scan(target, pack, runner=runner(Runner(raw)), clock=FixedClock(NOW))
    assert isinstance(result, AdapterResultArtifact)
    assert result.target == str(target.resolve()) and result.scanned_at == "2026-10-24T12:00:00Z"
    assert result.metadata.tool == "opengrep" and result.metadata.scanner_version == "1.25.0"
    [finding] = result.findings
    assert finding.id == "opengrep/traust-go-tls" and finding.title == "traust-go-tls"
    assert finding.severity == "medium" and finding.cwes == ("CWE-295",)
    assert finding.locations[0].path == "main.go" and finding.locations[0].lines == "1-2"
    assert finding.evidence[0].code == "tls() // nosem"
    assert "not an exemption" in finding.description
    assert result.summary.total == 1
    assert "1 CWE value(s) with no CWE-<n> id" in caplog.text


def test_scan_forwards_the_supplements_and_never_loads_config(
    pack: Path, target: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def execute(_target: Path, _sources: Any, **kw: Any) -> dict[str, Any]:
        seen.update(kw)
        return {"facts": [], "opengrep_version": "test"}

    monkeypatch.setattr(R, "execute_scan", execute)
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    clock = FixedClock(NOW)
    R.scan(target, pack, runner=runner(Runner()), clock=clock)
    assert seen["supplements"] == ()
    supplement = SupplementalPack("p", f"https://example.com/rules@{SHA}", ("r1",))
    R.scan(target, pack, runner=runner(Runner()), clock=clock, supplements=(supplement,))
    assert seen["supplements"] == (supplement,)


def test_scan_refuses_a_missing_target_or_binary(
    pack: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FixedClock(NOW)
    with pytest.raises(ValueError, match="not a directory"):
        R.scan(tmp_path / "absent", pack, runner=runner(Runner()), clock=clock)
    monkeypatch.setattr(R.shutil, "which", lambda _: None)
    with pytest.raises(FileNotFoundError, match="opengrep not found on PATH"):
        R.scan(tmp_path, pack, runner=runner(Runner()), clock=clock)


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep not on PATH")
def test_a_real_scan_with_a_local_rule(tmp_path: Path, pack: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", c) }\n'
    )
    rule = tmp_path.parent / "rule.yaml"
    rule.write_text(
        "rules:\n"
        "  - id: sh-c\n"
        "    languages: [go]\n"
        "    severity: WARNING\n"
        "    message: shell exec\n"
        '    pattern: exec.Command("sh", "-c", ...)\n'
    )
    report = R.execute_scan(
        tmp_path, [str(rule)], pack=pack, runner=ProcessRunner(("opengrep", "git"))
    )
    assert report["stats"]["facts"] == 1
    [fact] = report["facts"]
    assert Path(fact["file"]).name == "main.go" and fact["severity_hint"] == "medium"
    assert report["opengrep_version"]
