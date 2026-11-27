from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import CheckoutForge, NoCheckouts
from tests.v1.providers.tools.opengrep_fixtures import native_output, write_fixture, write_rule
from traust_core.v1.context.documents import yaml_documents
from traust_core.v1.errors import NotFoundError, ScannerError, ScannerFailure, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import (
    ProcessError,
    ProcessOutputLimit,
    ProcessResult,
    ProcessRunner,
    ProcessTimeout,
)
from traust_core.v1.providers.tools import opengrep as R
from traust_core.v1.providers.tools.opengrep import RuleAllowlist, SupplementalPack

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
FIXED_CLOCK = FixedClock(NOW)
SHA = "a" * 40
PINNED = "b" * 40

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
        write_fixture(root / lang / "rules.yaml")
    return root


@pytest.fixture
def target(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "main.go").write_text("package main\n")
    return root


class Runner:
    """opengrep, scripted: its JSON report and version."""

    def __init__(self, report: dict[str, Any] | bytes = RAW) -> None:
        self.report = report
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(self, argv: Any, **kw: Any) -> ProcessResult:
        args = tuple(argv)
        self.calls.append((args, kw))
        native = native_output(args)
        if native is not None:
            return ProcessResult(args, 0, native, b"", 0.1)
        out = b""
        if args[1:] == ("--version",):
            out = b"warning\n1.25.0\n"
        elif args[1] == "scan":
            out = (
                self.report if isinstance(self.report, bytes) else json.dumps(self.report).encode()
            )
        return ProcessResult(args, 0, out, b"", 0.1)


def runner(fake: Runner) -> ProcessRunner:
    return fake  # type: ignore[return-value]


NEVER = NoCheckouts()


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
        R.resolve_rules(["auto"], Path(), pack, NEVER)


def test_registry_shorthand_without_local_fixtures_is_refused(pack: Path) -> None:
    with pytest.raises(ValidationError, match="no local test fixtures"):
        R.resolve_rules(["p/golang"], Path(), pack, NEVER)


def test_local_path_used_as_is(tmp_path: Path, pack: Path) -> None:
    rules = tmp_path / "r.yaml"
    rules.write_text("rules: []\n")
    [resolved], _ = R.resolve_rules([str(rules)], Path(), pack, NEVER)
    assert resolved["config"] == [str(rules.resolve())]


def test_missing_local_path_is_refused(pack: Path) -> None:
    with pytest.raises(ValidationError, match="rules source not found"):
        R.resolve_rules(["/nonexistent/rules.yaml"], Path(), pack, NEVER)


def test_default_is_the_pack_language_filtered(pack: Path, target: Path) -> None:
    [resolved], _ = R.resolve_rules([], target, pack, NEVER)
    assert resolved["source"] == "traust rule pack"
    assert resolved["config"] == [str(pack / "go")]
    assert "no external restrictions" in resolved["license_note"]


def test_a_target_in_no_pack_language_scans_with_the_whole_pack(pack: Path, tmp_path: Path) -> None:
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "x.rs").write_text("fn main() {}\n")
    [resolved], _ = R.resolve_rules([], target, pack, NEVER)
    assert resolved["config"] == [str(pack)]


@pytest.fixture
def web_pack(tmp_path: Path) -> Path:
    root = tmp_path / "web-pack"
    for lang, n in {"typescript": 10, "yaml": 2}.items():
        (root / lang).mkdir(parents=True)
        (root / lang / "rules.yaml").write_text(_rules(n, f"traust-{lang}"))
        write_fixture(root / lang / "rules.yaml")
    return root


@pytest.mark.parametrize("name", ["app.js", "app.jsx", "app.mjs", "app.cjs"])
def test_javascript_scans_with_the_typescript_rules(
    web_pack: Path, tmp_path: Path, name: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / name).write_text("module.exports = {};\n")
    (repo / "ci.yaml").write_text("k: v\n")
    [resolved], _ = R.resolve_rules([], repo, web_pack, NEVER)
    assert resolved["config"] == [str(web_pack / "typescript"), str(web_pack / "yaml")]


def test_javascript_coverage_counts_the_typescript_rules(web_pack: Path, tmp_path: Path) -> None:
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "server.js").write_text("module.exports = {};\n")
    cov = R.coverage_block(target, web_pack)
    assert cov["detected_languages"] == ["javascript"]
    assert cov["traust_rules_by_language"] == {"javascript": 10}
    assert cov["uncovered_languages"] == [] and cov["thin_languages"] == []


def test_a_missing_pack_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a directory"):
        R.resolve_rules([], tmp_path, tmp_path / "absent", NEVER)


def test_fork_supplement_pin_constants() -> None:
    assert "opengrep-rules" in R.FORK_RULES_REPO and len(R.FORK_RULES_SHA) == 40


@pytest.mark.parametrize(
    ("src", "pinned"),
    [
        (R.FORK_RULES_REPO, (R.FORK_RULES_REPO, R.FORK_RULES_SHA)),
        (f"https://example.com/o/rules@{SHA}", ("https://example.com/o/rules", SHA)),
    ],
)
def test_a_git_source_is_pinned_to_a_commit(src: str, pinned: tuple[str, str]) -> None:
    assert R.pinned_rules_source(src) == pinned


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ("https://example.com/o/rules@main", "40-hex commit"),
        ("https://example.com/o/rules", "40-hex commit"),
        (f"http://example.com/rules@{SHA}", "https:// URLs only"),
        (f"git@example.com:org/rules@{SHA}", "https:// URLs only"),
    ],
)
def test_a_movable_ref_or_insecure_transport_is_refused(src: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        R.pinned_rules_source(src)


def test_a_git_source_is_a_workspace_from_the_checkout_service_at_its_pin(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    forge = CheckoutForge(tmp_path, R.ARGUS_RULES_REPO)
    sha = forge.commit({"rules/languages/go/tls.yaml": "rules:\n  - id: x\n    pattern: y\n"})
    [resolved], held = R.resolve_rules(
        [f"{R.ARGUS_RULES_REPO}@{sha}"], target, pack, forge.service()
    )
    (workspace,) = held
    assert resolved["config"] == [str(workspace.path / "rules" / "languages")]
    assert resolved["sha"] == str(sha) and resolved["license_note"] == R.ARGUS_RULES_LICENSE
    assert (workspace.path / "rules" / "languages" / "go" / "tls.yaml").is_file()
    forge.service().release(workspace)
    assert not workspace.path.exists()


def test_a_git_source_pinned_to_a_commit_the_forge_does_not_hold_is_refused(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    forge = CheckoutForge(tmp_path, "https://example.com/o/rules")
    forge.commit({"go/x.yaml": "rules: []\n"})
    with pytest.raises(NotFoundError, match="is not in"):
        R.resolve_rules([f"https://example.com/o/rules@{'e' * 40}"], target, pack, forge.service())


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


@pytest.mark.parametrize("packs", [_packs(enabled=False), {"p": "not a mapping"}, {}])
def test_a_disabled_pack_is_off(packs: dict[str, Any]) -> None:
    assert R.supplemental_packs(packs) == []


@pytest.mark.parametrize("packs", [_packs(rules=[]), _packs(source=None), _packs(rules=["r", "r"])])
def test_an_enabled_pack_cannot_silently_disable_or_duplicate_rules(packs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="needs a source and unique rule ids"):
        R.supplemental_packs(packs)


def test_local_adopter_sources_resolve_beside_the_allowlist(tmp_path: Path) -> None:
    [pack] = R.supplemental_packs(_packs(source="rules/acme"), base=tmp_path)
    assert pack.source == str(tmp_path / "rules" / "acme")


def test_the_scan_command_never_honours_the_targets_own_suppressions(
    pack: Path, target: Path
) -> None:
    fake = Runner()
    R.execute_scan(
        target,
        [],
        pack=pack,
        runner=runner(fake),
        checkouts=NEVER,
        load=yaml_documents,
        clock=FIXED_CLOCK,
    )
    [scan] = [a for a, _ in fake.calls if a[1] == "scan"]
    assert scan[:5] == ("opengrep", "scan", "--json", "--quiet", "--disable-nosem")
    assert scan[-1] == str(target)
    assert [scan[i + 1] for i, a in enumerate(scan) if a == "--exclude"] == list(R.EXCLUDES)


def test_the_report_carries_facts_rules_coverage_and_the_scanner_version(
    pack: Path, target: Path
) -> None:
    report = R.execute_scan(
        target,
        [],
        pack=pack,
        runner=runner(Runner()),
        checkouts=NEVER,
        load=yaml_documents,
        clock=FIXED_CLOCK,
    )
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
    assert report["supplemental_packs"] == {"applied": []}
    assert report["coverage"]["detected_languages"] == ["go"]


def test_a_supplements_allowlist_filters_only_the_supplement(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    forge = CheckoutForge(tmp_path, "https://example.com/o/argus")
    sha = forge.commit(
        {
            "go/x.yaml": (
                "rules:\n  - id: go-tls-bypass\n    languages: [go]\n"
                "    severity: ERROR\n    message: TLS bypass\n    pattern: tls()\n"
            ),
            "go/x.go": (
                "package fixture\nfunc sample() {\n// ruleid: go-tls-bypass\n"
                "tls()\n// ok: go-tls-bypass\nverified_tls()\n}\n"
            ),
        }
    )
    raw = {
        "results": [
            {"check_id": "traust-go-1", "path": "main.go", "extra": {}},
            {"check_id": "argus.go-tls-bypass", "path": "main.go", "extra": {}},
            {"check_id": "argus.go-reflection-basic-usage", "path": "main.go", "extra": {}},
        ]
    }
    supplements = (
        SupplementalPack("argus", f"https://example.com/o/argus@{sha}", ("go-tls-bypass",)),
    )
    report = R.execute_scan(
        target,
        [],
        pack=pack,
        runner=runner(Runner(raw)),
        checkouts=forge.service(),
        load=yaml_documents,
        supplements=supplements,
        clock=FIXED_CLOCK,
    )
    assert [f["rule_id"] for f in report["facts"]] == ["traust-go-1", "go-tls-bypass"]
    assert report["supplemental_packs"]["applied"] == ["argus"]
    allowlist = report["rule_allowlist"]
    assert allowlist["source"] == (
        "rule-pack-allowlist.yaml (1 supplemental + 23 traust rule pack rules)"
    )
    assert allowlist["suppressed_facts"] == 1 and "traust-go-1" in allowlist["rules"]


def test_supplements_apply_only_to_a_default_run(pack: Path, target: Path, tmp_path: Path) -> None:
    rules = write_rule(tmp_path, "custom-rule", name="r")
    supplement = SupplementalPack("argus", f"https://example.com/o/argus@{SHA}", ("r",))
    report = R.execute_scan(
        target,
        [str(rules)],
        pack=pack,
        runner=runner(Runner()),
        checkouts=NEVER,
        load=yaml_documents,
        supplements=(supplement,),
        clock=FIXED_CLOCK,
    )
    assert report["supplemental_packs"]["applied"] == []


def test_an_explicit_rule_allowlist_filters_every_fact(pack: Path, target: Path) -> None:
    allow = RuleAllowlist(frozenset({"go-sqli-taint"}), "inline")
    report = R.execute_scan(
        target,
        [],
        pack=pack,
        runner=runner(Runner()),
        checkouts=NEVER,
        rule_allow=allow,
        load=yaml_documents,
        clock=FIXED_CLOCK,
    )
    assert [f["rule_id"] for f in report["facts"]] == ["go-sqli-taint"]
    assert report["rule_allowlist"] == {
        "source": "inline",
        "rules": ["go-sqli-taint"],
        "suppressed_facts": 2,
    }


def _custom(rule_id: str, **changes: object) -> dict[str, Any]:
    return {
        "id": rule_id,
        "languages": ["go"],
        "severity": "WARNING",
        "message": "Prefer the current API",
        "metadata": {"cwe": ["CWE-477"]},
        "pattern": "oldAPI($X)",
    } | changes


def _write_custom(root: Path, *rules: dict[str, Any]) -> Path:
    root.mkdir()
    config = root / "custom.yaml"
    config.write_text(json.dumps({"rules": rules}))
    write_fixture(config)
    return config


class AdditiveRunner(Runner):
    def __init__(self, *, noisy: bool = False, timed_out: bool = False) -> None:
        super().__init__(
            {
                "results": [
                    {"check_id": f"pack.{rule_id}", "path": "main.go", "extra": {}}
                    for rule_id in ("traust-go-1", "supp-rule")
                ]
            }
        )
        self.noisy = noisy
        self.timed_out = timed_out

    def run(self, argv: Any, **kw: Any) -> ProcessResult:
        if argv[1] != "scan" or not kw.get("max_output_bytes"):
            return super().run(argv, **kw)
        self.calls.append((tuple(argv), kw))
        if self.timed_out:
            raise ProcessTimeout(tuple(argv), subprocess.TimeoutExpired(argv, 1))
        ids = [
            rule["id"]
            for i, token in enumerate(argv)
            if token == "--config"
            for rule in json.loads(Path(argv[i + 1]).read_text())["rules"]
        ]
        return ProcessResult(
            tuple(argv),
            0,
            json.dumps(
                {
                    "results": [
                        {"check_id": f"optional.{rule_id}", "path": "main.go", "extra": {}}
                        for rule_id in ids
                        for _ in range(26 if self.noisy and rule_id == "extra-rule" else 1)
                    ],
                    "paths": {"scanned": ["main.go"]},
                }
            ).encode(),
            b"",
            0.1,
        )


def test_additions_preserve_primary_facts_and_reject_only_the_offending_rules(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    supplement = _write_custom(tmp_path / "supp", _custom("supp-rule"))
    locale = _write_custom(
        tmp_path / "extra",
        _custom("extra-rule"),
        _custom("traust-python-1"),
        _custom("supp-rule"),
        _custom("wrong-language", languages=["py"]),
        _custom("bad-pattern", pattern="$X"),
    )
    (locale.parent / "broken.yaml").write_text("rules: [")
    another = _write_custom(tmp_path / "another", _custom("extra-rule"))
    opts = {
        "pack": pack,
        "checkouts": NEVER,
        "load": yaml_documents,
        "supplements": (SupplementalPack("required", str(supplement.parent), ("supp-rule",)),),
    }
    primary = R.execute_scan(target, [], runner=runner(AdditiveRunner()), **opts, clock=FIXED_CLOCK)
    report = R.execute_scan(
        target,
        [],
        runner=runner(AdditiveRunner()),
        additive=(str(locale.parent), str(another.parent)),
        **opts,
        clock=FIXED_CLOCK,
    )
    assert report["outcome"] == "degraded"
    assert report["facts"][:2] == primary["facts"]
    assert [f["origin"] for f in report["facts"]] == [
        "traust",
        "supplement:required",
        f"additive:{locale.parent}",
    ]
    assert [f["rule_id"] for f in report["facts"]] == ["traust-go-1", "supp-rule", "extra-rule"]
    assert "extra-rule" in report["rule_allowlist"]["rules"]
    refusals = {r["rule_id"]: r for r in report["additive_rules"]["refused"]}
    assert {rule: r["check"] for rule, r in refusals.items()} == {
        None: "parse",
        "traust-python-1": "collision",
        "supp-rule": "collision",
        "bad-pattern": "catch-all",
        "extra-rule": "collision",
    }
    assert "traust rule pack" in refusals["traust-python-1"]["reason"]
    assert "required" in refusals["supp-rule"]["reason"]
    assert str(locale.parent) in refusals["extra-rule"]["reason"]
    assert str(another.parent) in refusals["extra-rule"]["reason"]
    assert report["additive_rules"]["degraded"] == {str(locale.parent): 4, str(another.parent): 1}
    assert [entry["rule_id"] for entry in report["additive_rules"]["skipped"]] == ["wrong-language"]


@pytest.mark.parametrize("timeout", [False, True])
def test_optional_scan_timeout_or_output_volume_keeps_the_primary_scan(
    pack: Path, target: Path, tmp_path: Path, timeout: bool
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("extra-rule"), _custom("another-rule"))
    raw = AdditiveRunner(noisy=True, timed_out=timeout)
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(raw),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra.parent),),
        clock=FIXED_CLOCK,
    )
    assert report["outcome"] == "degraded"
    assert report["facts"][0]["rule_id"] == "traust-go-1"
    assert [f["rule_id"] for f in report["facts"][2:]] == ([] if timeout else ["another-rule"])
    assert {r["check"] for r in report["additive_rules"]["refused"]} == {
        "scan" if timeout else "explosion"
    }


def test_explicit_output_allowlist_still_filters_admitted_additions(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("extra-rule"))
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(AdditiveRunner()),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        rule_allow=RuleAllowlist(frozenset({"traust-go-1"}), "explicit"),
        clock=FIXED_CLOCK,
    )
    assert [f["rule_id"] for f in report["facts"]] == ["traust-go-1"]
    assert [r["rule_id"] for r in report["additive_rules"]["applied"]] == ["extra-rule"]
    assert report["rule_allowlist"]["suppressed_facts"] == 2
    assert report["outcome"] == "succeeded"


def test_intake_refuses_the_whole_pack_on_a_static_collision_without_activation(
    pack: Path, tmp_path: Path
) -> None:
    extra = _write_custom(
        tmp_path / "extra", _custom("extra-rule", languages=["typescript"]), _custom("traust-go-1")
    )
    original = extra.read_bytes()
    raw = Runner()
    report = R.intake_rules(
        [str(extra)],
        tmp_path / "accepted",
        pack=pack,
        supplements=(),
        runner=runner(raw),
        checkouts=NEVER,
        load=yaml_documents,
        timeout=5,
        binary="opengrep",
        clock=FIXED_CLOCK,
    )
    assert report["admitted"] is False
    assert report["applied"] == []
    assert {r["check"] for r in report["refused"]} == {"collision", "admission"}
    assert "destination" not in report
    assert not (tmp_path / "accepted").exists()
    assert all(argv[1] != "scan" for argv, _ in raw.calls)
    assert extra.read_bytes() == original


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="requires native opengrep")
def test_native_intake_refuses_the_whole_pack_but_runtime_vetting_remains_partial(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "pack"
    pack.mkdir()
    extra = _write_custom(
        tmp_path / "extra",
        _custom("extra.good", pattern="deprecated($X)", languages=["python"]),
        _custom("extra.bad", pattern="absent($X)", languages=["python"]),
    )
    extra.with_suffix(".py").write_text(
        "# ruleid: extra.good,extra.bad\ndeprecated('value')\n"
        "# ok: extra.good,extra.bad\ncurrent('value')\n"
    )
    report = R.intake_rules(
        [str(extra)],
        tmp_path / "accepted",
        pack=pack,
        supplements=(),
        runner=ProcessRunner(("opengrep",)),
        checkouts=NEVER,
        load=yaml_documents,
        timeout=30,
        binary="opengrep",
        clock=FIXED_CLOCK,
    )
    assert report["admitted"] is False
    assert report["applied"] == []
    assert {r["rule_id"] for r in report["refused"]} == {"extra.good", "extra.bad"}
    assert {r["check"] for r in report["refused"]} == {"test"}
    assert not (tmp_path / "accepted").exists()

    write_rule(pack / "python", "baseline-rule")
    target = tmp_path / "checkout"
    target.mkdir()
    (target / "code.py").write_text("dangerous(value)\ndeprecated('value')\n")
    scan = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=ProcessRunner(("opengrep",)),
        checkouts=NEVER,
        load=yaml_documents,
        additive=[str(extra)],
        clock=FIXED_CLOCK,
    )
    assert [(f["rule_id"], f["origin"]) for f in scan["facts"]] == [
        ("baseline-rule", "traust"),
        ("extra.good", f"additive:{extra}"),
    ]
    assert [(r["rule_id"], r["check"]) for r in scan["additive_rules"]["refused"]] == [
        ("extra.bad", "test")
    ]


def test_a_scan_with_no_json_or_past_its_timeout_fails(pack: Path, target: Path) -> None:
    with pytest.raises(ScannerError, match="invalid JSON") as invalid:
        R.execute_scan(
            target,
            [],
            pack=pack,
            runner=runner(Runner(b"")),
            checkouts=NEVER,
            load=yaml_documents,
            clock=FIXED_CLOCK,
        )
    assert invalid.value.reason is ScannerFailure.OUTPUT

    class Slow(Runner):
        def run(self, argv: Any, **kw: Any) -> ProcessResult:
            if argv[1] == "scan":
                raise ProcessTimeout(tuple(argv), subprocess.TimeoutExpired(argv, 5))
            return super().run(argv, **kw)

    with pytest.raises(ScannerError, match="opengrep timed out after 5s") as timeout:
        R.execute_scan(
            target,
            [],
            pack=pack,
            runner=runner(Slow()),
            checkouts=NEVER,
            timeout=5,
            load=yaml_documents,
            clock=FIXED_CLOCK,
        )
    assert timeout.value.reason is ScannerFailure.TIMEOUT
    assert timeout.value.timeout_seconds == 5


class Refused:
    """A checkout seam that refuses every request with the error it was built from."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def checkout(self, request: Any) -> Any:
        raise self.error

    def release(self, workspace: Any) -> None:
        pass


@pytest.mark.parametrize(
    "error",
    [
        ProcessError(ProcessResult(("git", "fetch"), 128, b"", b"fatal: unreachable", 0.0)),
        ProcessTimeout(("git", "fetch"), subprocess.TimeoutExpired(["git", "fetch"], 600)),
        NotFoundError(f"commit {'e' * 40} is not in https://example.com/o/argus"),
    ],
    ids=["process-error", "process-timeout", "not-found"],
)
def test_an_unfetchable_enabled_supplement_aborts_instead_of_falling_back(
    pack: Path, target: Path, error: Exception
) -> None:
    supplement = SupplementalPack("argus", f"https://example.com/o/argus@{SHA}", ("go-tls-bypass",))
    with pytest.raises(type(error)):
        R.execute_scan(
            target,
            [],
            pack=pack,
            runner=runner(Runner()),
            checkouts=Refused(error),  # type: ignore[arg-type]
            load=yaml_documents,
            supplements=(supplement,),
            clock=FIXED_CLOCK,
        )


@pytest.mark.parametrize("name", ["repo", "-looks-like-an-option"])
def test_the_scanned_target_is_separated_from_the_options(
    pack: Path, tmp_path: Path, name: str
) -> None:
    target = tmp_path / name
    target.mkdir()
    (target / "main.go").write_text("package main\n")
    run = runner(Runner())
    R.execute_scan(
        target, [], pack=pack, runner=run, checkouts=NEVER, load=yaml_documents, clock=FIXED_CLOCK
    )
    scan_argv, _ = next(c for c in run.calls if c[0][1] == "scan")
    assert scan_argv[-2:] == ("--", str(target))


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
        result = R.scan(
            target,
            pack,
            runner=runner(Runner(raw)),
            checkouts=NEVER,
            clock=FixedClock(NOW),
            load=yaml_documents,
        )
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
        return {
            "facts": [],
            "opengrep_version": "test",
            "outcome": "succeeded",
            "stats": {"skipped_rules": 0},
        }

    monkeypatch.setattr(R, "execute_scan", execute)
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    clock = FixedClock(NOW)
    R.scan(target, pack, runner=runner(Runner()), checkouts=NEVER, clock=clock, load=yaml_documents)
    assert seen["supplements"] == ()
    supplement = SupplementalPack("p", f"https://example.com/o/rules@{SHA}", ("r1",))
    R.scan(
        target,
        pack,
        runner=runner(Runner()),
        checkouts=NEVER,
        load=yaml_documents,
        clock=clock,
        supplements=(supplement,),
        additive=("custom-pack",),
    )
    assert seen["supplements"] == (supplement,)
    assert seen["additive"] == ("custom-pack",)


@pytest.mark.parametrize(
    "partial",
    [
        {"skipped_rules": ["PRIVATE_NATIVE_SENTINEL"]},
        {"errors": [{"type": "ParseError", "message": "PRIVATE_NATIVE_SENTINEL"}]},
    ],
)
def test_artifact_scan_refuses_partial_native_coverage_without_disclosing_output(
    pack: Path, target: Path, monkeypatch: pytest.MonkeyPatch, partial: dict[str, Any]
) -> None:
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    with pytest.raises(ScannerError, match="incomplete rule coverage") as caught:
        R.scan(
            target,
            pack,
            runner=runner(Runner({"results": [], **partial})),
            checkouts=NEVER,
            clock=FIXED_CLOCK,
            load=yaml_documents,
        )
    assert caught.value.reason == ScannerFailure.OUTPUT
    assert "PRIVATE_NATIVE_SENTINEL" not in str(caught.value)


def test_artifact_scan_cannot_combine_replacement_and_additive_sources(
    pack: Path, target: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    with pytest.raises(ValidationError, match="cannot be combined"):
        R.scan(
            target,
            pack,
            rules=("replacement",),
            additive=("custom-pack",),
            runner=runner(Runner()),
            checkouts=NEVER,
            clock=FIXED_CLOCK,
            load=yaml_documents,
        )


def test_scan_refuses_a_missing_target_or_binary(
    pack: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FixedClock(NOW)
    with pytest.raises(ValueError, match="not a directory"):
        R.scan(
            tmp_path / "absent",
            pack,
            runner=runner(Runner()),
            checkouts=NEVER,
            clock=clock,
            load=yaml_documents,
        )
    monkeypatch.setattr(R.shutil, "which", lambda _: None)
    with pytest.raises(FileNotFoundError, match="opengrep not found on PATH"):
        R.scan(
            tmp_path,
            pack,
            runner=runner(Runner()),
            checkouts=NEVER,
            clock=clock,
            load=yaml_documents,
        )


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
    rule.with_suffix(".go").write_text(
        'package fixture\nimport "os/exec"\nfunc sample(c string) {\n'
        '// ruleid: sh-c\nexec.Command("sh", "-c", c)\n'
        '// ok: sh-c\nexec.Command("echo", c)\n}\n'
    )
    report = R.execute_scan(
        tmp_path,
        [str(rule)],
        pack=pack,
        runner=ProcessRunner(("opengrep", "git")),
        checkouts=NEVER,
        load=yaml_documents,
        clock=FIXED_CLOCK,
    )
    assert report["stats"]["facts"] == 1
    [fact] = report["facts"]
    assert Path(fact["file"]).name == "main.go" and fact["severity_hint"] == "medium"
    assert report["opengrep_version"]


@pytest.mark.parametrize(
    ("source", "want"),
    [
        (f"https://github.com/o/r@{PINNED}", ("https://github.com/o/r", PINNED)),
        (R.FORK_RULES_REPO, (R.FORK_RULES_REPO, R.FORK_RULES_SHA)),
        (R.FORK_RULES_REPO + "/", (R.FORK_RULES_REPO + "/", R.FORK_RULES_SHA)),
    ],
)
def test_a_pinned_rules_source_is_its_https_url_and_commit(
    source: str, want: tuple[str, str]
) -> None:
    assert R.pinned_rules_source(source) == want


@pytest.mark.parametrize(
    ("source", "match"),
    [
        ("https://github.com/o/r@main", "ref must be a 40-hex commit"),
        ("https://github.com/o/r", "ref must be a 40-hex commit"),
        (f"https://github.com/o/r@{PINNED[:12]}", "ref must be a 40-hex commit"),
        (f"http://github.com/o/r@{PINNED}", "https:// URLs only"),
        (f"git@github.com:o/r@{PINNED}", "https:// URLs only"),
    ],
)
def test_an_unpinned_or_non_https_rules_source_is_refused(source: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        R.pinned_rules_source(source)


def test_only_argus_nests_its_rules(tmp_path: Path) -> None:
    argus = "https://github.com/o/argus-observe-rules/"
    assert R.rules_root("https://github.com/o/r", tmp_path) == tmp_path
    assert R.rules_root(argus, tmp_path) == tmp_path / "rules"
    (tmp_path / "rules" / "languages").mkdir(parents=True)
    assert R.rules_root(argus, tmp_path) == tmp_path / "rules" / "languages"


def test_a_weakness_rule_hit_is_a_weakness_finding(
    pack: Path, target: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")
    hit = {
        "path": str(target / "main.go"),
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {
            "severity": "INFO",
            "message": "m",
            "lines": "x",
            "metadata": {"cwe": ["CWE-693"]},
        },
    }
    weak = {**hit, "check_id": "go.traust-go-weak"}
    weak["extra"] = {**hit["extra"], "metadata": {"cwe": ["CWE-693"], "kind": "weakness"}}
    raw = {"results": [{**hit, "check_id": "go.traust-go-plain"}, weak]}
    result = R.scan(
        target,
        pack,
        runner=runner(Runner(raw)),
        checkouts=NEVER,
        clock=FixedClock(NOW),
        load=yaml_documents,
    )
    kinds = {f.id: f.kind for f in result.findings}
    assert kinds == {"opengrep/traust-go-plain": None, "opengrep/traust-go-weak": "weakness"}


def test_engine_error_diagnostics_do_not_expose_native_source_text() -> None:
    sentinel = "PRIVATE_NATIVE_SENTINEL"
    _, errors = R.normalize(
        {
            "results": [],
            "errors": [
                {
                    "level": sentinel,
                    "type": sentinel,
                    "message": f"syntax error near {sentinel}",
                    "path": sentinel,
                }
            ],
        },
        Path("/repo"),
    )
    assert errors == [
        {"level": "error", "type": "ScannerError", "message": "native scanner reported an error"}
    ]
    assert sentinel not in json.dumps(errors)


class OptionalReportRunner(AdditiveRunner):
    def __init__(self, changes: dict[str, Any]) -> None:
        super().__init__()
        self.changes = changes

    def run(self, argv: Any, **kwargs: Any) -> ProcessResult:
        result = super().run(argv, **kwargs)
        if argv[1] == "scan" and kwargs.get("max_output_bytes"):
            report = json.loads(result.stdout) | self.changes
            return ProcessResult(
                result.argv, result.returncode, json.dumps(report).encode(), b"", 0.1
            )
        return result


@pytest.mark.parametrize("kind", ["PartialParsing", "ParseError", "Timeout"])
def test_optional_target_warnings_keep_valid_facts_and_report_partial_coverage(
    pack: Path, target: Path, tmp_path: Path, kind: str
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("extra-rule"))
    raw = OptionalReportRunner(
        {
            "errors": [{"level": "warn", "type": kind, "message": "private parse detail"}],
            "paths": {"scanned": ["main.go", "additional.go"]},
        }
    )
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(raw),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert {fact["rule_id"] for fact in report["facts"]} == {
        "traust-go-1",
        "supp-rule",
        "extra-rule",
    }
    assert report["outcome"] == "degraded"
    assert report["stats"]["files_scanned"] == 2
    assert [error["type"] for error in report["errors"]] == [kind]
    assert report["additive_rules"]["refused"] == []
    assert "private parse detail" not in json.dumps(report)


def test_optional_rule_errors_do_not_discard_other_rules_from_the_source(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("broken-rule"), _custom("healthy-rule"))
    raw = OptionalReportRunner(
        {
            "errors": [
                {"level": "error", "type": "RuleParseError", "rule_id": "optional.broken-rule"}
            ],
            "skipped_rules": ["optional.broken-rule"],
        }
    )
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(raw),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert {fact["rule_id"] for fact in report["facts"]} == {
        "traust-go-1",
        "supp-rule",
        "healthy-rule",
    }
    assert [entry["rule_id"] for entry in report["additive_rules"]["refused"]] == ["broken-rule"]
    assert [entry["rule_id"] for entry in report["additive_rules"]["applied"]] == ["healthy-rule"]
    assert report["outcome"] == "degraded"
    assert report["stats"]["skipped_rules"] == 1


def test_native_skipped_primary_rules_are_degraded_without_an_error(
    pack: Path, target: Path
) -> None:
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(Runner({"results": [], "skipped_rules": ["traust-go-1"]})),
        checkouts=NEVER,
        load=yaml_documents,
        clock=FIXED_CLOCK,
    )
    assert report["outcome"] == "degraded"
    assert report["stats"]["skipped_rules"] == 1
    assert report["errors"] == []


@pytest.mark.parametrize("failure", ["timeout", "noise"])
def test_failed_optional_source_does_not_reserve_a_later_working_rule_id(
    pack: Path, target: Path, tmp_path: Path, failure: str
) -> None:
    first = _write_custom(tmp_path / "first", _custom("extra-rule"))
    second = _write_custom(tmp_path / "second", _custom("extra-rule"))

    class FirstSourceFails(AdditiveRunner):
        def __init__(self) -> None:
            super().__init__()
            self.optional_scans = 0

        def run(self, argv: Any, **kwargs: Any) -> ProcessResult:
            if argv[1] == "scan" and kwargs.get("max_output_bytes"):
                self.optional_scans += 1
                self.timed_out = self.optional_scans == 1 and failure == "timeout"
                self.noisy = self.optional_scans == 1 and failure == "noise"
            return super().run(argv, **kwargs)

    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(FirstSourceFails()),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(first), str(second)),
        clock=FIXED_CLOCK,
    )
    assert [entry["source"] for entry in report["additive_rules"]["applied"]] == [str(second)]
    assert [fact["origin"] for fact in report["facts"] if fact["rule_id"] == "extra-rule"] == [
        f"additive:{second}"
    ]
    assert all(entry["check"] != "collision" for entry in report["additive_rules"]["refused"])


def test_valid_but_inapplicable_optional_rules_do_not_degrade_a_checkout(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("python-only", languages=["python"]))
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(AdditiveRunner()),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert report["outcome"] == "succeeded"
    assert report["additive_rules"]["refused"] == []
    assert report["additive_rules"]["degraded"] == {}
    assert [entry["rule_id"] for entry in report["additive_rules"]["skipped"]] == ["python-only"]


def test_dart_rules_are_applied_to_dart_checkouts(pack: Path, tmp_path: Path) -> None:
    target = tmp_path / "dart-checkout"
    target.mkdir()
    (target / "main.dart").write_text("void main() {}\n")
    extra = _write_custom(tmp_path / "extra", _custom("dart-rule", languages=["dart"]))
    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(AdditiveRunner()),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert [entry["rule_id"] for entry in report["additive_rules"]["applied"]] == ["dart-rule"]
    assert any(fact["rule_id"] == "dart-rule" for fact in report["facts"])


def test_optional_output_budget_accounts_for_checkout_paths(
    pack: Path, target: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(R, "_ADDITIVE_OUTPUT_LIMIT", 256)
    for index in range(12):
        (target / f"additional-{index}-long-path.go").write_text("package main\n")
    scanned = [str(path) for path in target.iterdir()]
    extra = _write_custom(tmp_path / "extra", _custom("extra-rule"))

    class BoundedPaths(OptionalReportRunner):
        def run(self, argv: Any, **kwargs: Any) -> ProcessResult:
            result = super().run(argv, **kwargs)
            limit = kwargs.get("max_output_bytes")
            if argv[1] == "scan" and limit and len(result.stdout) > limit:
                raise ProcessOutputLimit(result, limit)
            return result

    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(BoundedPaths({"paths": {"scanned": scanned}})),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert report["outcome"] == "succeeded"
    assert any(fact["rule_id"] == "extra-rule" for fact in report["facts"])
    assert report["stats"]["files_scanned"] == len(scanned)


def test_output_limit_is_reported_as_output_failure_without_losing_baseline(
    pack: Path, target: Path, tmp_path: Path
) -> None:
    extra = _write_custom(tmp_path / "extra", _custom("extra-rule"))

    class OutputLimit(AdditiveRunner):
        def run(self, argv: Any, **kwargs: Any) -> ProcessResult:
            if argv[1] == "scan" and (limit := kwargs.get("max_output_bytes")):
                raise ProcessOutputLimit(
                    ProcessResult(tuple(argv), -9, b"PRIVATE_NATIVE_OUTPUT", b"", 0.1), limit
                )
            return super().run(argv, **kwargs)

    report = R.execute_scan(
        target,
        (),
        pack=pack,
        runner=runner(OutputLimit()),
        checkouts=NEVER,
        load=yaml_documents,
        additive=(str(extra),),
        clock=FIXED_CLOCK,
    )
    assert {fact["rule_id"] for fact in report["facts"]} == {"traust-go-1", "supp-rule"}
    assert report["outcome"] == "degraded"
    assert "capture limit" in report["additive_rules"]["refused"][0]["reason"]
    assert "PRIVATE_NATIVE_OUTPUT" not in json.dumps(report)
