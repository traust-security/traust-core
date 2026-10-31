from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tests.v1.conftest import commit_all, git
from tests.v1.models.test_elf_formats import elf
from traust_core.v1.context import Config, Context
from traust_core.v1.context import tool_reports as reports
from traust_core.v1.context.config import Locations
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import osv, osv_sbom
from traust_core.v1.providers.tools.toolchain import ToolCheck
from traust_core.v1.providers.tools.yara import Yara

FIXTURES = Path(__file__).parents[2] / "fixtures" / "tools"
NOW = datetime(2026, 10, 27, 9, 30, tzinfo=UTC)


@pytest.fixture
def bindir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "bin"
    path.mkdir()
    monkeypatch.setenv("PATH", f"{path}{os.pathsep}{os.environ['PATH']}")
    return path


def fake(bindir: Path, name: str, body: str) -> Path:
    """An executable `name` on PATH running `body` (Python, with `json`, `sys` and `args`)."""
    path = bindir / name
    path.write_text(f"#!{sys.executable}\nimport json, sys, time\nargs = sys.argv[1:]\n{body}\n")
    path.chmod(0o755)
    return path


def context(tmp_path: Path, **locations: str) -> Context:
    ctx = Context(
        Config(home=tmp_path / "store", locations=Locations(**locations)), clock=FixedClock(NOW)
    )
    ctx.register_toolchain(FIXTURES / "external-tools.yaml", FIXTURES / "safe-exec-profiles.yaml")
    return ctx


def checkout(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    return repo


def git_repo(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    repo = checkout(tmp_path, files)
    git(repo, "init", "-q")
    return repo, commit_all(repo, "c")


OPENGREP = """
if args == ["--version"]:
    print("opengrep 1.25.0")
else:
    target = args[-1]
    print(json.dumps({
        "results": [
            {"check_id": "pack.go.weak-hash", "path": f"{target}/main.go",
             "start": {"line": 3}, "end": {"line": 3},
             "extra": {"severity": "ERROR", "message": "md5", "lines": "md5.Sum(b)",
                       "metadata": {"cwe": ["CWE-328"]}}},
        ],
        "errors": [{"level": "warn", "type": "Syntax", "message": "skipped", "path": "x.go"}],
        "paths": {"scanned": ["main.go"]},
        "skipped_rules": [],
    }))
"""


def pack(tmp_path: Path) -> Path:
    root = tmp_path / "pack"
    (root / "go").mkdir(parents=True)
    (root / "go" / "weak-hash.yaml").write_text("rules:\n  - id: weak-hash\n")
    return root


def test_opengrep_reports_the_facts_on_the_registered_pack_with_the_binary_given(
    tmp_path: Path, bindir: Path
) -> None:
    fake(bindir, "my-opengrep", OPENGREP)
    ctx = context(tmp_path)
    ctx.register_rule_pack(pack(tmp_path))
    repo = checkout(tmp_path, {"main.go": "package main\n"})

    report = reports.opengrep_report(ctx, repo, [], binary="my-opengrep", timeout=60)

    assert report["opengrep_version"] == "opengrep 1.25.0"
    assert [r["source"] for r in report["rules"]] == ["traust rule pack"]
    assert report["rules"][0]["config_paths"] == [str(tmp_path / "pack" / "go")]
    [fact] = report["facts"]
    assert (fact["rule_id"], fact["file"], fact["severity_hint"]) == (
        "weak-hash",
        "main.go",
        "high",
    )
    assert report["stats"] == {
        "facts": 1,
        "files_scanned": 1,
        "errors": 1,
        "skipped_rules": 0,
        "suppressed_by_allowlist": 0,
    }
    assert report["rule_allowlist"] is None
    assert report["supplemental_packs"] == {"applied": [], "skipped": []}


def test_opengrep_keeps_only_the_allowed_rules_and_takes_a_pack_override(
    tmp_path: Path, bindir: Path
) -> None:
    fake(bindir, "opengrep", OPENGREP)
    ctx = context(tmp_path)
    ctx.register_rule_pack(tmp_path / "missing")
    repo = checkout(tmp_path, {"main.go": "package main\n"})

    report = reports.opengrep_report(ctx, repo, [], pack=pack(tmp_path), rule_allow="other")

    assert report["facts"] == []
    assert report["rule_allowlist"] == {
        "source": "inline",
        "rules": ["other"],
        "suppressed_facts": 1,
    }


def test_opengrep_refuses_a_pack_that_is_not_a_directory(tmp_path: Path) -> None:
    ctx = context(tmp_path)
    ctx.register_rule_pack(tmp_path / "missing")
    with pytest.raises(ConfigError, match="rule pack is not a directory"):
        reports.opengrep_report(ctx, tmp_path, [])


@pytest.mark.parametrize(
    ("sources", "rule_allow", "message"),
    [(["auto"], None, "refusing '--rules auto'"), ([], "@/nonexistent", "no such file")],
)
def test_opengrep_refusals_are_validation_errors(
    tmp_path: Path, sources: list[str], rule_allow: str | None, message: str
) -> None:
    ctx = context(tmp_path)
    ctx.register_rule_pack(pack(tmp_path))
    with pytest.raises(ValidationError, match=message):
        reports.opengrep_report(ctx, tmp_path, sources, rule_allow=rule_allow)


GOVULNCHECK = """
for rec in [
    {"config": {"scanner_name": "govulncheck", "scanner_version": "v1.1.4"}},
    {"osv": {"id": "GO-1", "aliases": ["CVE-1"], "summary": "bad"}},
    {"finding": {"osv": "GO-1", "fixed_version": "v1.2.0", "trace": [
        {"module": "m", "version": "v1.0.0", "package": "m/p", "function": "F"}]}},
]:
    print(json.dumps(rec))
"""


def test_govulncheck_reports_candidates_with_the_reach_summary(
    tmp_path: Path, bindir: Path
) -> None:
    fake(bindir, "govulncheck", GOVULNCHECK)
    repo, head = git_repo(tmp_path, {"go.mod": "module m\n"})

    doc = reports.govulncheck_report(
        context(tmp_path), repo, timeout=60, binary="govulncheck", harness_version="1.2.3"
    )

    meta = doc["metadata"]
    assert meta["artifact"] == "govulncheck-reachability-candidates"
    assert (meta["harness_version"], meta["commit"], meta["repository"]) == (
        "1.2.3",
        head,
        str(repo),
    )
    assert meta["generated_at"] == "2026-10-27T09:30:00Z"
    assert meta["invocation"] == "govulncheck -json ./..."
    assert meta["tool"]["version"] == "v1.1.4"
    assert doc["summary"] == {
        "osv_total": 1,
        "module_required_not_observed": 0,
        "package_imported_not_observed": 0,
        "symbol_reachable": 1,
    }
    assert [c["osv_id"] for c in doc["candidates"]] == ["GO-1"]


def test_govulncheck_without_a_config_record_is_a_runtime_error_and_a_plain_dir_has_no_commit(
    tmp_path: Path, bindir: Path
) -> None:
    fake(bindir, "govulncheck", "print('boom', file=sys.stderr); sys.exit(3)")
    with pytest.raises(RuntimeError, match=r"no scan output \(exit 3\):\nboom"):
        reports.govulncheck_report(
            context(tmp_path), tmp_path, timeout=60, binary="govulncheck", harness_version="x"
        )
    assert reports._head(context(tmp_path), tmp_path) is None


GITLEAKS = """
if args == ["version"]:
    print("8.30.1")
else:
    report = args[args.index("--report-path") + 1]
    repo = args[1]
    json.dump([{"RuleID": "aws-access-token", "Description": "AWS", "File": f"{repo}/k.env",
                "StartLine": 1, "EndLine": 1, "Entropy": 4.2, "Fingerprint": "c:k.env:aws:1",
                "Commit": "abc", "Date": "2026-01-01", "Email": "a@example.test"}],
              open(report, "w"))
"""


@pytest.mark.parametrize("mode", ["dir", "history"])
def test_gitleaks_reports_secret_free_candidates(tmp_path: Path, bindir: Path, mode: str) -> None:
    fake(bindir, "gitleaks", GITLEAKS)
    repo, head = git_repo(tmp_path, {"k.env": "KEY=x\n"})
    ctx = context(tmp_path, gitleaks_config=str(FIXTURES / "gitleaks-rules.toml"))

    doc = reports.gitleaks_report(ctx, repo, mode=mode, config=None, timeout=60, binary="gitleaks")

    assert doc["metadata"] == {
        "artifact": "gitleaks-secret-candidates",
        "mode": mode,
        "repository": str(repo),
        "head": head,
        "gitleaks_version": "8.30.1",
    }
    [cand] = doc["candidates"]
    assert (cand["rule_id"], cand["path"], cand["liveness_class"]) == (
        "aws-access-token",
        "k.env",
        "aws",
    )
    assert ("commit" in cand) == (mode == "history")


def test_gitleaks_needs_rules_and_its_binary(tmp_path: Path, bindir: Path) -> None:
    with pytest.raises(ConfigError, match="gitleaks config required"):
        reports.gitleaks_report(
            context(tmp_path), tmp_path, mode="dir", config=None, timeout=60, binary="gitleaks"
        )
    with pytest.raises(ConfigError, match="not a file"):
        reports.gitleaks_report(
            context(tmp_path),
            tmp_path,
            mode="dir",
            config=tmp_path / "none.toml",
            timeout=60,
            binary="gitleaks",
        )
    with pytest.raises(FileNotFoundError, match=r"gitleaks not found on PATH \(no-gitleaks\)"):
        reports.gitleaks_report(
            context(tmp_path),
            tmp_path,
            mode="dir",
            config=FIXTURES / "gitleaks-rules.toml",
            timeout=60,
            binary="no-gitleaks",
        )


def test_gitleaks_failing_or_timing_out_is_named(tmp_path: Path, bindir: Path) -> None:
    rules = FIXTURES / "gitleaks-rules.toml"
    fake(bindir, "gitleaks", "print('bad', file=sys.stderr); sys.exit(2)")
    with pytest.raises(RuntimeError, match=r"gitleaks failed \(exit 2\): bad"):
        reports.gitleaks_report(
            context(tmp_path), tmp_path, mode="dir", config=rules, timeout=60, binary="gitleaks"
        )
    fake(bindir, "gitleaks", "time.sleep(5)")
    with pytest.raises(TimeoutError, match="gitleaks timed out after 1s"):
        reports.gitleaks_report(
            context(tmp_path), tmp_path, mode="dir", config=rules, timeout=1, binary="gitleaks"
        )


YARA = """
if args == ["--version"]:
    print("4.5.8")
else:
    target = args[-1]
    print(f"Family_Trojan {target}/payload.bin")
"""


def rules_dir(tmp_path: Path) -> Path:
    root = tmp_path / "rules" / "malware"
    root.mkdir(parents=True)
    (root / "Win32.Trojan.Family.yara").write_text("rule Family_Trojan { condition: true }\n")
    return tmp_path / "rules"


def test_yara_reports_facts_from_the_local_rules(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "yara-4", YARA)
    target = checkout(tmp_path, {"payload.bin": "x"})

    report = reports.yara_report(
        context(tmp_path),
        target,
        [str(rules_dir(tmp_path))],
        timeout=60,
        binary="yara-4",
        max_file_mb=1,
    )

    assert report["yara_version"] == "4.5.8"
    assert report["stats"]["facts"] == report["stats"]["rules_compiled"] == 1
    assert [(f["rule_id"], f["file"]) for f in report["facts"]] == [
        ("Family_Trojan", "payload.bin")
    ]


def test_yara_refusals_missing_binary_and_timeout(
    tmp_path: Path, bindir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(bindir))  # a yara installed on the machine must not answer
    with pytest.raises(FileNotFoundError, match="yara not found on PATH"):
        reports.yara_report(
            context(tmp_path), tmp_path, [], timeout=60, binary="yara", max_file_mb=1
        )
    fake(bindir, "yara", YARA)
    with pytest.raises(ValidationError, match="40-hex"):
        reports.yara_report(
            context(tmp_path),
            tmp_path,
            ["https://example.test/rules@main"],
            timeout=60,
            binary="yara",
            max_file_mb=1,
        )
    with pytest.raises(RuntimeError, match=r"no \.yar/\.yara rule files"):
        empty = tmp_path / "empty"
        empty.mkdir()
        reports.yara_report(
            context(tmp_path), tmp_path, [str(empty)], timeout=60, binary="yara", max_file_mb=1
        )
    fake(bindir, "yara", "time.sleep(5) if args != ['--version'] else print('4.5.8')")
    with pytest.raises(TimeoutError, match="yara timed out after 1s"):
        reports.yara_report(
            context(tmp_path),
            tmp_path,
            [str(rules_dir(tmp_path))],
            timeout=1,
            binary="yara",
            max_file_mb=1,
        )
    monkeypatch.setattr(
        Yara, "execute", lambda *a, **k: (_ for _ in ()).throw(ValidationError("x"))
    )
    with pytest.raises(ValidationError, match="x"):
        reports.yara_report(
            context(tmp_path), tmp_path, [], timeout=60, binary="yara", max_file_mb=1
        )


def test_k8s_hardening_reports_the_khs_checks(tmp_path: Path) -> None:
    repo = checkout(
        tmp_path,
        {
            "deploy.yaml": (
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
                "  - name: c\n    image: i\n    securityContext:\n      privileged: true\n"
            )
        },
    )
    report = reports.k8s_hardening_report(repo)
    assert report["tool"] == "scan_k8s_hardening"
    assert report["target"] == str(repo)
    assert any(r["check"] == "KHS-W01" and r["file"] == "deploy.yaml" for r in report["results"])
    assert report["summary"]["KHS-W01"] == 1


def test_joern_states_its_soundness_even_when_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    doc = reports.joern_report(
        context(tmp_path),
        tmp_path,
        symbols=["a.B#c"],
        language="java",
        packages="",
        module="",
        timeout=60,
        max_sites=10,
    )
    assert doc["status"] == "skipped: joern not on PATH"
    assert list(doc)[-1] == "soundness"
    assert doc["soundness"]["absent_path"].startswith("NEVER proof of safety")


def test_joern_runs_the_symbols_with_the_java_opts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def run_scan(repo: Path, **kw: Any) -> dict[str, Any]:
        seen.update(kw, repo=repo)
        return {"tool": "joern", "status": "ran", "targets": []}

    monkeypatch.setattr(reports.joern, "run_scan", run_scan)
    monkeypatch.setenv("JOERN_JAVA_OPTS", "-Xmx2g")
    doc = reports.joern_report(
        context(tmp_path),
        tmp_path,
        symbols=["f"],
        language="c",
        packages="p",
        module="m",
        timeout=30,
        max_sites=5,
    )
    assert doc["status"] == "ran" and "soundness" in doc
    assert seen["runner"].allows("joern-parse") and not seen["runner"].allows("git")
    assert {k: seen[k] for k in ("symbols", "language", "packages", "module", "timeout")} == {
        "symbols": ("f",),
        "language": "c",
        "packages": "p",
        "module": "m",
        "timeout": 30,
    }
    assert (seen["max_sites"], seen["java_opts"]) == (5, "-Xmx2g")


def test_osv_api_runs_through_the_registry_lookup_and_deps_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = context(tmp_path)
    registry = tmp_path / "feeds.yaml"
    registry.write_text(
        "version: 1\nsources:\n"
        "  deps_dev:\n    tier: live\n    url_template: https://dd.test/v3/systems/{ident}\n"
    )
    ctx.register_feeds(registry)
    seen: dict[str, Any] = {}
    lookup = object()
    monkeypatch.setattr(reports, "osv_lookup", lambda c: lookup)

    def scan_api(repo: Path, advisories: object, clock: object, resolver: object) -> dict[str, Any]:
        seen.update(repo=repo, advisories=advisories, resolver=resolver)
        return {"provenance": {"status": "complete"}, "candidates": []}

    monkeypatch.setattr(osv, "scan_api", scan_api)
    assert reports.osv_report(ctx, tmp_path, timeout=60)["provenance"]["status"] == "complete"
    assert seen["repo"] == tmp_path and seen["advisories"] is lookup
    assert seen["resolver"] is not None and seen["resolver"].base_url == "https://dd.test/v3"


def test_osv_api_without_deps_dev_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reports, "osv_lookup", lambda c: object())
    with pytest.raises(ConfigError, match="no deps_dev feed source"):
        reports.osv_report(context(tmp_path), tmp_path, timeout=60)


def test_osv_without_a_live_osv_source_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no OSV API lookup"):
        reports.osv_report(context(tmp_path), tmp_path, timeout=60)


OSV_SCANNER = """
if args == ["--version"]:
    print("osv-scanner version: 2.7.0")
    sys.exit(0)
target = args[-1]
print(json.dumps({"results": [{"source": {"path": f"{target}/go.mod"}, "packages": [
    {"package": {"name": "golang.org/x/net", "ecosystem": "Go", "version": "0.1.0"},
     "groups": [{"ids": ["GO-2"], "max_severity": "7.5"}],
     "vulnerabilities": [{"id": "GO-2", "aliases": ["CVE-2"], "summary": "s",
                          "affected": [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
                                        "ranges": [{"events": [{"fixed": "0.2.0"}]}]}]}]}]}]}))
sys.exit(1)
"""


def test_osv_scanner_offline_reads_its_candidates_and_version(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "osv-scanner", OSV_SCANNER)
    repo = checkout(tmp_path, {"go.mod": "module m\n"})

    body = reports.osv_report(context(tmp_path), repo, scanner="osv-scanner", timeout=60)

    prov = body["provenance"]
    assert prov["status"] == "complete"
    assert prov["tool_version"] == "osv-scanner version: 2.7.0"
    assert prov["invocation"].endswith(f"--format json --offline {repo}")
    [cand] = body["candidates"]
    assert (cand["osv_id"], cand["package"], cand["fixed_version"]) == (
        "GO-2",
        "golang.org/x/net",
        "0.2.0",
    )
    assert cand["sources"] == ["go.mod"]


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ("print('no db', file=sys.stderr); sys.exit(127)", "produced no JSON (exit 127):\nno db"),
        (
            "print('{}'); print('Error: unable to load db', file=sys.stderr); sys.exit(127)",
            "failed (exit 127): Error: unable to load db",
        ),
        ("time.sleep(5)", "timed out after 1"),
    ],
)
def test_a_failing_osv_scanner_is_a_failed_body_naming_the_air_gapped_setup(
    tmp_path: Path, bindir: Path, body: str, detail: str
) -> None:
    fake(bindir, "osv-scanner", body)
    out = reports.osv_report(
        context(tmp_path), tmp_path, scanner="osv-scanner", timeout=1, freeze=False
    )
    failure = out["provenance"]["failure"]
    assert out["provenance"]["status"] == "failed" and out["candidates"] == []
    assert detail in failure["detail"]
    assert failure["detail"].endswith(f" — {reports.OSV_AIR_GAPPED_HELP}")


def test_a_missing_osv_scanner_is_a_failed_body(tmp_path: Path) -> None:
    out = reports.osv_report(context(tmp_path), tmp_path, scanner="no-osv-scanner", timeout=60)
    assert out["provenance"]["failure"]["detail"] == (
        f"osv-scanner not found (no-osv-scanner): {reports.OSV_AIR_GAPPED_HELP}"
    )


def syft(tmp_path: Path) -> Path:
    path = tmp_path / "img.syft.json"
    path.write_text(
        json.dumps(
            {
                "source": {"name": "img", "metadata": {"userInput": "registry.example.test/img"}},
                "artifacts": [
                    {
                        "id": "a1",
                        "type": "go-module",
                        "name": "golang.org/x/net",
                        "version": "0.1.0",
                        "purl": "pkg:golang/golang.org/x/net@0.1.0",
                        "locations": [{"path": "/app/bin"}],
                    }
                ],
                "artifactRelationships": [],
            }
        )
    )
    return path


SBOM_SCANNER = """
print(json.dumps({"results": [{"packages": [
    {"package": {"name": "golang.org/x/net", "ecosystem": "Go", "version": "0.1.0"},
     "vulnerabilities": [{"id": "GO-2", "aliases": ["CVE-2"]}]}]}]}))
sys.exit(1)
"""
GRYPE = {
    "matches": [
        {
            "artifact": {"purl": "pkg:golang/golang.org/x/net@0.1.0", "type": "go-module"},
            "vulnerability": {"id": "CVE-2"},
        }
    ]
}


def test_osv_sbom_offline_counts_the_sbom_and_marks_grype_duplicates(
    tmp_path: Path, bindir: Path
) -> None:
    fake(bindir, "osv-scanner", SBOM_SCANNER)
    body = reports.osv_sbom_report(
        context(tmp_path), syft(tmp_path), scanner="osv-scanner", timeout=60, grype=GRYPE
    )
    prov = body["provenance"]
    assert prov["status"] == "complete" and prov["image"] == "registry.example.test/img"
    assert prov["language_packages"] == 1
    assert prov["grype_dedupe"] == {"also_in_grype": 1, "osv_only": 0}
    assert prov["grype_os_installed_matches"] == 0 and body["grype_os_installed"] == []
    assert [c["also_in_grype"] for c in body["candidates"]] == [True]


def test_a_failed_sbom_scan_keeps_its_counts_and_lists_grypes_matches_undeduped(
    tmp_path: Path,
) -> None:
    body = reports.osv_sbom_report(
        context(tmp_path), syft(tmp_path), scanner="no-osv-scanner", timeout=60, grype=GRYPE
    )
    prov = body["provenance"]
    assert prov["status"] == "failed" and prov["sbom_artifacts"] == 1
    assert "grype_dedupe" not in prov and prov["grype_os_installed_matches"] == 0


def test_osv_sbom_api_runs_through_the_registry_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reports, "osv_lookup", lambda c: "lookup")
    monkeypatch.setattr(
        osv_sbom,
        "scan_sbom",
        lambda doc, advisories, clock: {
            "provenance": {"status": "complete", "advisories": advisories},
            "candidates": [],
        },
    )
    body = reports.osv_sbom_report(context(tmp_path), syft(tmp_path), timeout=60)
    assert body == {"provenance": {"status": "complete", "advisories": "lookup"}, "candidates": []}


def test_a_malformed_sbom_is_a_validation_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"bomFormat": "CycloneDX"}')
    with pytest.raises(ValidationError):
        reports.osv_sbom_report(context(tmp_path), bad, timeout=60)


def test_elf_reports_header_libraries_and_symbol_matches(tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(elf())
    report = reports.elf_report(binary, ["libssl"], max_scan=1_000_000)
    assert report is not None
    assert report["metadata"] == {"arch": "x86_64", "elf_class": 64, "endian": "little"}
    assert report["linked_libraries"] == ["libssl.so.3", "libc.so.6"]
    assert [m["matched"] for m in report["string_matches"]] == ["libssl"]
    assert "string_matches" not in (reports.elf_report(binary, [], max_scan=10) or {})


def test_elf_report_is_none_for_anything_else(tmp_path: Path) -> None:
    text = tmp_path / "t"
    text.write_text("#!/bin/sh\n")
    assert reports.elf_report(text, [], max_scan=10) is None


def test_the_toolchain_doctors_doors() -> None:
    missing = ToolCheck(name="gitleaks", installed=False)
    ready = ToolCheck(name="opengrep", installed=True, version="1.25.0", version_ok=True)
    assert reports.populatable_tools() == {"grype"}
    assert reports.toolchain_failures([missing, ready]) == ["gitleaks: not found on PATH"]
    assert reports.tool_stamp(ready) == "opengrep 1.25.0"
