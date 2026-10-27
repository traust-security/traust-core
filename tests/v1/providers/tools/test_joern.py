from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import joern as jr
from traust_core.v1.providers.tools.joern import PatternInput

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def _tree(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_symbol_becomes_method_prefix() -> None:
    [pat] = jr.patterns_from(PatternInput(symbols=("com.foo.Bar#deserialize",)))
    assert pat["pattern"] == "com.foo.Bar.deserialize:" and pat["kind"] == "symbol"


def test_a_symbol_without_a_method_is_a_package() -> None:
    pats = jr.patterns_from(PatternInput(symbols=("com.foo", "com.bar.")))
    assert [p["pattern"] for p in pats] == ["com.foo.", "com.bar."]


def test_packages_get_trailing_dot() -> None:
    pats = jr.patterns_from(PatternInput(packages="com.foo, ,com.bar."))
    assert [p["pattern"] for p in pats] == ["com.foo.", "com.bar."]
    assert all(p["kind"] == "package" for p in pats)


def test_module_group_is_heuristic_fallback_only() -> None:
    [pat] = jr.patterns_from(PatternInput(module="com.fasterxml.jackson.core:jackson-databind"))
    assert pat["kind"] == "group-heuristic"
    stronger = jr.patterns_from(
        PatternInput(symbols=("com.x.Y#z",), module="com.fasterxml.jackson.core:jackson-databind")
    )
    assert all(p["kind"] != "group-heuristic" for p in stronger)


def test_groupless_module_derives_nothing() -> None:
    assert jr.patterns_from(PatternInput(module="flatjar")) == []


def test_duplicate_patterns_collapse_in_order() -> None:
    pats = jr.patterns_from(PatternInput(symbols=("com.foo",), packages="com.foo,com.bar"))
    assert [p["pattern"] for p in pats] == ["com.foo.", "com.bar."]


def test_c_symbols_are_exact_match() -> None:
    pats = jr.patterns_from(PatternInput(symbols=("EVP_EncryptUpdate", "strcpy"), language="c"))
    assert [p["pattern"] for p in pats] == ["=EVP_EncryptUpdate", "=strcpy"]
    assert all(p["kind"] == "symbol" for p in pats)


def test_bare_class_symbol_uses_contains_match() -> None:
    [pat] = jr.patterns_from(PatternInput(symbols=("Bar#deserialize",)))
    assert pat["pattern"].startswith("~") and pat["kind"] == "symbol"


def test_frontend_is_explicit_per_language() -> None:
    assert jr._FRONTEND == {"java": "JAVASRC", "c": "NEWC"}


def test_derives_real_package_not_group_id(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        "src/main/java/a/A.java",
        "package a;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nclass A {}\n",
    )
    got = jr.derive_packages_from_imports(tmp_path, "com.fasterxml.jackson.core:jackson-databind")
    assert [g["pattern"] for g in got] == ["com.fasterxml.jackson.databind."]
    assert got[0]["evidence_file"] == "src/main/java/a/A.java"


def test_ranks_out_weak_single_token_matches(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        "src/main/java/a/A.java",
        "package a;\n"
        "import com.fasterxml.jackson.databind.ObjectMapper;\n"
        "import io.quarkus.jackson.ObjectMapperCustomizer;\n"
        "class A {}\n",
    )
    got = jr.derive_packages_from_imports(tmp_path, "com.fasterxml.jackson.core:jackson-databind")
    assert [g["pattern"] for g in got] == ["com.fasterxml.jackson.databind."]


def test_emits_nothing_when_dependency_is_not_imported(tmp_path: Path) -> None:
    _tree(tmp_path, "src/main/java/a/A.java", "package a;\nimport java.util.List;\nclass A {}\n")
    assert jr.derive_packages_from_imports(tmp_path, "com.h2database:h2") == []
    assert jr.derive_packages_from_imports(tmp_path, "core:api") == []


def test_group_heuristic_still_used_when_no_import_evidence(tmp_path: Path) -> None:
    pats = jr.patterns_from(PatternInput(repo=tmp_path, module="com.example.grp:artifact"))
    assert pats[0]["kind"] == "group-heuristic"


def test_import_derived_packages_back_a_module(tmp_path: Path) -> None:
    _tree(tmp_path, "A.java", "import com.fasterxml.jackson.databind.ObjectMapper;\n")
    [pat] = jr.patterns_from(
        PatternInput(repo=tmp_path, module="com.fasterxml.jackson.core:jackson-databind")
    )
    assert pat["source"] == "import-derived:com.fasterxml.jackson.databind"


class Runner:
    """joern and joern-parse, scripted: a version, a CPG, and the query's TSV."""

    def __init__(self, tsv: str = "", *, parse_rc: int = 0, query_rc: int = 0) -> None:
        self.tsv = tsv
        self.parse_rc = parse_rc
        self.query_rc = query_rc
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(self, argv: Any, **kw: Any) -> ProcessResult:
        args = tuple(argv)
        self.calls.append((args, kw))
        if args[1] == "--version":
            return ProcessResult(args, 0, b"Version: 4.0.600\n", b"", 0.1)
        if Path(args[0]).name == "joern-parse":
            if self.parse_rc == 0:
                Path(args[args.index("--output") + 1]).write_bytes(b"cpg")
            return ProcessResult(args, self.parse_rc, b"", b"parse broke", 0.1)
        if self.query_rc == 0:
            out = next(a for a in args if a.startswith("outFile=")).removeprefix("outFile=")
            Path(out).write_text(self.tsv)
        return ProcessResult(args, self.query_rc, b"", b"query broke", 0.1)


def runner(fake: Runner) -> ProcessRunner:
    return fake  # type: ignore[return-value]


@pytest.fixture
def on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jr.shutil, "which", lambda name: f"/opt/joern/{name}")


@pytest.fixture
def java_repo(tmp_path: Path) -> Path:
    _tree(tmp_path, "src/main/java/a/A.java", "class A {}\n")
    return tmp_path


def test_skips_without_joern_and_states_the_asymmetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(jr.shutil, "which", lambda _: None)
    doc = jr.with_soundness(jr.run_scan(tmp_path, runner=runner(Runner()), packages="com.foo"))
    assert doc["status"] == "skipped: joern not on PATH"
    assert "NEVER" in doc["soundness"]["absent_path"]


def test_skips_without_java_sources(tmp_path: Path, on_path: None) -> None:
    doc = jr.run_scan(tmp_path, runner=runner(Runner()), packages="com.foo")
    assert doc["status"] == "skipped: no java sources"


def test_skips_when_no_pattern_is_derivable(java_repo: Path, on_path: None) -> None:
    doc = jr.run_scan(java_repo, runner=runner(Runner()), module="flatjar")
    assert doc["status"] == "skipped: no symbol/package patterns derivable"


def test_soundness_already_stated_is_kept() -> None:
    assert jr.with_soundness({"soundness": {"x": "y"}})["soundness"] == {"x": "y"}


def test_a_scan_reports_call_sites_by_pattern(java_repo: Path, on_path: None) -> None:
    repo = str(java_repo.resolve())
    tsv = "\n".join(
        [
            f"SITE\tcom.foo.\t{repo}/src/main/java/a/A.java\t9\ta.A.run\tcom.foo.X.y:void()",
            f"SITE\tcom.foo.\t{repo}/src/main/java/a/A.java\t3\ta.A.init\tcom.foo.X.z:void()",
            "SITE\tcom.foo.\tsrc/test/java/a/ATest.java\t4\ta.ATest.t\tcom.foo.X.y:void()",
            "SITE\tunknown.\tA.java\t1\tc\td",
            "COUNT\tcom.foo.\t5",
            "COUNT\tcom.bar.\t0",
            "COUNT\tunknown.\t1",
            "BOGUS",
        ]
    )
    fake = Runner(tsv)
    doc = jr.run_scan(
        java_repo, runner=runner(fake), packages="com.foo,com.bar", max_sites=2, java_opts="-Xmx1g"
    )
    assert (doc["status"], doc["version"], doc["frontend"]) == ("ran", "4.0.600", "JAVASRC")
    foo, bar = doc["targets"]
    assert [(s["file"], s["line"]) for s in foo["call_sites"]] == [
        ("src/main/java/a/A.java", 3),
        ("src/main/java/a/A.java", 9),
    ]
    assert foo["referenced"] and not foo["referenced_test_only"]
    assert (foo["total_calls"], foo["sites_capped_at"]) == (5, 2)
    assert not bar["referenced"] and "sites_capped_at" not in bar
    version, parse, query = fake.calls
    assert version[1] == {"stdin": b"", "check": False, "timeout_seconds": jr.VERSION_TIMEOUT}
    assert parse[0][2:4] == ("--language", "JAVASRC")
    assert parse[1]["env"] == query[1]["env"] == {"JAVA_OPTS": "-Xmx1g"}
    assert parse[1]["stdin"] == query[1]["stdin"] == b""


def test_test_only_sites_are_marked(java_repo: Path, on_path: None) -> None:
    tsv = "SITE\tcom.foo.\tsrc/test/java/ATest.java\t4\tt\tcom.foo.X.y\nCOUNT\tcom.foo.\t1\n"
    [target] = jr.run_scan(java_repo, runner=runner(Runner(tsv)), packages="com.foo")["targets"]
    assert not target["referenced"] and target["referenced_test_only"]
    assert target["call_sites"][0]["test_path"]


def test_a_failed_build_or_query_is_an_error_status(java_repo: Path, on_path: None) -> None:
    built = jr.run_scan(java_repo, runner=runner(Runner(parse_rc=1)), packages="com.foo")
    assert built["status"] == "error: joern-parse failed"
    assert built["detail_head"] == built["detail"] == "parse broke"
    queried = jr.run_scan(java_repo, runner=runner(Runner(query_rc=1)), packages="com.foo")
    assert (queried["status"], queried["detail"]) == ("error: joern query failed", "query broke")


def test_an_unreadable_version_is_unknown(java_repo: Path, on_path: None) -> None:
    class Silent(Runner):
        def run(self, argv: Any, **kw: Any) -> ProcessResult:
            if argv[1] == "--version":
                raise ProcessTimeout(tuple(argv), subprocess.TimeoutExpired(argv, 120))
            return super().run(argv, **kw)

    assert jr.run_scan(java_repo, runner=runner(Silent()), packages="a")["version"] == "unknown"

    class Unversioned(Runner):
        def run(self, argv: Any, **kw: Any) -> ProcessResult:
            if argv[1] == "--version":
                return ProcessResult(tuple(argv), 0, b"joern\n", b"", 0.1)
            return super().run(argv, **kw)

    assert (
        jr.run_scan(java_repo, runner=runner(Unversioned()), packages="a")["version"] == "unknown"
    )


def test_c_sources_build_with_the_c_frontend(tmp_path: Path, on_path: None) -> None:
    _tree(tmp_path, "src/a.c", "int main() {}\n")
    fake = Runner("COUNT\t=strcpy\t0\n")
    doc = jr.run_scan(tmp_path, runner=runner(fake), symbols=("strcpy",), language="c")
    assert doc["frontend"] == "NEWC" and doc["targets"][0]["pattern"] == "=strcpy"


def test_scan_returns_one_finding_per_call_site(java_repo: Path, on_path: None) -> None:
    tsv = "SITE\tcom.foo.X.y:\tsrc/A.java\t9\ta.A.run\tcom.foo.X.y:void()\nCOUNT\tcom.foo.X.y:\t1\n"
    result = jr.scan(
        java_repo, runner=runner(Runner(tsv)), clock=FixedClock(NOW), symbols=("com.foo.X#y",)
    )
    assert result.metadata.tool == "joern" and result.metadata.scanner_version == "4.0.600"
    [finding] = result.findings
    assert finding.id == "joern/com.foo.X.y::src/A.java:9"
    assert finding.title == "Call to com.foo.X#y at src/A.java"
    assert (finding.severity, finding.category) == ("high", "symbol")
    assert finding.locations[0].lines == "9" and finding.locations[0].description == "a.A.run"
    assert finding.description == "callee=com.foo.X.y:void() pattern=com.foo.X.y: kind=symbol"


def test_scan_raises_the_status_of_a_scan_that_did_not_run(tmp_path: Path, on_path: None) -> None:
    with pytest.raises(RuntimeError, match="skipped: no java sources"):
        jr.scan(tmp_path, runner=runner(Runner()), clock=FixedClock(NOW), symbols=("a.B#c",))
