from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ValidationError
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import govulncheck as G
from traust_core.v1.providers.tools.safe_exec import SafeExec

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def _pretty_stream(*records: dict[str, Any]) -> str:
    """govulncheck -json emits a concatenation of pretty-printed objects."""
    return "\n".join(json.dumps(r, indent=2) for r in records)


CONFIG = {
    "config": {
        "scanner_name": "govulncheck",
        "scanner_version": "v1.1.4",
        "go_version": "go1.26.4",
        "db": "https://vuln.go.dev",
        "scan_level": "symbol",
    }
}
OSV = {
    "osv": {
        "id": "GO-2026-0001",
        "aliases": ["CVE-2026-1111"],
        "summary": "Example vulnerability in example.com/dep",
    }
}
MODULE_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [{"module": "example.com/dep", "version": "v1.2.0"}],
    }
}
PACKAGE_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [
            {"module": "example.com/dep", "version": "v1.2.0", "package": "example.com/dep/pkg"}
        ],
    }
}
SYMBOL_FINDING = {
    "finding": {
        "osv": "GO-2026-0001",
        "fixed_version": "v1.2.3",
        "trace": [
            {
                "module": "example.com/dep",
                "version": "v1.2.0",
                "package": "example.com/dep/pkg",
                "function": "Vulnerable",
                "position": {"filename": "pkg/v.go", "line": 10},
            },
            {
                "module": "example.com/target",
                "package": "example.com/target/cmd",
                "function": "main",
                "position": {"filename": "cmd/main.go", "line": 5},
            },
        ],
    }
}
OSV2 = {"osv": {"id": "GO-2026-0002", "aliases": [], "summary": "s"}}
MODULE2 = {
    "finding": {
        "osv": "GO-2026-0002",
        "trace": [{"module": "example.com/other", "version": "v0.1.0"}],
    }
}


class FakeSafeExec:
    def __init__(self, out: str = "", rc: int = 0, err: str = "") -> None:
        self.outcome = (rc, out, err)
        self.calls: list[tuple[Any, str, dict[str, Any]]] = []

    def run(self, cmd: Any, profile_name: str, **kw: Any) -> tuple[int, str, str]:
        self.calls.append((cmd, profile_name, kw))
        return self.outcome


def safe_exec(fake: FakeSafeExec) -> SafeExec:
    return fake  # type: ignore[return-value]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text(
        "module example.com/target\n\nrequire example.com/dep v1.2.0\n"
    )
    return tmp_path


def test_parses_concatenated_pretty_objects_and_jsonl() -> None:
    tool, cands = G.parse_stream(_pretty_stream(CONFIG, OSV, MODULE_FINDING))
    assert tool["version"] == "v1.1.4" and len(cands) == 1
    jsonl = "\n".join(json.dumps(r) for r in (CONFIG, OSV, MODULE_FINDING))
    assert G.parse_stream(jsonl) == (tool, cands)


def test_an_empty_stream_has_no_config_and_garbage_is_refused() -> None:
    assert G.parse_stream("") == ({}, [])
    with pytest.raises(ValidationError, match="malformed record at offset 0"):
        G.parse_stream("not json")


@pytest.mark.parametrize(
    ("finding", "level"),
    [
        (MODULE_FINDING["finding"], "module_required_not_observed"),
        (PACKAGE_FINDING["finding"], "package_imported_not_observed"),
        (SYMBOL_FINDING["finding"], "symbol_reachable"),
        ({"trace": []}, "module_required_not_observed"),
    ],
)
def test_classify_levels(finding: dict[str, Any], level: str) -> None:
    assert G.classify(finding) == level


def test_most_specific_evidence_wins() -> None:
    tool, cands = G.parse_stream(
        _pretty_stream(CONFIG, OSV, MODULE_FINDING, PACKAGE_FINDING, SYMBOL_FINDING)
    )
    assert tool["version"] == "v1.1.4"
    [c] = cands
    assert c["reachability"] == "symbol_reachable"
    assert c["aliases"] == ["CVE-2026-1111"]
    assert c["fixed_version"] == "v1.2.3"
    assert c["packages"] == ["example.com/dep/pkg"]
    assert "main" in c["example_trace"][0] and "Vulnerable" in c["example_trace"][-1]


def test_order_does_not_downgrade() -> None:
    _, cands = G.parse_stream(_pretty_stream(CONFIG, OSV, SYMBOL_FINDING, MODULE_FINDING))
    assert cands[0]["reachability"] == "symbol_reachable"


def test_the_shortest_call_path_is_the_example() -> None:
    short = {"finding": {**SYMBOL_FINDING["finding"]}}
    short["finding"]["trace"] = SYMBOL_FINDING["finding"]["trace"][:1]
    _, [c] = G.parse_stream(_pretty_stream(CONFIG, SYMBOL_FINDING, short, SYMBOL_FINDING))
    assert len(c["example_trace"]) == 1


def test_symbol_reachable_ranked_first() -> None:
    _, cands = G.parse_stream(_pretty_stream(CONFIG, OSV2, MODULE2, OSV, SYMBOL_FINDING))
    assert [c["reachability"] for c in cands] == [
        "symbol_reachable",
        "module_required_not_observed",
    ]


def test_no_config_means_tool_failure_signal() -> None:
    tool, cands = G.parse_stream(_pretty_stream(OSV, MODULE_FINDING, {"finding": {}}, [1]))
    assert tool == {} and len(cands) == 1


def test_trace_symbols_receiver_and_position() -> None:
    trace = [
        {
            "package": "p",
            "function": "F",
            "receiver": "*T",
            "position": {"filename": "a/b.go", "line": 7},
        }
    ]
    assert G.trace_symbols(trace) == ["p.*T.F (a/b.go:7)"]


def test_trace_frames_without_function_skipped() -> None:
    assert G.trace_symbols([{"module": "m"}, {"package": "p", "function": "F"}]) == ["p.F"]
    assert G.trace_symbols([{"function": "F"}]) == ["F"]


def test_run_govulncheck_runs_under_the_go_scan_profile(repo: Path) -> None:
    fake = FakeSafeExec(_pretty_stream(CONFIG))
    rc, _out, _err, tool, cands = G.run_govulncheck(
        repo, 30, "govulncheck", safe_exec=safe_exec(fake)
    )
    [(cmd, profile, kw)] = fake.calls
    assert cmd == ["govulncheck", "-json", "./..."] and profile == "go-scan"
    assert kw == {"timeout": 30, "cwd": repo, "extra_env": None}
    assert (rc, tool["version"], cands) == (0, "v1.1.4", [])


def test_scan_forwards_safe_exec_and_returns_typed_findings(repo: Path) -> None:
    fake = FakeSafeExec(_pretty_stream(CONFIG, OSV, SYMBOL_FINDING, OSV2, MODULE2, PACKAGE_FINDING))
    result = G.scan(repo, safe_exec=safe_exec(fake), clock=FixedClock(NOW), timeout=45)
    assert fake.calls[0][2]["timeout"] == 45
    assert result.metadata.tool == "govulncheck" and result.metadata.scanner_version == "v1.1.4"
    assert result.scanned_at == "2026-10-24T12:00:00Z"
    symbol, module = result.findings
    assert (symbol.id, symbol.severity, symbol.category) == (
        "GO-2026-0001",
        "high",
        "symbol_reachable",
    )
    assert symbol.title == "Example vulnerability in example.com/dep"
    assert [loc.description for loc in symbol.locations] == ["call path"] * 2 + ["imported package"]
    assert symbol.description == (
        "module=example.com/dep version=v1.2.0 reachability=symbol_reachable"
    )
    assert (module.id, module.severity) == ("GO-2026-0002", "low")
    summary = json.loads(result.payload)["summary"]
    assert summary == {"total": 2, "by_severity": {"high": 1, "low": 1}}


def test_a_module_only_finding_points_at_the_go_mod_requiring_it(tmp_path: Path) -> None:
    for sub, text in {
        "a": "module a\n",
        "b": "module b\nrequire example.com/other v0.1.0\n",
    }.items():
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "go.mod").write_text(text)
    fake = FakeSafeExec(_pretty_stream(CONFIG, OSV2, MODULE2))
    [finding] = G.scan(tmp_path, safe_exec=safe_exec(fake), clock=FixedClock(NOW)).findings
    [location] = finding.locations
    assert location.path == "b/go.mod"
    assert location.description == (
        "requires example.com/other@v0.1.0 (module_required_not_observed)"
    )


def test_a_module_only_finding_with_no_named_module_falls_to_the_first_go_mod(repo: Path) -> None:
    unnamed = {"finding": {"osv": "GO-2026-0003", "trace": []}}
    fake = FakeSafeExec(_pretty_stream(CONFIG, unnamed))
    [finding] = G.scan(repo, safe_exec=safe_exec(fake), clock=FixedClock(NOW)).findings
    assert finding.title == "GO-2026-0003"
    assert finding.locations[0].path == "go.mod"
    assert finding.locations[0].description == "requires None (module_required_not_observed)"


def test_scan_refuses_a_checkout_with_no_go_mod(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"no go\.mod under"):
        G.scan(tmp_path, safe_exec=safe_exec(FakeSafeExec()), clock=FixedClock(NOW))


def test_no_scan_output_is_a_tool_failure(repo: Path) -> None:
    fake = FakeSafeExec("", rc=126, err="[safe_exec blocked: not in profile]")
    with pytest.raises(RuntimeError, match=r"no scan output \(exit 126\): \[safe_exec blocked"):
        G.scan(repo, safe_exec=safe_exec(fake), clock=FixedClock(NOW))
