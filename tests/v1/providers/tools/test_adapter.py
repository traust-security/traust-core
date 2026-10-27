from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import DocumentError, ServiceError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.common import SymbolQuery, ToolRequest, ToolTarget
from traust_core.v1.providers.base import Readiness, argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase, ToolProvider
from traust_core.v1.providers.tools import adapter as adapter_module
from traust_core.v1.providers.tools.adapter import (
    AdapterTool,
    adapter_result,
    format_lines,
    resolves,
)
from traust_core.v1.providers.tools.toolchain import GRYPE_DB_MAX_AGE, ToolPin

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
BUILT = datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC)


def result(tool: str, target: Path, version: str = "1.0.0") -> AdapterResultArtifact:
    finding = {
        "id": f"{tool}/x",
        "title": "x",
        "severity": "high",
        "cwes": [],
        "locations": [{"path": "main.go"}],
        "description": "",
        "remediation": "",
    }
    return AdapterResultArtifact.from_document(
        {
            "target": str(target),
            "scanned_at": "2026-10-24T12:00:00Z",
            "metadata": {"tool": tool, "scanner_version": version},
            "findings": [finding],
        }
    )


class FakeToolchain:
    def __init__(self, pins: dict[str, ToolPin] | None = None) -> None:
        self.pins = pins or {}
        self.asked: list[tuple[str, Any, Any]] = []
        self.populated: list[str] = []
        self.populate_result = (True, "ok")

    def version(self, binary: str, version_cmd: Any = None, version_regex: Any = None) -> str:
        self.asked.append((binary, version_cmd, version_regex))
        return "4.0.600"

    def database(self, tool: str) -> DatabaseStatus | None:
        return DatabaseStatus(tool=tool, exists=True, built_at=BUILT, max_age=GRYPE_DB_MAX_AGE)

    def populate(self, tool: str) -> tuple[bool, str]:
        self.populated.append(tool)
        return self.populate_result


def tool(
    name: str = "t",
    binaries: tuple[str, ...] = (),
    scan: Any = None,
    toolchain: FakeToolchain | None = None,
    **kw: Any,
) -> AdapterTool[Any]:
    chain = toolchain or FakeToolchain()
    return AdapterTool(
        name,
        binaries,
        scan or (lambda t: result(name, t)),
        FixedClock(NOW),
        lambda: chain,  # type: ignore[arg-type,return-value]
        **kw,
    )


def test_an_adapter_tool_is_a_tool_provider() -> None:
    assert isinstance(tool(), ToolProvider)


def test_acquire_runs_the_scan_and_records_its_provenance(tmp_path: Path) -> None:
    seen: list[Path] = []

    def scan(target: Path) -> AdapterResultArtifact:
        seen.append(target)
        return result("t", target, "8.30.1")

    found = tool(scan=scan).acquire(ToolRequest(workspace=tmp_path))
    assert seen == [tmp_path]
    assert found.data.findings[0].id == "t/x"
    acquisition = found.acquisition
    assert (acquisition.provider, acquisition.acquired_at) == ("t", NOW)
    assert acquisition.version == "8.30.1"
    assert acquisition.source == str(tmp_path.resolve())
    assert acquisition.argv_sha256 is None and acquisition.db_built_at is None


def test_a_result_that_isnt_an_adapter_result_has_no_scanner_version(tmp_path: Path) -> None:
    found = tool(scan=lambda _: {"candidates": []}).acquire(ToolRequest(workspace=tmp_path))
    assert found.acquisition.version is None
    empty = tool(scan=lambda t: result("t", t, "")).acquire(ToolRequest(workspace=tmp_path))
    assert empty.acquisition.version is None


def test_grype_records_the_argv_it_ran_and_its_database_build_time(tmp_path: Path) -> None:
    grype = tool("grype", ("grype",), argv=lambda w: ["grype", str(w), "-o", "json"])
    acquisition = grype.acquire(ToolRequest(workspace=tmp_path)).acquisition
    assert acquisition.argv_sha256 == argv_digest(["grype", str(tmp_path), "-o", "json"])
    assert acquisition.db_built_at == BUILT


@pytest.mark.parametrize(
    ("raised", "kind"),
    [
        (ValueError("no go.mod"), ValidationError),
        (RuntimeError("tool failed"), ServiceError),
        (FileNotFoundError("absent"), ServiceError),
        (TimeoutError("timed out"), ServiceError),
    ],
)
def test_an_adapter_failure_is_a_typed_error_naming_the_tool(
    tmp_path: Path, raised: Exception, kind: type[Exception]
) -> None:
    def scan(_: Path) -> AdapterResultArtifact:
        raise raised

    with pytest.raises(kind, match=f"t over {tmp_path}: {raised}"):
        tool(scan=scan).acquire(ToolRequest(workspace=tmp_path))


def test_a_typed_error_from_the_adapter_passes_through(tmp_path: Path) -> None:
    def scan(_: Path) -> AdapterResultArtifact:
        raise ServiceError("OSV API unavailable")

    with pytest.raises(ServiceError, match=r"^OSV API unavailable$"):
        tool(scan=scan).acquire(ToolRequest(workspace=tmp_path))


def test_a_missing_workspace_never_reaches_the_adapter(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="not a directory"):
        tool(scan=lambda _: pytest.fail("scanned")).acquire(
            ToolRequest(workspace=tmp_path / "absent")
        )


def test_symbols_run_over_the_query_and_name_its_checkout(tmp_path: Path) -> None:
    seen: list[SymbolQuery] = []
    joern = tool(
        "joern",
        scan=lambda q: seen.append(q) or result("joern", q.workspace),
        target=ToolTarget.SYMBOLS,
    )
    query = SymbolQuery(workspace=tmp_path, names=("com.foo.Bar#parse",))
    found = joern.acquire(ToolRequest(symbols=query))
    assert seen == [query] and found.acquisition.source == str(tmp_path.resolve())


def test_an_sbom_runs_over_the_file(tmp_path: Path) -> None:
    sbom = tmp_path / "image.syft.json"
    sbom.write_text("{}", encoding="utf-8")
    osv_sbom = tool("osv_sbom", scan=lambda p: {"sbom": p}, target=ToolTarget.SBOM)
    found = osv_sbom.acquire(ToolRequest(sbom=sbom))
    assert found.data == {"sbom": sbom} and found.acquisition.version is None


@pytest.mark.parametrize(
    ("target", "request_for", "message"),
    [
        (ToolTarget.CHECKOUT, lambda p: {"sbom": p / "x.json"}, "over a checkout, not a sbom"),
        (ToolTarget.SBOM, lambda p: {"workspace": p}, "t runs over a sbom, not a checkout"),
        (ToolTarget.SYMBOLS, lambda p: {"workspace": p}, "t runs over a symbols, not a checkout"),
        (ToolTarget.SBOM, lambda p: {"sbom": p / "absent.json"}, "SBOM is not a file"),
        (
            ToolTarget.SYMBOLS,
            lambda p: {"symbols": SymbolQuery(workspace=p / "absent", names=("f",))},
            "workspace is not a directory",
        ),
    ],
)
def test_a_request_for_another_or_a_missing_target_never_reaches_the_adapter(
    tmp_path: Path, target: ToolTarget, request_for: Any, message: str
) -> None:
    provider = tool(scan=lambda _: pytest.fail("scanned"), target=target)
    with pytest.raises(ValidationError, match=message):
        provider.acquire(ToolRequest(**request_for(tmp_path)))


def test_readiness_names_missing_binaries_then_an_unresolved_precondition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        adapter_module,
        "on_path",
        lambda *b, missing="": Readiness(ready=False, detail=f"{b[0]}{missing}"),
    )
    assert tool(binaries=("nope",)).check().detail == "nope not on PATH"
    monkeypatch.setattr(adapter_module, "on_path", lambda *b, missing="": Readiness(ready=True))

    def unresolved() -> object:
        raise ValueError("pack missing")

    gated = tool(binaries=("x",), precondition=lambda: resolves("t", unresolved))
    assert gated.check() == Readiness(ready=False, detail="t: pack missing")
    assert tool(binaries=("x",), precondition=lambda: resolves("t", object)).check().ready
    assert tool().check().ready


def test_version_is_asked_through_the_binarys_pin() -> None:
    regex = r"Version:\s*(\d+)\.(\d+)\.(\d+)"
    chain = FakeToolchain({"joern": ToolPin(name="joern", expected="4.0.0", version_regex=regex)})
    joern = tool("joern", ("joern", "joern-parse"), toolchain=chain)
    assert joern.version() == "4.0.600" and chain.asked == [("joern", None, regex)]
    assert joern.database() is None


def test_an_unpinned_binary_is_asked_its_default_version_and_an_api_has_none() -> None:
    chain = FakeToolchain()
    assert tool("yara", ("yara", "git"), toolchain=chain).version() == "4.0.600"
    assert chain.asked == [("yara", None, None)]
    assert tool("osv", (), toolchain=chain).version() is None


def test_grypes_database_is_reported_under_the_tools_name() -> None:
    db = tool("grype-image", ("grype",)).database()
    assert db is not None and db.tool == "grype-image" and db.max_age == timedelta(days=5)


def test_update_database_refreshes_only_a_tool_that_keeps_one() -> None:
    chain = FakeToolchain()
    assert tool("grype", ("grype",), toolchain=chain).update_database().tool == "grype"
    assert chain.populated == ["grype"]
    with pytest.raises(NoDatabase, match="gitleaks keeps no vulnerability database"):
        tool("gitleaks", ("gitleaks",), toolchain=chain).update_database()


def test_a_failed_or_unreadable_database_update_is_a_service_error() -> None:
    chain = FakeToolchain()
    chain.populate_result = (False, "grype: db update failed")
    with pytest.raises(ServiceError, match="db update failed"):
        tool("grype", ("grype",), toolchain=chain).update_database()
    chain.populate_result = (True, "ok")
    chain.database = lambda tool: None  # type: ignore[method-assign]
    with pytest.raises(ServiceError, match="status is unreadable"):
        tool("grype", ("grype",), toolchain=chain).update_database()


def test_the_wrapper_starts_no_process_of_its_own() -> None:
    source = Path(adapter_module.__file__).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "urlopen", "ProcessRunner(", "socket"):
        assert forbidden not in source


def scanner_finding() -> dict[str, Any]:
    return {
        "id": "SAMPLE-abcdef0-001",
        "title": "Synthetic scanner finding",
        "severity": "high",
        "cwes": ["CWE-79"],
        "locations": [{"path": "src/example.py", "lines": "12"}],
        "description": "A synthetic scanner observation retaining its source claim.",
        "remediation": "Validate untrusted input at the actual processing boundary.",
    }


def test_complete_adapter_evidence_survives_artifact_admission() -> None:
    source = {
        **scanner_finding(),
        "kind": "vulnerability",
        "validation_status": "confirmed",
        "source_findings": ["opaque:original-scanner-result"],
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v2",
        "remediation_effort": None,
        "blocked_external": False,
        "dependency": {
            "advisory": "CVE-2026-0001",
            "module": "example-module",
            "ecosystem": "pypi",
            "evidence_level": "manifest",
            "classification": "likely_affected",
        },
    }
    document = adapter_result("synthetic-repository", "fixture-scanner", [source], scanned_at=NOW)
    (recorded,) = document.findings
    assert recorded.fingerprint == source["fingerprint"] and recorded.fingerprint_algo == "v2"
    assert recorded.dependency.classification == "likely_affected"
    assert recorded.source_findings == ("opaque:original-scanner-result",)
    assert recorded.remediation_effort is None and recorded.blocked_external is False
    assert document.metadata.tool == "fixture-scanner"
    assert document.summary.by_severity.high == 1


def test_an_adapter_result_fills_unreported_fields_and_counts_by_severity() -> None:
    low = {"id": "x/2", "title": "y", "severity": "low", "locations": [{"path": "a"}]}
    document = adapter_result(
        "t",
        "tool",
        [scanner_finding(), low, {**low, "id": "x/3"}],
        scanned_at=datetime(2026, 10, 24, 14, tzinfo=timezone(timedelta(hours=2))),
        scanner_version="1.2.3",
        focus_areas=["kubernetes"],
    )
    assert json.loads(document.payload) == {
        "target": "t",
        "scanned_at": "2026-10-24T12:00:00Z",
        "metadata": {"tool": "tool", "scanner_version": "1.2.3"},
        "findings": [
            scanner_finding(),
            {**low, "cwes": [], "description": "", "remediation": ""},
            {**low, "id": "x/3", "cwes": [], "description": "", "remediation": ""},
        ],
        "summary": {"total": 3, "by_severity": {"high": 1, "low": 2}},
        "focus_areas": ["kubernetes"],
    }
    empty = adapter_result("t", "tool", [], scanned_at=NOW)
    assert empty.findings == () and empty.summary.total == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "urgent"),
        ("unrecognized_provenance", "original evidence"),
        ("origin", "gitleaks"),
        ("pqc_classification", "invented"),
        ("fingerprint", "scanner:local-id"),
        ("isolation_dimensions", []),
    ],
)
def test_invalid_or_undeclared_evidence_is_refused_at_admission(field: str, value: Any) -> None:
    with pytest.raises(DocumentError):
        adapter_result("t", "tool", [{**scanner_finding(), field: value}], scanned_at=NOW)


@pytest.mark.parametrize(
    ("start", "end", "lines"),
    [(None, None, ""), (0, 3, ""), (12, None, "12"), (12, 12, "12"), (12, 14, "12-14")],
)
def test_format_lines(start: int | None, end: int | None, lines: str) -> None:
    assert format_lines(start, end) == lines


def test_adapter_result_fills_the_engines_defaults_and_counts_by_severity(tmp_path: Path) -> None:
    built = adapter_module.adapter_result(
        str(tmp_path),
        "opengrep",
        [
            {"id": "a", "title": "A", "severity": "HIGH", "locations": [{"path": "x"}]},
            {"id": "b", "title": "B", "locations": [{"path": "y"}], "cwes": ["CWE-89"]},
        ],
        scanned_at=datetime(2026, 10, 24, 14, tzinfo=timezone(timedelta(hours=2))),
        scanner_version="1.25.0",
    )
    assert json.loads(built.payload) == {
        "target": str(tmp_path),
        "scanned_at": "2026-10-24T12:00:00Z",
        "focus_areas": [],
        "metadata": {"tool": "opengrep", "scanner_version": "1.25.0"},
        "findings": [
            {
                "id": "a",
                "title": "A",
                "severity": "high",
                "cwes": [],
                "locations": [{"path": "x"}],
                "description": "",
                "remediation": "",
            },
            {
                "id": "b",
                "title": "B",
                "severity": "low",
                "cwes": ["CWE-89"],
                "locations": [{"path": "y"}],
                "description": "",
                "remediation": "",
            },
        ],
        "summary": {"total": 2, "by_severity": {"high": 1, "low": 1}},
    }


@pytest.mark.parametrize(
    "finding",
    [
        {"id": "a", "title": "A", "locations": []},
        {"id": "a", "title": "A", "locations": [{"path": "x"}], "cwes": ["CWE-89: SQLi"]},
        {"id": "a", "title": "A", "locations": [{"path": "x"}], "undeclared": 1},
    ],
)
def test_adapter_result_refuses_a_finding_the_contract_does_not_allow(
    tmp_path: Path, finding: dict[str, Any]
) -> None:
    with pytest.raises(DocumentError):
        adapter_module.adapter_result(str(tmp_path), "t", [finding], scanned_at=NOW)
