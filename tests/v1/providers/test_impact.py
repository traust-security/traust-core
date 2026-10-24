from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.candidate_formats import govulncheck_records
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    ImpactQuery,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.impact import (
    GovulncheckAnalyzer,
    SourceScanAnalyzer,
    govulncheck_reach,
    source_files,
)
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import ToolRequest

FIXTURES = Path(__file__).parents[2] / "fixtures" / "dependencies"
SAMPLE = (FIXTURES / "govulncheck-sample.jsonl").read_bytes()
AT = datetime(2026, 10, 23, tzinfo=UTC)


def query(
    name: str = "google.golang.org/grpc",
    ecosystem: Ecosystem = Ecosystem.GO,
    identifier: str = "GHSA-m425-mq94-257g",
    aliases: tuple[str, ...] = ("GO-2023-2153",),
    symbols: tuple[str, ...] = (),
) -> ImpactQuery:
    return ImpactQuery(
        advisory=AdvisoryRecord(
            identifier=AdvisoryIdentifier(identifier),
            aliases=tuple(AdvisoryIdentifier(a) for a in aliases),
            source="s",
        ),
        package=AffectedPackage(ecosystem=ecosystem, name=name),
        symbols=symbols,
    )


class Runner:
    def __init__(self, stdout: bytes, returncode: int = 0, stderr: bytes = b"") -> None:
        self.result = (stdout, returncode, stderr)
        self.argv: list[str] = []

    def run(self, argv: list[str], *, check: bool = True) -> ProcessResult:
        self.argv = argv
        out, code, err = self.result
        return ProcessResult(tuple(argv), code, out, err, 0.1)


def govulncheck(runner: Runner) -> GovulncheckAnalyzer:
    return GovulncheckAnalyzer(runner, FixedClock(AT))  # type: ignore[arg-type]


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def test_a_real_run_finds_the_advisorys_symbol_called_by_alias(tmp_path: Path) -> None:
    runner = Runner(SAMPLE)
    found = govulncheck(runner).evidence(query(), ToolRequest(workspace=tmp_path))
    assert runner.argv == ["govulncheck", "-json", "-C", str(tmp_path), "./..."]
    assert found.data.govulncheck == "symbol_reachable"
    assert found.data.govulncheck_trace is not None
    assert found.data.govulncheck_trace[0] == "example.test/sample.main"
    assert found.data.needs_manual_trace is None
    assert (found.acquisition.provider, found.acquisition.acquired_at) == ("govulncheck", AT)


def test_reach_is_the_strongest_finding_for_this_advisory_only() -> None:
    records = list(govulncheck_records(SAMPLE.decode()))
    by_module = query(identifier="CVE-2099-0001", aliases=())
    assert govulncheck_reach(records, by_module)[0] == "symbol_reachable"
    other = query(name="example.com/unused", identifier="CVE-2099-0001", aliases=())
    assert govulncheck_reach(records, other) == ("module_required_not_observed", ())
    imported_only = [
        r for r in records if "finding" not in r or not r["finding"]["trace"][0].get("function")
    ]
    assert govulncheck_reach(imported_only, query())[0] == "package_imported_not_observed"


def test_unsafe_reflect_or_cgo_asks_for_a_manual_trace(tmp_path: Path) -> None:
    write(tmp_path, {"pkg/a.go": 'import "unsafe"\nvar p = unsafe.Pointer(nil)\n'})
    write(tmp_path, {"vendor/x/b.go": "reflect.ValueOf(x)"})
    found = govulncheck(Runner(b"")).evidence(query(), ToolRequest(workspace=tmp_path)).data
    assert (found.govulncheck, found.needs_manual_trace) == ("module_required_not_observed", True)
    assert found.notes is not None and "manual trace" in found.notes


def test_vendored_unsafe_doesnt_count(tmp_path: Path) -> None:
    write(tmp_path, {"vendor/x/b.go": "reflect.ValueOf(x)", "main.go": "package main"})
    found = govulncheck(Runner(b"")).evidence(query(), ToolRequest(workspace=tmp_path)).data
    assert found.needs_manual_trace is None


def test_a_failed_run_raises_and_bad_output_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ServiceError, match="exited 1: no go"):
        govulncheck(Runner(b"", 1, b"no go.mod")).evidence(query(), ToolRequest(workspace=tmp_path))
    with pytest.raises(ValidationError):
        govulncheck(Runner(b"{broken")).evidence(query(), ToolRequest(workspace=tmp_path))


def test_govulncheck_is_ready_only_when_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert govulncheck(Runner(b"")).check().ready is False
    monkeypatch.setattr("shutil.which", lambda _: "/bin/govulncheck")
    assert govulncheck(Runner(b"")).check().ready is True


@pytest.mark.parametrize(
    ("ecosystem", "name", "files", "imports"),
    [
        (
            Ecosystem.PYPI,
            "django-rest",
            {"app/v.py": "from django_rest import x\n"},
            "imports_found",
        ),
        (Ecosystem.PYPI, "django", {"app/v.py": "import flask\n"}, "imports_not_found"),
        (Ecosystem.NPM, "lodash", {"web/a.ts": "import _ from 'lodash'\n"}, "imports_found"),
        (Ecosystem.NPM, "lodash", {"web/a.js": "const _ = require('lodash')\n"}, "imports_found"),
        (
            Ecosystem.NPM,
            "lodash",
            {"node_modules/x/a.js": "require('lodash')"},
            "imports_not_found",
        ),
        (
            Ecosystem.MAVEN,
            "org.apache.logging.log4j:log4j-core",
            {"src/A.java": "import org.apache.logging.log4j.Logger;\n"},
            "imports_found",
        ),
        (
            Ecosystem.CARGO,
            "serde-json",
            {"src/lib.rs": "use serde_json::Value;\n"},
            "imports_found",
        ),
        (Ecosystem.RUBY, "rack", {"lib/a.rb": "require 'rack'\n"}, "imports_found"),
        (Ecosystem.RPM, "openssl", {"src/tls.c": "#include <openssl/ssl.h>\n"}, "imports_found"),
        (Ecosystem.DEB, "zlib", {"src/z.c": '#include "zlib.h"\n'}, "imports_found"),
        (Ecosystem.APK, "zlib", {"src/z.py": "#include <zlib.h>\n"}, "imports_not_found"),
    ],
)
def test_source_scan_looks_for_imports_where_the_ecosystem_writes_them(
    tmp_path: Path, ecosystem: Ecosystem, name: str, files: dict[str, str], imports: str
) -> None:
    write(tmp_path, files)
    found = SourceScanAnalyzer(FixedClock(AT)).evidence(
        query(name=name, ecosystem=ecosystem), ToolRequest(workspace=tmp_path)
    )
    assert found.data.source_import_scan == imports
    assert found.data.symbol_usage_scan is None


def test_symbol_usage_matches_the_bare_callable_name(tmp_path: Path) -> None:
    write(tmp_path, {"web/a.js": "const t = _.template (input)\n"})
    scan = SourceScanAnalyzer(FixedClock(AT))
    used = query(name="lodash", ecosystem=Ecosystem.NPM, symbols=("lodash.template", ""))
    assert scan.evidence(used, ToolRequest(workspace=tmp_path)).data.symbol_usage_scan == (
        "symbols_used"
    )
    unused = query(name="lodash", ecosystem=Ecosystem.NPM, symbols=("Foo#merge",))
    assert scan.evidence(unused, ToolRequest(workspace=tmp_path)).data.symbol_usage_scan == (
        "symbols_not_found"
    )


def test_nuget_has_no_import_scan_only_symbol_usage(tmp_path: Path) -> None:
    write(tmp_path, {"src/A.cs": "JsonConvert.DeserializeObject(x);\n"})
    found = SourceScanAnalyzer(FixedClock(AT)).evidence(
        query(name="Newtonsoft.Json", ecosystem=Ecosystem.NUGET, symbols=("DeserializeObject",)),
        ToolRequest(workspace=tmp_path),
    )
    assert (found.data.source_import_scan, found.data.symbol_usage_scan) == (None, "symbols_used")


def test_source_files_skip_vendored_trees(tmp_path: Path) -> None:
    write(tmp_path, {"a.go": "", "vendor/b.go": "", "x/.git/c.go": "", "x/node_modules/d.go": ""})
    assert [p.name for p in source_files(tmp_path, (".go",))] == ["a.go"]
