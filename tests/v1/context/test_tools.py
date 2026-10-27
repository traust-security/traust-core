from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.context import context as context_module
from traust_core.v1.context.tools import load_safe_exec, load_toolchain, scanner_tools
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.base import Readiness, argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import DatabaseStatus, ToolProvider, grype, osv, osv_sbom
from traust_core.v1.providers.tools.adapter import AdapterTool
from traust_core.v1.providers.tools.safe_exec import RECURSION_ENV
from traust_core.v1.providers.tools.toolchain import GRYPE_DB_MAX_AGE, Toolchain, ToolPin
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind

FIXTURES = Path(__file__).parents[2] / "fixtures" / "tools"
EXTERNAL_TOOLS = FIXTURES / "external-tools.yaml"
SAFE_EXEC = FIXTURES / "safe-exec-profiles.yaml"
NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)
SCANNERS = {"gitleaks": ("gitleaks",), "grype": ("grype",), "osv": ()}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURES, config)
    return config


def _ctx(tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch, **scans: Any) -> Context:
    ctx = Context(Config(home=tmp_path / "store"), clock=FixedClock(NOW))

    def scanners(c: Context) -> tuple[AdapterTool[Any], ...]:
        return tuple(
            AdapterTool(
                name,
                binaries,
                scans.get(name, lambda w: {"scanned": w}),
                c.clock,
                lambda: c.toolchain,
                precondition=lambda: Readiness(ready=True),
            )
            for name, binaries in SCANNERS.items()
        )

    monkeypatch.setattr(context_module, "scanner_tools", scanners)
    ctx.register_toolchain(home / "external-tools.yaml", home / "safe-exec-profiles.yaml")
    return ctx


def test_core_registers_its_scanners_by_name(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    assert [t.name for t in scanner_tools(ctx)] == ["grype", "osv", "osv_sbom"]
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    assert ctx.tools.names() == ["grype", "osv", "osv_sbom"]


def test_the_toolchain_reads_every_pin_and_allows_only_pinned_binaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "grype"))
    toolchain = load_toolchain(EXTERNAL_TOOLS)
    assert list(toolchain.pins)[:4] == ["opengrep", "gitleaks", "syft", "grype"]
    assert toolchain.pins["govulncheck"] == ToolPin(
        name="govulncheck",
        expected="1.6.0",
        version_cmd=("govulncheck", "-version"),
        version_regex=r"govulncheck@v(\d+)\.(\d+)\.(\d+)",
        consumers=("secure-code-audit", "secure-rpm-audit", "triage"),
    )
    assert toolchain.db_cache_dirs() == {"grype": tmp_path / "grype"}
    toolchain.version("joern")
    for unpinned in ("curl", "bash"):
        with pytest.raises(ValidationError, match=r"never allowed|not allowed"):
            toolchain.version(unpinned)


def test_grypes_cache_defaults_under_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    cache = load_toolchain(EXTERNAL_TOOLS).db_cache_dirs()["grype"]
    assert cache == Path.home() / ".cache" / "grype" / "db"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (None, "No such file"),
        ("tools: [unclosed\n", "while parsing"),
        ("tools: []\n", "external-tools"),
        ("tools:\n  - {name: x, expected: '1', version_regex: 5}\n", "version_regex"),
    ],
)
def test_a_bad_pins_file_is_a_config_error_naming_it(
    tmp_path: Path, text: str | None, message: str
) -> None:
    path = tmp_path / "external-tools.yaml"
    if text is not None:
        path.write_text(text)
    with pytest.raises(ConfigError, match=str(path)) as raised:
        load_toolchain(path)
    assert message in str(raised.value)


def test_safe_exec_reads_the_profiles_and_its_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RECURSION_ENV, "3")
    safe_exec = load_safe_exec(SAFE_EXEC)
    assert "govulncheck" in safe_exec.profile("go-scan").allow
    assert (
        "recursion"
        in safe_exec.validate_argv(["echo"], safe_exec.profile("validation-step")).reason
    )
    monkeypatch.delenv(RECURSION_ENV)
    assert (
        load_safe_exec(SAFE_EXEC).validate_argv(["echo"], safe_exec.profile("validation-step")).ok
    )


def test_a_bad_profiles_file_is_a_config_error_naming_it(tmp_path: Path) -> None:
    path = tmp_path / "safe-exec-profiles.yaml"
    path.write_text("version: 1\nprofiles: {evil: {allow: [sudo]}}\n")
    with pytest.raises(ConfigError, match="hard denies are never grantable"):
        load_safe_exec(path)
    path.write_text("profiles: {}\n")
    with pytest.raises(ConfigError, match=str(path)):
        load_safe_exec(path)


def test_the_context_serves_the_registered_toolchain_and_profiles(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    assert isinstance(ctx.toolchain, Toolchain) and ctx.toolchain is ctx.toolchain
    assert "govulncheck" in ctx.safe_exec.profile("go-scan").allow


def test_without_a_registered_toolchain_its_doors_say_how_to_get_one(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    with pytest.raises(ConfigError, match=r"Context\.register_toolchain"):
        ctx.toolchain  # noqa: B018
    with pytest.raises(ConfigError, match=r"Context\.register_toolchain"):
        ctx.safe_exec  # noqa: B018


def test_a_second_registration_is_refused(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    with pytest.raises(ConfigError, match="registered twice"):
        ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)


def test_the_config_is_read_on_first_use_so_a_home_without_it_runs_everything_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = tmp_path / "bare"
    bare.mkdir()
    ctx = _ctx(tmp_path, bare, monkeypatch)
    assert ctx.tools.names() == sorted(SCANNERS)
    ctx.services()
    with pytest.raises(ConfigError, match=r"external-tools\.yaml"):
        ctx.tools.get("grype")
    with pytest.raises(ConfigError, match=r"safe-exec-profiles\.yaml"):
        ctx.safe_exec  # noqa: B018


def test_every_scanner_is_registered_reporting_itself_with_its_pins_floor(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path, home, monkeypatch)
    assert ctx.tool_floors == {}
    assert all(isinstance(ctx.tools.get(n), ToolProvider) for n in ctx.tools.names())
    assert ctx.tool_inspector is None
    assert ctx.tool_floors == {"gitleaks": "8.30.1", "grype": "0.115.0"}


def test_run_tools_calls_the_scan_through_the_services(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Path] = []
    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    ctx = _ctx(tmp_path, home, monkeypatch, gitleaks=lambda w: seen.append(w) or "found")
    run = ctx.services().assessment.run_tools(tmp_path, [ToolName("gitleaks")])
    assert run.data("gitleaks", str) == "found" and seen == [tmp_path]
    assert run.results["gitleaks"].acquisition.acquired_at == NOW


def test_unready_tools_stop_run_tools_before_any_scan(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path, home, monkeypatch, grype=lambda _: pytest.fail("scanned"))
    monkeypatch.setattr(
        AdapterTool, "check", lambda self: Readiness(ready=False, detail="grype not on PATH")
    )
    with pytest.raises(ConfigError, match="grype: grype not on PATH"):
        ctx.services().assessment.run_tools(tmp_path, [ToolName("grype")])


class Probes:
    """The toolchain's runner: each binary's version, grype's status, and the updates run."""

    def __init__(self, versions: dict[str, str]) -> None:
        self.versions = versions
        self.updated: list[str] = []

    def run(self, argv: Any, **_: Any) -> ProcessResult:
        args = tuple(argv)
        if args == ("grype", "db", "update"):
            self.updated.append("grype")
        out = (
            "Schema: v6.0.2\nBuilt: 2026-10-23T01:31:46Z\n"
            if args[1:] == ("db", "status")
            else self.versions.get(args[0], "")
        )
        return ProcessResult(args, 0, out.encode(), b"", 0.1)


def _probed(monkeypatch: pytest.MonkeyPatch, probes: Probes) -> None:
    def load(path: Path) -> Toolchain:
        pins = load_toolchain(path).pins
        return Toolchain(pins, probes, grype_db_dir=path.parent / "grype")  # type: ignore[arg-type]

    monkeypatch.setattr(context_module, "load_toolchain", load)


def test_the_catalog_stamps_versions_and_grypes_database(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path, home, monkeypatch)
    _probed(monkeypatch, Probes({"grype": "grype 0.115.0", "gitleaks": "8.30.1"}))
    catalog = ctx.services().catalog
    stamp = {s.tool: s for s in catalog.stamp().tools}
    assert stamp["grype"].render() == "grype 0.115.0 (db built 2026-10-23, schema v6.0.2)"
    assert stamp["gitleaks"].render() == "gitleaks 8.30.1"
    assert stamp["osv"].version is None
    [db] = catalog.databases()
    assert db == DatabaseStatus(
        tool="grype",
        exists=True,
        built_at=datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC),
        schema_version="v6.0.2",
        max_age=GRYPE_DB_MAX_AGE,
        path=str(home / "grype"),
    )
    assert not db.stale(NOW)


def test_readiness_holds_a_tool_below_its_floor(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    ctx = _ctx(tmp_path, home, monkeypatch)
    _probed(monkeypatch, Probes({"gitleaks": "8.0.0"}))
    catalog = ctx.services().catalog
    [binding] = catalog.readiness(Capability(kind=CapabilityKind.TOOL, name="gitleaks"))
    assert binding.readiness == Readiness(
        ready=False, detail="version 8.0.0 is below the floor 8.30.1"
    )


def test_fetch_databases_updates_only_grype(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _ctx(tmp_path, home, monkeypatch)
    probes = Probes({})
    _probed(monkeypatch, probes)
    [db] = ctx.services().catalog.fetch_databases()
    assert probes.updated == ["grype"] and db.tool == "grype"


FEEDS = (
    "version: 1\nsources:\n  osv:\n    tier: live\n    url_template: https://osv.test/v1/{ident}\n"
)


def _core(tmp_path: Path, *, feeds: bool = True) -> Context:
    ctx = Context(Config(home=tmp_path / "store"), clock=FixedClock(NOW))
    if feeds:
        registry = tmp_path / "feeds.yaml"
        registry.write_text(FEEDS)
        ctx.register_feeds(registry)
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    return ctx


def test_cores_scanners_report_themselves_and_only_grype_has_a_floor(tmp_path: Path) -> None:
    ctx = _core(tmp_path)
    assert all(isinstance(ctx.tools.get(n), ToolProvider) for n in ctx.tools.names())
    assert ctx.tool_floors == {"grype": "0.115.0"}
    assert ctx.tools.get("osv").version() is None
    assert ctx.tools.get("osv_sbom").database() is None


def test_osv_scans_the_checkout_through_the_registrys_osv_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Path, Any, Any]] = []
    monkeypatch.setattr(osv, "scan", lambda w, a, c: seen.append((w, a, c)) or "found")
    ctx = _core(tmp_path)
    result = ctx.tools.get("osv").acquire(ToolRequest(workspace=tmp_path))
    assert result.data == "found" and result.acquisition.provider == "osv"
    [(where, advisories, clock)] = seen
    assert where == tmp_path and advisories is ctx.advisories and clock is ctx.clock
    assert ctx.tools.get("osv").check() == Readiness(ready=True)


@pytest.mark.parametrize("tool", ["osv", "osv_sbom"])
def test_osv_is_not_ready_without_a_live_osv_source(tmp_path: Path, tool: str) -> None:
    ctx = _core(tmp_path, feeds=False)
    readiness = ctx.tools.get(tool).check()
    assert not readiness.ready
    assert readiness.detail == f"{tool}: no OSV lookup: the feeds registry has no live osv source"


def test_osv_sbom_runs_over_the_sbom_and_a_failed_lookup_is_a_service_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sbom = tmp_path / "image.syft.json"
    sbom.write_text("{}", encoding="utf-8")
    doc = {"provenance": {"status": "complete"}, "candidates": []}
    seen: list[tuple[Path, Any]] = []
    monkeypatch.setattr(osv_sbom, "scan_sbom", lambda p, a, c: seen.append((p, a)) or doc)
    ctx = _core(tmp_path)
    tool = ctx.tools.get("osv_sbom")
    result = tool.acquire(ToolRequest(sbom=sbom))
    assert result.data == doc and seen == [(sbom, ctx.advisories)]
    assert result.acquisition.version is None
    failed = {"status": "failed", "base_url": "https://osv.invalid", "failure": {"detail": "503"}}
    monkeypatch.setattr(osv_sbom, "scan_sbom", lambda p, a, c: {"provenance": failed})
    with pytest.raises(ServiceError, match=r"OSV API unavailable at https://osv.invalid: 503"):
        tool.acquire(ToolRequest(sbom=sbom))


def test_a_malformed_sbom_is_a_validation_error(tmp_path: Path) -> None:
    sbom = tmp_path / "image.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")
    with pytest.raises(ValidationError, match="not a syft JSON SBOM"):
        _core(tmp_path).tools.get("osv_sbom").acquire(ToolRequest(sbom=sbom))


@pytest.mark.parametrize(
    ("tool", "request_for", "message"),
    [
        ("grype", lambda p: {"sbom": p / "x.json"}, "grype runs over a checkout, not a sbom"),
        ("osv_sbom", lambda p: {"workspace": p}, "osv_sbom runs over a sbom, not a checkout"),
        ("osv_sbom", lambda p: {"sbom": p / "absent.json"}, "SBOM is not a file"),
        ("osv", lambda p: {"workspace": p / "absent"}, "workspace is not a directory"),
    ],
)
def test_a_request_for_another_or_a_missing_target_never_reaches_the_scanner(
    tmp_path: Path, tool: str, request_for: Any, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _core(tmp_path).tools.get(tool).acquire(ToolRequest(**request_for(tmp_path)))


def test_grype_scans_with_its_own_runner_and_the_toolchains_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def scan(target: Path, runner: Any, clock: Any, **kw: Any) -> str:
        seen.append({"target": target, "runner": runner, **kw})
        return "matched"

    monkeypatch.setattr(grype, "scan", scan)
    _probed(monkeypatch, Probes({"grype": "Application: grype\nVersion: 0.115.0"}))
    ctx = _core(tmp_path)
    result = ctx.tools.get("grype").acquire(ToolRequest(workspace=tmp_path))
    [call] = seen
    assert call["target"] == tmp_path and call["scanner_version"] == "0.115.0"
    assert call["runner"].allows("grype") and not call["runner"].allows("syft")
    assert result.acquisition.argv_sha256 == argv_digest(grype.command(str(tmp_path)))
