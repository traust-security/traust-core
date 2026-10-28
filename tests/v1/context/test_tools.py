from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.v1.settings_support import configure
from traust_core.v1.context import Config, Context
from traust_core.v1.context import context as context_module
from traust_core.v1.context.config import Locations
from traust_core.v1.context.tools import (
    gitleaks_config,
    load_rule_allowlist,
    load_safe_exec,
    load_toolchain,
    scanner_tools,
)
from traust_core.v1.errors import ConfigError, ServiceError, ValidationError
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.models.common import SymbolQuery, ToolRequest
from traust_core.v1.providers.base import Readiness, argv_digest
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import (
    DatabaseStatus,
    ToolProvider,
    govulncheck,
    grype,
    joern,
    opengrep,
    osv,
    osv_sbom,
)
from traust_core.v1.providers.tools import adapter as adapter_module
from traust_core.v1.providers.tools.adapter import AdapterTool, adapter_result
from traust_core.v1.providers.tools.cloud_config import CheckovProvider
from traust_core.v1.providers.tools.gitleaks import Gitleaks
from traust_core.v1.providers.tools.opengrep import RuleAllowlist, SupplementalPack
from traust_core.v1.providers.tools.safe_exec import RECURSION_ENV
from traust_core.v1.providers.tools.toolchain import GRYPE_DB_MAX_AGE, Toolchain, ToolPin
from traust_core.v1.providers.tools.yara import Yara
from traust_core.v1.services.provider_catalog import Capability, CapabilityKind

FIXTURES = Path(__file__).parents[2] / "fixtures" / "tools"
EXTERNAL_TOOLS = FIXTURES / "external-tools.yaml"
SAFE_EXEC = FIXTURES / "safe-exec-profiles.yaml"
GITLEAKS_RULES = FIXTURES / "gitleaks-rules.toml"
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


def test_core_registers_its_scanners_with_their_pins_floors(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    scanners = [
        "govulncheck",
        "joern",
        "opengrep",
        "gitleaks",
        "gitleaks-history",
        "yara",
        "grype",
        "osv",
        "osv_sbom",
    ]
    assert [t.name for t in scanner_tools(ctx)] == scanners
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    assert ctx.tools.names() == sorted(["checkov", *scanners])
    assert isinstance(ctx.tools.get("checkov"), CheckovProvider)
    assert ctx.tool_floors == {}  # Checkov's pin is in core, not external-tools.yaml
    assert all(isinstance(ctx.tools.get(n), ToolProvider) for n in ctx.tools.names())
    assert ctx.tool_floors == {
        "govulncheck": "1.6.0",
        "joern": "4.0.600",
        "opengrep": "1.25.0",
        "gitleaks": "8.30.1",
        "gitleaks-history": "8.30.1",
        "yara": "4.5.8",
        "grype": "0.115.0",
    }


def _scanning(tmp_path: Path, **locations: str) -> Context:
    ctx = Context(
        Config(home=tmp_path / "store", locations=Locations(**locations)), clock=FixedClock(NOW)
    )
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    return ctx


def _found(tool: str, target: Path) -> AdapterResultArtifact:
    finding = {"id": f"{tool}/x", "title": "x", "severity": "high", "locations": [{"path": "a"}]}
    return adapter_result(str(target), tool, [finding], scanned_at=NOW, scanner_version="8.30.1")


@pytest.mark.parametrize(
    ("tool", "scanner", "expect"),
    [
        ("gitleaks", Gitleaks, ((GITLEAKS_RULES,), {"mode": "dir"})),
        ("gitleaks-history", Gitleaks, ((GITLEAKS_RULES,), {"mode": "history"})),
        ("yara", Yara, ((), {})),
    ],
)
def test_run_tools_calls_each_scanners_own_scan_with_its_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str, scanner: type, expect: Any
) -> None:
    seen: list[tuple[Path, Any]] = []

    def scan(self: object, target: Path, *args: Any, **kw: Any) -> AdapterResultArtifact:
        seen.append((target, (args, kw)))
        return _found(tool, target)

    monkeypatch.setattr(scanner, "scan", scan)
    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    ctx = _scanning(tmp_path, gitleaks_config=str(GITLEAKS_RULES))
    run = ctx.services().assessment.run_tools(tmp_path, [ToolName(tool)])
    assert run.data(tool, AdapterResultArtifact).findings[0].id == f"{tool}/x"
    acquisition = run.results[tool].acquisition
    assert (acquisition.version, acquisition.acquired_at) == ("8.30.1", NOW)
    assert (acquisition.argv_sha256, acquisition.db_built_at) == (None, None)
    assert seen == [(tmp_path, expect)]


@pytest.mark.parametrize(
    ("locations", "detail"),
    [
        ({}, "gitleaks: gitleaks config required (locations.gitleaks_config)"),
        ({"gitleaks_config": "s3://bucket/rules.toml"}, "has no local path form"),
        ({"gitleaks_config": "/absent.toml"}, "required (locations.gitleaks_config): no file"),
    ],
)
def test_gitleaks_is_not_ready_without_the_rules_the_pack_configures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, locations: dict[str, str], detail: str
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    ctx = _scanning(tmp_path, **locations)
    for name in ("gitleaks", "gitleaks-history"):
        readiness = ctx.tools.get(name).check()
        assert not readiness.ready and detail in readiness.detail
    ready = _scanning(tmp_path / "ok", gitleaks_config=str(GITLEAKS_RULES))
    assert ready.tools.get("gitleaks").check() == Readiness(ready=True)


def test_the_gitleaks_rules_are_the_local_file_locations_names(tmp_path: Path) -> None:
    assert gitleaks_config(Locations(gitleaks_config=f"file://{GITLEAKS_RULES}")) == GITLEAKS_RULES


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
    assert ctx.tools.names() == sorted([*SCANNERS, "checkov"])
    ctx.services()
    assert ctx.tools.get("checkov").name == "checkov"
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


ALLOWLIST = """\
packs:
  argus:
    enabled: true
    source: https://example.com/argus@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    rules: [go-tls-bypass, java-tls-bypass]
    held_back:
      - {rule: go-crypto-tls-version, readmit_when: precision holds}
  fork:
    enabled: false
    source: https://example.com/fork@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    rules: [r1]
"""


def test_the_rule_pack_and_its_allowlist_are_read_on_first_use(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_rule_pack(tmp_path / "pack")
    configure(ctx, "rule-pack-allowlist", yaml.safe_load(ALLOWLIST))
    assert ctx.rule_pack == tmp_path / "pack"
    assert ctx.rule_pack_supplements == (
        SupplementalPack(
            "argus", f"https://example.com/argus@{'a' * 40}", ("go-tls-bypass", "java-tls-bypass")
        ),
    )


def test_a_rule_pack_without_an_allowlist_enables_no_supplement(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    ctx.register_rule_pack(tmp_path)
    assert ctx.rule_pack_supplements == ()


def test_without_a_rule_pack_its_doors_say_how_to_register_one(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    for door in ("rule_pack", "rule_pack_supplements"):
        with pytest.raises(ConfigError, match=r"Context\.register_rule_pack"):
            getattr(ctx, door)
    ctx.register_rule_pack(tmp_path)
    with pytest.raises(ConfigError, match="rule pack registered twice"):
        ctx.register_rule_pack(tmp_path)


def _code_ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Context:
    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    ctx = Context(Config(home=tmp_path / "store"), clock=FixedClock(NOW))
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    return ctx


def test_the_deps_scanners_report_themselves_and_only_grype_has_a_floor(tmp_path: Path) -> None:
    ctx = _core(tmp_path)
    assert all(isinstance(ctx.tools.get(n), ToolProvider) for n in ctx.tools.names())
    assert ctx.tool_floors["grype"] == "0.115.0"
    assert "osv" not in ctx.tool_floors and "osv_sbom" not in ctx.tool_floors
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
    assert readiness.detail == (
        f"{tool}: no OSV API lookup: the feeds registry has no live osv source, or it is air-gapped"
    )


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


def test_opengrep_is_ready_only_with_its_pack_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adapter_module, "on_path", lambda *b, missing="": Readiness(ready=True))
    ctx = Context(Config(home=tmp_path))
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    ctx.register_rule_pack(tmp_path / "absent")
    readiness = ctx.tools.get("opengrep").check()
    assert not readiness.ready and "opengrep rule pack is not a directory" in str(readiness.detail)
    ctx._rule_pack = tmp_path
    assert ctx.tools.get("opengrep").check().ready


def test_opengrep_scans_with_the_registered_pack_and_supplements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def scan(workspace: Path, pack: Path, **kw: Any) -> str:
        seen.update(kw, workspace=workspace, pack=pack)
        return "scanned"

    monkeypatch.setattr(opengrep, "scan", scan)
    ctx = _code_ctx(tmp_path, monkeypatch)
    configure(ctx, "rule-pack-allowlist", yaml.safe_load(ALLOWLIST))
    ctx.register_rule_pack(tmp_path / "pack")
    found = ctx.tools.get("opengrep").acquire(ToolRequest(workspace=tmp_path))
    assert found.data == "scanned" and found.acquisition.acquired_at == NOW
    assert (seen["workspace"], seen["pack"]) == (tmp_path, tmp_path / "pack")
    assert seen["supplements"] == ctx.rule_pack_supplements and seen["clock"] is ctx.clock
    assert seen["runner"].allows("opengrep") and seen["runner"].allows("git")
    assert not seen["runner"].allows("curl")


def test_govulncheck_scans_under_safe_exec_and_records_its_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(govulncheck, "scan", lambda w, **kw: seen.update(kw, workspace=w))
    ctx = _code_ctx(tmp_path, monkeypatch)
    found = ctx.tools.get("govulncheck").acquire(ToolRequest(workspace=tmp_path))
    assert seen == {"workspace": tmp_path, "safe_exec": ctx.safe_exec, "clock": ctx.clock}
    assert found.acquisition.argv_sha256 == argv_digest(["govulncheck", "-json", "./..."])


def test_joern_scans_the_querys_symbols_with_the_java_opts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(joern, "scan", lambda w, **kw: seen.update(kw, workspace=w))
    monkeypatch.setenv("JOERN_JAVA_OPTS", "-Xmx2g")
    ctx = _code_ctx(tmp_path, monkeypatch)
    query = SymbolQuery(workspace=tmp_path, names=("com.foo.Bar#parse",))
    ctx.tools.get("joern").acquire(ToolRequest(symbols=query))
    assert (seen["workspace"], seen["symbols"]) == (tmp_path, ("com.foo.Bar#parse",))
    assert seen["java_opts"] == "-Xmx2g" and seen["runner"].allows("joern-parse")


def test_joern_defaults_to_an_8g_heap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(joern, "scan", lambda w, **kw: seen.update(kw))
    monkeypatch.delenv("JOERN_JAVA_OPTS", raising=False)
    ctx = _code_ctx(tmp_path, monkeypatch)
    query = SymbolQuery(workspace=tmp_path, names=("f",))
    ctx.tools.get("joern").acquire(ToolRequest(symbols=query))
    assert seen["java_opts"] == "-Xmx8g"


def test_rule_allowlist_inline_list() -> None:
    assert load_rule_allowlist("a-rule, b-rule") == RuleAllowlist(
        frozenset({"a-rule", "b-rule"}), "inline"
    )


def test_no_rule_allowlist_means_no_filtering() -> None:
    assert load_rule_allowlist(None) is None and load_rule_allowlist("") is None


@pytest.mark.parametrize(
    ("text", "rules"),
    [
        (
            "pack-name:\n  - go-tls-bypass   # 42 repos\n  - java-tls-bypass\n# a comment line\n",
            {"go-tls-bypass", "java-tls-bypass"},
        ),
        ("- a\n- b\n", {"a", "b"}),
        (ALLOWLIST, {"go-tls-bypass", "java-tls-bypass", "r1"}),
        ("a\nkey: value\nb:\n", {"a"}),
    ],
)
def test_rule_allowlist_reads_a_file(tmp_path: Path, text: str, rules: set[str]) -> None:
    path = tmp_path / "a.yaml"
    path.write_text(text)
    assert load_rule_allowlist(f"@{path}") == RuleAllowlist(frozenset(rules), str(path))


def test_an_unparseable_allowlist_file_reads_as_lines(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_text("- a\n- [b\n")
    assert load_rule_allowlist(f"@{path}") == RuleAllowlist(frozenset({"a", "[b"}), str(path))


def test_an_empty_or_missing_rule_allowlist_fails_closed(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("# nothing here\n")
    with pytest.raises(ValidationError, match="fail-closed"):
        load_rule_allowlist(f"@{empty}")
    with pytest.raises(ValidationError, match="fail-closed"):
        load_rule_allowlist(",  ,")
    with pytest.raises(ValidationError, match="no such file"):
        load_rule_allowlist(f"@{tmp_path / 'nope.yaml'}")
