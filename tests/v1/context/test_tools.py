from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.context import Config, Context
from traust_core.v1.context import context as context_module
from traust_core.v1.context.tools import load_safe_exec, load_toolchain, scanner_tools
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.assessment import ToolName
from traust_core.v1.providers.base import Readiness
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult
from traust_core.v1.providers.tools import DatabaseStatus, ToolProvider
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


def test_no_scanner_is_registered_by_core_yet(tmp_path: Path) -> None:
    ctx = Context(Config(home=tmp_path))
    assert scanner_tools(ctx) == ()
    ctx.register_toolchain(EXTERNAL_TOOLS, SAFE_EXEC)
    assert ctx.tools.names() == []


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
