from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.process import ProcessResult, ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import DatabaseStatus
from traust_core.v1.providers.tools import toolchain as tc
from traust_core.v1.providers.tools.toolchain import (
    GRYPE_DB_MAX_AGE,
    PROBE_ENV,
    Toolchain,
    ToolCheck,
    ToolPin,
    freeze_env,
    freeze_flags,
    preflight_failures,
    version_at_least,
)

GOVULNCHECK = ToolPin(
    name="govulncheck",
    expected="1.6.0",
    version_cmd=("govulncheck", "-version"),
    version_regex=r"govulncheck@v(\d+)\.(\d+)\.(\d+)",
)
PINS = {"grype": ToolPin(name="grype", expected="0.115.0"), "govulncheck": GOVULNCHECK}
GRYPE_STATUS = (
    "Path:      /cache/grype/db/6/vulnerability.db\n"
    "Schema:    v6.0.2\n"
    "Built:     2026-10-23T01:31:46Z\n"
    "Status:    valid\n"
)


class Runner:
    """Answers each argv with `answer(argv)`: stdout text, or an exception to raise."""

    def __init__(self, answer: Callable[[tuple[str, ...]], str | Exception], rc: int = 0) -> None:
        self.answer = answer
        self.rc = rc
        self.ran: list[tuple[tuple[str, ...], float | None]] = []

    def run(
        self, argv: Any, *, check: bool = True, timeout_seconds: float | None = None
    ) -> ProcessResult:
        args = tuple(argv)
        self.ran.append((args, timeout_seconds))
        found = self.answer(args)
        if isinstance(found, Exception):
            raise found
        return ProcessResult(args, self.rc, found.encode(), b"oops", 0.1)


def chain(runner: Runner, tmp_path: Path, pins: dict[str, ToolPin] = PINS) -> Toolchain:
    return Toolchain(pins, runner, grype_db_dir=tmp_path / "grype")  # type: ignore[arg-type]


def timeout(argv: tuple[str, ...]) -> ProcessTimeout:
    return ProcessTimeout(argv, subprocess.TimeoutExpired(list(argv), 1))


def not_found() -> ServiceError:
    e = ServiceError("grype failed to run")
    e.__cause__ = FileNotFoundError("grype")
    return e


class TestFreeze:
    def test_grype_freeze_env(self) -> None:
        env = freeze_env("grype")
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"

    def test_syft_freeze_env(self) -> None:
        assert freeze_env("syft")["SYFT_CHECK_FOR_APP_UPDATE"] == "false"

    def test_govulncheck_freeze_env_no_db_dir(self) -> None:
        assert "GOVULNDB" not in freeze_env("govulncheck")

    def test_govulncheck_freeze_env_with_db_dir(self) -> None:
        assert freeze_env("govulncheck", db_dir="/tmp/vulndb")["GOVULNDB"] == "file:///tmp/vulndb"

    def test_osv_scanner_freeze_flags(self) -> None:
        assert freeze_flags("osv-scanner") == ["--offline"]

    def test_unknown_tool_returns_empty(self) -> None:
        assert freeze_env("unknown-tool") == {}
        assert freeze_flags("unknown-tool") == []

    def test_a_child_sees_the_freeze_env(self) -> None:
        done = ProcessRunner(["printenv"]).run(["printenv"], env=freeze_env("grype"))
        assert b"GRYPE_DB_AUTO_UPDATE=false" in done.stdout
        assert b"GRYPE_CHECK_FOR_APP_UPDATE=false" in done.stdout


class TestPreflightFailures:
    def test_missing_tool(self) -> None:
        [msg] = preflight_failures([ToolCheck(name="grype", installed=False)])
        assert "not found on PATH" in msg

    def test_wrong_version(self) -> None:
        checks = [ToolCheck(name="grype", installed=True, version="0.100.0", version_ok=False)]
        [msg] = preflight_failures(checks)
        assert "does not meet pin" in msg

    def test_missing_db(self) -> None:
        db = DatabaseStatus(tool="grype", exists=False, path="/tmp/grype/db")
        checks = [ToolCheck("grype", True, "0.115.0", True, db)]
        assert preflight_failures(checks) == ["grype: vulnerability DB not found at /tmp/grype/db"]

    def test_all_ok(self) -> None:
        db = DatabaseStatus(tool="grype", exists=True)
        assert preflight_failures([ToolCheck("grype", True, "0.115.0", True, db)]) == []

    def test_tool_without_db_ok(self) -> None:
        assert preflight_failures([ToolCheck("opengrep", True, "1.25.0", True, None)]) == []

    def test_preflight_names_the_actual_fix_for_an_unstamped_build(self) -> None:
        [msg] = preflight_failures(
            [ToolCheck("govulncheck", True, "0.0.0", version_ok=False, unstamped=True)]
        )
        assert "no version stamp" in msg and "upgrading will not help" in msg


@pytest.mark.parametrize(
    ("installed", "expected", "ok"),
    [
        ("0.115.0", "0.115.0", True),
        ("0.116.0", "0.115.0", True),
        ("0.114.0", "0.115.0", False),
        ("1.0.0", "0.115.0", True),
        ("0.115.1", "0.115.0", True),
        ("0.115.0", "0.115.1", False),
        ("1.0.0-rc1", "1.0.0", False),
    ],
)
def test_version_at_least(installed: str, expected: str, ok: bool) -> None:
    assert version_at_least(installed, expected) is ok


@pytest.mark.parametrize(
    ("output", "cmd", "regex", "expect"),
    [
        ("grype 0.115.0\n", None, None, "0.115.0"),
        (
            "Go: go1.25\ngovulncheck@v1.6.0\n",
            ("govulncheck", "-version"),
            GOVULNCHECK.version_regex,
            "1.6.0",
        ),
        ("govulncheck@devel\n", None, GOVULNCHECK.version_regex, None),
        ("no version here\n", None, None, None),
        ("  \n", None, None, None),
    ],
)
def test_version_reads_the_regex_groups_or_the_first_semver(
    tmp_path: Path, output: str, cmd: tuple[str, ...] | None, regex: str | None, expect: str | None
) -> None:
    runner = Runner(lambda _: output)
    assert chain(runner, tmp_path).version("tool", cmd, regex) == expect
    assert runner.ran == [(cmd or ("tool", "--version"), tc.VERSION_SECONDS)]


def test_a_version_command_that_fails_to_run_reads_as_no_version(tmp_path: Path) -> None:
    runner = Runner(lambda a: timeout(a))
    assert chain(runner, tmp_path).version("grype") is None
    runner = Runner(lambda _: ServiceError("grype failed to run"))
    assert chain(runner, tmp_path).version("grype") is None


def test_an_unpinned_binary_is_refused_not_probed(tmp_path: Path) -> None:
    toolchain = Toolchain(PINS, ProcessRunner(["grype"]), grype_db_dir=tmp_path)
    with pytest.raises(ValidationError, match="binary not allowed: unpinned"):
        toolchain.version("unpinned")


def test_grypes_database_is_read_from_its_status(tmp_path: Path) -> None:
    db = chain(Runner(lambda _: GRYPE_STATUS), tmp_path).database("grype")
    assert db == DatabaseStatus(
        tool="grype",
        exists=True,
        built_at=datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC),
        schema_version="v6.0.2",
        max_age=GRYPE_DB_MAX_AGE,
        path=str(tmp_path / "grype"),
    )


def test_grypes_database_at_its_reported_location(tmp_path: Path) -> None:
    (tmp_path / "loc" / "6").mkdir(parents=True)
    (tmp_path / "loc" / "6" / "vulnerability.db").write_bytes(b"")
    db = chain(Runner(lambda _: f"Location: {tmp_path / 'loc'}\n"), tmp_path).database("grype")
    assert db is not None and db.exists and db.path == str(tmp_path / "loc")
    assert db.built_at is None and db.schema_version is None


def test_a_grype_that_cannot_report_has_no_database(tmp_path: Path) -> None:
    db = chain(Runner(lambda a: timeout(a)), tmp_path).database("grype")
    assert db == DatabaseStatus(tool="grype", exists=False, max_age=GRYPE_DB_MAX_AGE)
    db = chain(Runner(lambda _: "Status: missing\n"), tmp_path).database("grype")
    assert db is not None and not db.exists


@pytest.mark.parametrize("tool", ["opengrep", "gitleaks", "osv-scanner", "joern", "unknown"])
def test_tools_without_a_tracked_database(tmp_path: Path, tool: str) -> None:
    runner = Runner(lambda _: pytest.fail("probed"))
    assert chain(runner, tmp_path).database(tool) is None


def test_govulnchecks_database_is_read_from_its_scans_not_a_probe(tmp_path: Path) -> None:
    runner = Runner(lambda _: pytest.fail("probed"))
    assert chain(runner, tmp_path).database("govulncheck") == DatabaseStatus(
        tool="govulncheck", exists=True
    )


def test_populate_updates_grype_then_reads_its_build(tmp_path: Path) -> None:
    runner = Runner(lambda a: GRYPE_STATUS if a[-1] == "status" else "")
    assert chain(runner, tmp_path).populate("grype") == (
        True,
        "grype: DB populated (built 2026-10-23T01:31:46+00:00)",
    )
    assert runner.ran[0] == (("grype", "db", "update"), tc.POPULATE_SECONDS)


@pytest.mark.parametrize(
    ("runner", "message"),
    [
        (Runner(lambda _: "", rc=1), "grype: grype db update failed (exit 1): oops"),
        (Runner(lambda a: timeout(a)), "grype: grype db update timed out"),
        (
            Runner(lambda _: not_found()),
            "grype: grype not found on PATH",
        ),
    ],
)
def test_a_failed_populate_says_why(tmp_path: Path, runner: Runner, message: str) -> None:
    assert chain(runner, tmp_path).populate("grype") == (False, message)


def test_populate_raises_what_it_cannot_explain(tmp_path: Path) -> None:
    runner = Runner(lambda _: ServiceError("grype failed to run: denied"))
    with pytest.raises(ServiceError, match="denied"):
        chain(runner, tmp_path).populate("grype")


def test_populate_a_tool_without_a_database(tmp_path: Path) -> None:
    runner = Runner(lambda _: pytest.fail("ran"))
    assert chain(runner, tmp_path).populate("opengrep") == (True, "opengrep: no DB to populate")
    assert {"grype"} == tc.POPULATABLE_TOOLS


def test_check_uses_the_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tc.shutil, "which", lambda n: f"/usr/bin/{n}")
    runner = Runner(lambda _: "govulncheck@v1.7.0")
    check = chain(runner, tmp_path).check("govulncheck")
    assert check == ToolCheck(
        "govulncheck",
        installed=True,
        version="1.7.0",
        version_ok=True,
        database=DatabaseStatus(tool="govulncheck", exists=True),
    )
    assert runner.ran == [(("govulncheck", "-version"), tc.VERSION_SECONDS)]


@pytest.mark.parametrize(
    ("output", "version", "ok"),
    [("x 0.114.0", "0.114.0", False), ("nothing", None, False), ("x 0.200.0", "0.200.0", True)],
)
def test_check_holds_a_version_below_or_missing_its_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str, version: str | None, ok: bool
) -> None:
    monkeypatch.setattr(tc.shutil, "which", lambda n: f"/usr/bin/{n}")
    check = chain(Runner(lambda a: output if "--version" in a else ""), tmp_path).check("grype")
    assert (check.version, check.version_ok) == (version, ok)


def test_check_without_a_pin_takes_any_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tc.shutil, "which", lambda n: f"/usr/bin/{n}")
    check = chain(Runner(lambda _: "nothing"), tmp_path, pins={}).check("yara")
    assert check.installed and check.version_ok and check.version is None


def test_check_a_missing_tool(tmp_path: Path) -> None:
    runner = Runner(lambda _: pytest.fail("probed"))
    toolchain = chain(runner, tmp_path)
    assert toolchain.check("definitely-not-a-real-tool-xyz") == ToolCheck(
        "definitely-not-a-real-tool-xyz", installed=False
    )
    [msg] = preflight_failures(toolchain.preflight(["definitely-not-a-real-tool-xyz"]))
    assert "not found on PATH" in msg


@pytest.mark.parametrize(("version", "unstamped"), [("0.0.0", True), ("1.0.0", False)])
def test_an_unstamped_build_is_not_an_old_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str, unstamped: bool
) -> None:
    monkeypatch.setattr(tc.shutil, "which", lambda n: f"/usr/bin/{n}")
    check = chain(Runner(lambda _: f"govulncheck@v{version}"), tmp_path).check("govulncheck")
    assert check.unstamped is unstamped and check.version_ok is False


def test_floors_are_the_pins_of_the_binaries_tools_run(tmp_path: Path) -> None:
    toolchain = chain(Runner(lambda _: ""), tmp_path)
    floors = toolchain.floors({"grype": "grype", "osv": "", "vuln": "govulncheck", "x": "absent"})
    assert floors == {"grype": "0.115.0", "vuln": "1.6.0"}
    assert toolchain.db_cache_dirs() == {"grype": tmp_path / "grype"}


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        ("2026-10-23T01:31:46Z", datetime(2026, 10, 23, 1, 31, 46, tzinfo=UTC)),
        ("2026-10-23 01:31:46 +0000 UTC", datetime(2026, 10, 23, tzinfo=UTC)),
        ("2026-10-23T01:31:46+02:00 CEST", datetime(2026, 10, 22, 23, 31, 46, tzinfo=UTC)),
        ("garbage", None),
        ("", None),
        (None, None),
    ],
)
def test_grypes_built_value_reads_as_an_aware_datetime(raw: str | None, expect: Any) -> None:
    assert tc._built_at(raw) == expect


def test_the_probe_env_keeps_grypes_cache_location() -> None:
    assert "GRYPE_DB_CACHE_DIR" in PROBE_ENV and timedelta(days=5) == GRYPE_DB_MAX_AGE


def _pinned(*names: str) -> Toolchain:
    pins = {n: p for n, p in PINS.items() if n in names}
    return Toolchain(pins, ProcessRunner(names, keep_env=PROBE_ENV), grype_db_dir=Path("/absent"))


@pytest.mark.skipif(shutil.which("grype") is None, reason="grype not on PATH")
def test_a_real_grype_reports_its_version_and_database() -> None:
    toolchain = _pinned("grype")
    version = toolchain.version("grype")
    assert version is not None and len(version.split(".")) == 3
    assert toolchain.database("grype") is not None
    low = Toolchain(
        {"grype": ToolPin(name="grype", expected="0.1.0")},
        ProcessRunner(["grype"]),
        grype_db_dir=Path("/absent"),
    )
    assert low.check("grype").version_ok
    high = Toolchain(
        {"grype": ToolPin(name="grype", expected="999.0.0")},
        ProcessRunner(["grype"]),
        grype_db_dir=Path("/absent"),
    )
    [msg] = preflight_failures(high.preflight(["grype"]))
    assert "does not meet pin" in msg


@pytest.mark.skipif(shutil.which("govulncheck") is None, reason="govulncheck not on PATH")
def test_a_real_govulncheck_reports_its_version_through_its_regex() -> None:
    version = _pinned("govulncheck").version(
        "govulncheck", GOVULNCHECK.version_cmd, GOVULNCHECK.version_regex
    )
    assert version is not None
