"""The external scanners `external-tools.yaml` pins: their versions, vulnerability databases and
the env and flags that keep a scan from updating its database."""

from __future__ import annotations

import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from traust_core.v1.errors import ServiceError
from traust_core.v1.models.base import Dto
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import DatabaseStatus

# A version the Go toolchain stamps when it didn't install from the module proxy: not a version.
UNSTAMPED_VERSION = "0.0.0"
# grype refuses a database older than this itself (traust check_drift GRYPE_DB_MAX_AGE_DAYS).
GRYPE_DB_MAX_AGE = timedelta(days=5)
VERSION_SECONDS = 15.0
POPULATE_SECONDS = 300.0
# What a version or database probe keeps of our env: the base set and grype's cache location.
PROBE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "GRYPE_DB_CACHE_DIR")

_POPULATE: dict[str, tuple[tuple[str, ...], ...]] = {"grype": (("grype", "db", "update"),)}
POPULATABLE_TOOLS: frozenset[str] = frozenset(_POPULATE)
# osv-scanner's offline database exists only on air-gapped deployments, provided and kept current
# by the adopter (owner decision 2026-10-20); the others keep none the harness tracks.
_NO_DB_TOOLS = frozenset(
    {
        "opengrep",
        "gitleaks",
        "syft",
        "skopeo",
        "cosign",
        "yara",
        "joern",
        "pip-audit",
        "osv-scanner",
    }
)
_FREEZE_ENV: dict[str, dict[str, str]] = {
    "grype": {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"},
    "syft": {"SYFT_CHECK_FOR_APP_UPDATE": "false"},
    "govulncheck": {},
}
_FREEZE_FLAGS: dict[str, list[str]] = {"osv-scanner": ["--offline"]}


class ToolPin(Dto):
    """One `external-tools.yaml` entry: the binary, its version floor and how to ask its version."""

    name: str
    expected: str
    version_cmd: tuple[str, ...] | None = None
    version_regex: str | None = None
    consumers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolCheck:
    """One binary's readiness: on PATH, at or above its pin, its database present."""

    name: str
    installed: bool
    version: str | None = None
    version_ok: bool = False
    database: DatabaseStatus | None = None
    # `go install` from a local clone stamps v0.0.0: reinstalling fixes it, upgrading doesn't.
    unstamped: bool = False


def version_at_least(installed: str, expected: str) -> bool:
    """Numeric dotted comparison; False when either side isn't one."""
    try:
        return tuple(map(int, installed.split("."))) >= tuple(map(int, expected.split(".")))
    except ValueError:
        return False


def freeze_env(tool: str, *, db_dir: str | None = None) -> dict[str, str]:
    """Env that stops `tool` updating its database mid-scan; `db_dir` is govulncheck's mirror."""
    env = dict(_FREEZE_ENV.get(tool, {}))
    if tool == "govulncheck" and db_dir:
        env["GOVULNDB"] = f"file://{db_dir}"
    return env


def freeze_flags(tool: str) -> list[str]:
    return list(_FREEZE_FLAGS.get(tool, []))


def preflight_failures(results: Sequence[ToolCheck]) -> list[str]:
    """One message per check that should stop a run."""
    msgs: list[str] = []
    for tc in results:
        if not tc.installed:
            msgs.append(f"{tc.name}: not found on PATH")
        elif tc.unstamped:
            msgs.append(
                f"{tc.name}: reports version {tc.version}, which means the "
                f"binary carries no version stamp -- it was not installed from "
                f"the module proxy. Reinstall with a version query "
                f"(e.g. `go install <module>@latest`); upgrading will not help"
            )
        elif not tc.version_ok:
            msgs.append(f"{tc.name}: version {tc.version} does not meet pin")
        elif tc.database is not None and not tc.database.exists:
            msgs.append(f"{tc.name}: vulnerability DB not found at {tc.database.path}")
    return msgs


def _built_at(raw: str | None) -> datetime | None:
    """`grype db status`'s `Built:` value (`2026-08-24T01:31:46Z`, or with a trailing zone name)
    as an aware datetime; None when it reads as neither."""
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        found = datetime.fromisoformat(text.split(" ")[0] if "T" in text else text)
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", text)
        if not m:
            return None
        found = datetime.fromisoformat(m.group(1))
    return found if found.tzinfo else found.replace(tzinfo=UTC)


class Toolchain:
    """The pinned scanners, probed through `process` (which allows the pinned binaries)."""

    def __init__(
        self, pins: Mapping[str, ToolPin], process: ProcessRunner, *, grype_db_dir: Path
    ) -> None:
        self.pins = dict(pins)
        self._process = process
        self._grype_db_dir = grype_db_dir

    def version(
        self,
        binary: str,
        version_cmd: Sequence[str] | None = None,
        version_regex: str | None = None,
    ) -> str | None:
        """The binary's version from its version command: the regex's groups joined, else the
        first semver; None when it doesn't run or says neither."""
        text = self._output(list(version_cmd or [binary, "--version"]))
        if not text or not text.strip():
            return None
        if version_regex:
            m = re.search(version_regex, text)
            return ".".join(m.groups()) if m else None
        m = re.search(r"(\d+\.\d+\.\d+)", text)
        return m.group(1) if m else None

    def database(self, tool: str) -> DatabaseStatus | None:
        """The tool's vulnerability database; None for a tool that keeps none."""
        if tool in _NO_DB_TOOLS:
            return None
        if tool == "grype":
            return self._grype_database()
        if tool == "govulncheck":
            # Its database metadata comes from the scan's -json config record, not a probe.
            return DatabaseStatus(tool=tool, exists=True)
        return None

    def populate(self, tool: str) -> tuple[bool, str]:
        """Run the tool's database update: (succeeded, a one-line message)."""
        commands = _POPULATE.get(tool)
        if commands is None:
            return True, f"{tool}: no DB to populate"
        for cmd in commands:
            try:
                done = self._process.run(cmd, check=False, timeout_seconds=POPULATE_SECONDS)
            except ProcessTimeout:
                return False, f"{tool}: {' '.join(cmd)} timed out"
            except ServiceError as e:
                if isinstance(e.__cause__, FileNotFoundError):
                    return False, f"{tool}: {cmd[0]} not found on PATH"
                raise
            if done.returncode != 0:
                err = done.stderr.decode(errors="replace").strip()[:500]
                return False, f"{tool}: {' '.join(cmd)} failed (exit {done.returncode}): {err}"
        info = self.database(tool)
        built = info.built_at.isoformat() if info and info.built_at else "unknown"
        return True, f"{tool}: DB populated (built {built})"

    def check(self, name: str) -> ToolCheck:
        """Whether `name` is on PATH, at or above its pin, with its database present."""
        if not shutil.which(name):
            return ToolCheck(name=name, installed=False)
        pin = self.pins.get(name)
        version = self.version(
            name, pin.version_cmd if pin else None, pin.version_regex if pin else None
        )
        expected = pin.expected if pin else None
        version_ok = version_at_least(version, expected) if version and expected else not expected
        return ToolCheck(
            name=name,
            installed=True,
            version=version,
            version_ok=version_ok,
            database=self.database(name),
            unstamped=version == UNSTAMPED_VERSION,
        )

    def preflight(self, required: Sequence[str]) -> list[ToolCheck]:
        return [self.check(name) for name in required]

    def floors(self, binaries: Mapping[str, str]) -> dict[str, str]:
        """Each tool's floor, the pin of the binary it runs (tool name -> binary)."""
        return {
            name: pin.expected
            for name, binary in binaries.items()
            if binary and (pin := self.pins.get(binary))
        }

    def db_cache_dirs(self) -> dict[str, Path]:
        """Native database cache roots by tool (grype)."""
        return {"grype": self._grype_db_dir}

    def _output(self, cmd: list[str]) -> str | None:
        try:
            done = self._process.run(cmd, check=False, timeout_seconds=VERSION_SECONDS)
        except ServiceError:
            return None
        return (done.stdout + done.stderr).decode(errors="replace")

    def _grype_database(self) -> DatabaseStatus:
        text = self._output(["grype", "db", "status"])
        if text is None:
            return DatabaseStatus(tool="grype", exists=False, max_age=GRYPE_DB_MAX_AGE)
        fields = {
            key: m.group(1).strip()
            for line in text.splitlines()
            for key, pattern in _GRYPE_STATUS.items()
            if (m := re.match(pattern, line))
        }
        db_dir = Path(fields["location"]) if "location" in fields else self._grype_db_dir
        exists = db_dir.is_dir() and any(db_dir.glob("*/vulnerability.db"))
        return DatabaseStatus(
            tool="grype",
            exists=exists or "built" in fields,
            built_at=_built_at(fields.get("built")),
            schema_version=fields.get("schema"),
            max_age=GRYPE_DB_MAX_AGE,
            path=str(db_dir),
        )


_GRYPE_STATUS = {
    "built": r"^\s*Built:\s*(.+)",
    "schema": r"^\s*Schema:\s*(\S+)",
    "location": r"^\s*Location:\s*(.+)",
}
