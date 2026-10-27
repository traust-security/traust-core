"""Checkov as a tool provider: the offline scan behind a cloud-config audit.

Every rule about Checkov's output lives in `models.cloud_config`; this module runs the binaries and
lays out the scan tree. Not to be confused with `k8s_hardening`, which never runs Checkov.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from traust_core.v1.errors import ServiceError, TraustError, ValidationError
from traust_core.v1.models.cloud_config import (
    CHECKOV,
    CHECKOV_VERSION,
    CheckovScan,
    CloudConfigFacts,
    IacInventory,
    require_checkov,
)
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.clock import Clock
from traust_core.v1.providers.process import ProcessRunner, ProcessTimeout
from traust_core.v1.providers.tools import DatabaseStatus, NoDatabase

CHECKOV_TIMEOUT = 1800.0
PROBE_TIMEOUT = 60.0  # version probes, git HEAD, and one `bicep build`
# The `bicep` CLI is installed by hand (docs: requirements); verify the download against the
# sha256 vetted for its platform. Intake row: docs/external-dependencies.md (MIT, Azure/bicep).
# bicep-osx-arm64: 59072cc82da704ab45d6bb11133da15b169795e42ef585dedc73d98e19fcf1be
BICEP_VERSION = "0.45.15"
# Offline always: no policy downloads, no platform key, gitleaks is the one secret scanner.
_OFFLINE = ("--output", "json", "--skip-download", "--compact")
# Core's IacInventory applies the same skip rule; pruning here only spares the walk.
_SKIP_DIRS = frozenset({"vendor", "node_modules", "third_party"})
_YAML_READ_CAP = 1_000_000  # bytes; `kind:` sits near the top in practice
# The bicep fallback's yield: extra outputs, extra roots, aliases, notes, files recovered.
_Fallback = tuple[tuple[bytes, ...], tuple[str, ...], dict[str, str], dict[str, str], int]


class CheckovProvider:
    """The pinned Checkov over one checkout, as `CloudConfigFacts`; read-only toward it."""

    name = CHECKOV

    def __init__(
        self,
        checkov: ProcessRunner,
        probe: ProcessRunner,
        clock: Clock,
        bicep: Sequence[Path] = (),
    ) -> None:
        self._checkov = checkov
        self._probe = probe
        self._clock = clock
        self._bicep = tuple(bicep)

    def check(self) -> Readiness:
        try:
            require_checkov(self._version())
        except TraustError as e:
            return Readiness(ready=False, detail=str(e))
        return Readiness(ready=True)

    def acquire(self, request: ToolRequest) -> Result[CloudConfigFacts]:
        workspace = request.checkout()
        if not workspace.is_dir():
            raise ValidationError(f"checkov: workspace is not a directory: {workspace}")
        reported = self._version()
        require_checkov(reported)  # before the scan: another checkov never touches the checkout
        facts = CloudConfigFacts.of(self._scan(workspace, reported))
        return Result(
            facts,
            Acquisition(
                provider=self.name,
                acquired_at=self._clock.now(),
                version=facts.checkov_version,
                source=str(workspace.resolve()),
            ),
        )

    def version(self) -> str | None:
        try:
            found = re.search(r"\d+\.\d+\.\d+", self._version())
        except ServiceError:
            return None  # not installed: readiness says so
        return found.group(0) if found else None

    def database(self) -> DatabaseStatus | None:
        return None

    def update_database(self) -> DatabaseStatus:
        raise NoDatabase(f"{self.name} keeps no vulnerability database to update")

    def _version(self) -> str:
        try:
            out = self._probe.run(["checkov", "--version"], check=False)
        except ServiceError as e:
            raise ServiceError(
                _cause(
                    e,
                    missing=f"checkov not on PATH (pip install checkov=={CHECKOV_VERSION})",
                    timeout="checkov --version timed out",
                )
            ) from e
        return (out.stdout + out.stderr).decode(errors="replace")

    def _scan(self, workspace: Path, version: str) -> CheckovScan:
        resolved = workspace.resolve()
        files = list(_first_party(resolved))
        inventory = IacInventory.count(files, lambda p: _leading_text(resolved / p))
        observed: dict[str, Any] = {
            "target": resolved.name,
            "version": version,
            "inventory": inventory,
            "target_head": self._git_head(workspace),
        }
        with tempfile.TemporaryDirectory(prefix="cca-scan-") as tmp:
            scan_dir, aliases, notes = _scan_tree(resolved, Path(tmp), _containerfiles(files))
            extra = (str(scan_dir),) if scan_dir != resolved else ()
            observed["roots"] = (str(workspace), str(resolved), *extra)
            stdout, error = self._run_checkov(scan_dir, "--skip-framework", "secrets")
        if error is None:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                error = "unparseable checkov JSON output"
        if error is not None:
            return CheckovScan(**observed, error=error, aliases=aliases, notes=notes)
        arm, roots, arm_aliases, note, recovered = self._bicep_fallback(
            resolved, parsed, (*extra, str(resolved), str(workspace))
        )
        observed["roots"] += roots
        return CheckovScan(
            **observed,
            outputs=(stdout, *arm),
            aliases={**aliases, **arm_aliases},
            notes={**notes, **note},
            bicep_recovered=recovered,
        )

    def _run_checkov(self, directory: Path, *flags: str) -> tuple[bytes, str | None]:
        """One offline checkov run over a directory: its stdout, or why there is none."""
        argv = ["checkov", "--directory", str(directory), *_OFFLINE, *flags]
        try:
            done = self._checkov.run(argv, check=False)
        except ServiceError as e:
            return b"", _cause(
                e, missing="checkov not on PATH", timeout=f"timeout after {CHECKOV_TIMEOUT:.0f}s"
            )
        if not done.stdout.strip():
            stderr = done.stderr.decode(errors="replace").strip()
            return b"", (
                stderr.splitlines()[-1][:200] if stderr else f"exit {done.returncode}, no output"
            )
        return done.stdout, None

    def _git_head(self, workspace: Path) -> str | None:
        try:
            done = self._probe.run(["git", "-C", str(workspace), "rev-parse", "HEAD"], check=False)
        except ServiceError:
            return None  # not a git checkout, or no git: the facts say "unknown"
        return (done.stdout.decode().strip() or None) if done.returncode == 0 else None

    def _find_bicep(self) -> Path | None:
        """The first candidate that reports the pinned version; any other bicep counts as absent."""
        for cand in self._bicep:
            if not cand.is_file():
                continue
            try:
                done = self._probe.run([str(cand), "--version"], check=False)
            except TraustError:
                continue
            if BICEP_VERSION in done.stdout.decode(errors="replace"):
                return cand
        return None

    def _bicep_fallback(self, resolved: Path, parsed: Any, strip: tuple[str, ...]) -> _Fallback:
        """Checkov 3.3.6's bicep parser rejects much real-world Bicep: transpile each rejected
        file offline with the pinned CLI (`--no-restore`: registry modules are never fetched)
        and re-scan the ARM through the arm framework, citing the source `.bicep`."""
        failures = _bicep_parse_failures(parsed, strip)
        if not failures:
            return (), (), {}, {}, 0
        bicep = self._find_bicep()
        if bicep is None:
            return _note(
                f"{len(failures)} .bicep file(s) failed checkov's parser and the pinned bicep "
                f"CLI (v{BICEP_VERSION}) is not installed — transpile fallback unavailable, "
                "files stay NOT ASSESSED (docs/setup.md has the install)"
            )
        with tempfile.TemporaryDirectory(prefix="cca-bicep-") as tmp:
            ok, failed = [], []
            for rel in failures:
                src = resolved / rel.lstrip("/")
                dst = Path(tmp) / (rel.lstrip("/") + ".arm.json")
                dst.parent.mkdir(parents=True, exist_ok=True)
                built = src.is_file() and self._transpile(bicep, src, dst)
                (ok if built else failed).append(rel)
            if not ok:
                return _note(
                    f"0/{len(failures)} parse-failed .bicep file(s) transpiled (bicep "
                    f"v{BICEP_VERSION} --no-restore; likely external registry modules — fetched "
                    "by design never); files stay NOT ASSESSED"
                )
            arm, error = self._run_checkov(Path(tmp), "--framework", "arm")
            if error is not None:
                return _note(
                    f"{len(ok)}/{len(failures)} parse-failed .bicep file(s) transpiled but the "
                    f"arm re-scan failed: {error}; files stay NOT ASSESSED"
                )
        note = (
            f"{len(ok)}/{len(failures)} parse-failed .bicep file(s) transpiled with the pinned "
            f"bicep CLI v{BICEP_VERSION} (--no-restore, offline) and re-scanned via the arm "
            "framework; fact paths cite the source .bicep but LINE RANGES refer to the "
            "generated ARM template"
            + (f"; still unparsed (stay NOT ASSESSED): {', '.join(failed)}" if failed else "")
        )
        aliases = {"/" + rel.lstrip("/") + ".arm.json": rel for rel in ok}
        return (arm,), (tmp,), aliases, {"bicep_transpile_fallback": note}, len(ok)

    def _transpile(self, bicep: Path, src: Path, dst: Path) -> bool:
        argv = [str(bicep), "build", str(src), "--no-restore", "--outfile", str(dst)]
        try:
            done = self._probe.run(argv, check=False)
        except ServiceError:
            return False
        return done.returncode == 0 and dst.is_file()


def _cause(e: ServiceError, *, missing: str, timeout: str) -> str:
    if isinstance(e.__cause__, FileNotFoundError):
        return missing
    if isinstance(e, ProcessTimeout):
        return timeout
    return str(e)


def _note(text: str) -> _Fallback:
    return (), (), {}, {"bicep_transpile_fallback": text}, 0


def _first_party(root: Path) -> Iterator[PurePosixPath]:
    """Checkout-relative files outside vendored, hidden (but `.tekton`) and symlinked dirs."""
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _SKIP_DIRS
            and (not d.startswith(".") or d == ".tekton")
            and not Path(top, d).is_symlink()
        )
        for name in sorted(names):
            if (path := Path(top, name)).is_file():
                yield PurePosixPath(path.relative_to(root).as_posix())


def _containerfiles(files: Sequence[PurePosixPath]) -> list[PurePosixPath]:
    """Checkov 3.3.6's dockerfile framework only matches `Dockerfile` / `Dockerfile.*`, so it
    silently skips the Red Hat `Containerfile` convention."""
    return sorted(
        f
        for f in files
        if ".tekton" not in f.parts
        and (f.name == "Containerfile" or f.name.startswith("Containerfile."))
    )


def _leading_text(path: Path) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return fh.read(_YAML_READ_CAP)
    except OSError:
        return ""


def _scan_tree(
    resolved: Path, tmp: Path, containerfiles: Sequence[PurePosixPath]
) -> tuple[Path, dict[str, str], dict[str, str]]:
    """Where checkov scans: the checkout itself, or a temp tree when a 3.3.6 blind spot needs
    one. Returns (scan dir, {alias path: real path}, {metadata key: workaround note})."""
    hidden = any(part.startswith(".") for part in resolved.parts[1:])
    if not (hidden or containerfiles):
        return resolved, {}, {}
    scan_dir = tmp / (resolved.name.lstrip(".") or "target")
    aliases: dict[str, str] = {}
    notes: dict[str, str] = {}
    if containerfiles:
        scan_dir.mkdir()
        _mirror(resolved, scan_dir)
        skipped = []
        for rel in containerfiles:
            alias = scan_dir / rel.parent / ("Dockerfile" + rel.name[len("Containerfile") :])
            if alias.exists() or alias.is_symlink():
                skipped.append(rel.as_posix())  # a real Dockerfile twin is scanned instead
                continue
            alias.symlink_to(resolved / rel)
            prefix = "" if str(rel.parent) == "." else "/" + rel.parent.as_posix()
            aliases[f"{prefix}/{alias.name}"] = f"{prefix}/{rel.name}"
        notes["containerfile_alias_workaround"] = (
            f"{len(aliases)} Containerfile(s) aliased to Dockerfile-named symlinks in temp scan "
            f"tree {scan_dir} (checkov {CHECKOV_VERSION}'s dockerfile framework skips "
            "Containerfile names); fact paths are mapped back to the real Containerfile paths"
            + (
                f"; not aliased (Dockerfile-name twin already exists): {', '.join(skipped)}"
                if skipped
                else ""
            )
        )
    else:
        scan_dir.symlink_to(resolved)
    if hidden:
        # checkov 3.3.6's kubernetes framework evaluates zero checks, silently, when any
        # component of the scan path is dot-prefixed.
        notes["hidden_path_workaround"] = (
            f"hidden path component in {resolved} suppresses checkov's kubernetes framework; "
            f"scanned via non-hidden temp path {scan_dir}"
        )
    return scan_dir, aliases, notes


def _mirror(src: Path, dst: Path) -> None:
    """Every real directory as a real directory (checkov's discovery never descends a directory
    symlink), every file and symlinked dir as a symlink back to the checkout."""
    for entry in sorted(src.iterdir()):
        if entry.is_dir() and not entry.is_symlink():
            (dst / entry.name).mkdir()
            _mirror(entry, dst / entry.name)
        else:
            (dst / entry.name).symlink_to(entry)


def _bicep_parse_failures(parsed: Any, strip: tuple[str, ...]) -> list[str]:
    """Checkout paths (leading /) of the .bicep files checkov failed to parse."""
    rels = set()
    for block in parsed if isinstance(parsed, list) else [parsed]:
        if not isinstance(block, Mapping):
            continue
        for path in (block.get("results") or {}).get("parsing_errors") or []:
            path = str(path)
            if not path.endswith(".bicep"):
                continue
            if root := next((r for r in strip if r and path.startswith(r)), None):
                path = "/" + path[len(root) :].lstrip("/")
            rels.add(path)
    return sorted(rels)
