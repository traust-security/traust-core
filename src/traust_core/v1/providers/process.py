from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "env"})
_DEFAULT_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    seconds: float


class ProcessError(ServiceError):
    def __init__(self, result: ProcessResult) -> None:
        tail = result.stderr.decode(errors="replace").strip()[-500:]
        super().__init__(f"{result.argv[0]} exited {result.returncode}: {tail}")
        self.result = result


class ProcessRunner:
    def __init__(
        self,
        allowed: Iterable[str],
        *,
        keep_env: Iterable[str] = _DEFAULT_ENV,
        timeout_seconds: float = 600.0,
    ) -> None:
        self._allowed = frozenset(allowed) - _SHELLS
        self._keep_env = tuple(keep_env)
        self._timeout = timeout_seconds

    def _validate(self, argv: Sequence[str]) -> tuple[str, ...]:
        if not argv or not all(isinstance(a, str) for a in argv):
            raise ValidationError(f"argv must be a non-empty list of strings: {argv!r}")
        head = Path(argv[0]).name
        if head in _SHELLS:
            raise ValidationError(f"shells are never allowed: {head}")
        if head not in self._allowed:
            raise ValidationError(f"binary not allowed: {head}")
        return tuple(argv)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        check: bool = True,
    ) -> ProcessResult:
        args = self._validate(argv)
        child_env = {k: os.environ[k] for k in self._keep_env if k in os.environ}
        child_env.update(env or {})
        start = time.monotonic()
        try:
            done = subprocess.run(
                args,
                cwd=cwd,
                env=child_env,
                input=stdin,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ServiceError(f"{args[0]} failed to run: {e}") from e
        result = ProcessResult(
            args, done.returncode, done.stdout, done.stderr, time.monotonic() - start
        )
        if check and result.returncode != 0:
            raise ProcessError(result)
        return result
