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
_UPSTREAM_WAIT_SECONDS = 5


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


class ProcessTimeout(ServiceError):
    """A run killed at its timeout, with what it had written by then."""

    def __init__(self, argv: tuple[str, ...], e: subprocess.TimeoutExpired) -> None:
        super().__init__(f"{argv[0]} failed to run: {e}")
        self.stdout: bytes = e.stdout or b""
        self.stderr: bytes = e.stderr or b""


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

    def allows(self, binary: str) -> bool:
        """Whether `binary` may run here (the deployment's allowlist, never a shell)."""
        return Path(binary).name in self._allowed

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
        timeout_seconds: float | None = None,
    ) -> ProcessResult:
        args = self._validate(argv)
        start = time.monotonic()
        try:
            done = subprocess.run(
                args,
                cwd=cwd,
                env=self._child_env(env),
                input=stdin,
                capture_output=True,
                timeout=self._seconds(timeout_seconds),
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ProcessTimeout(args, e) from e
        except OSError as e:
            raise ServiceError(f"{args[0]} failed to run: {e}") from e
        result = ProcessResult(
            args, done.returncode, done.stdout, done.stderr, time.monotonic() - start
        )
        if check and result.returncode != 0:
            raise ProcessError(result)
        return result

    def pipeline(
        self,
        segments: Sequence[Sequence[str]],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[ProcessResult, ...]:
        """Each segment's stdout piped into the next, no shell: one result per segment, the
        output and stderr on the last one. Without `stdin` the first segment inherits ours."""
        argvs = [self._validate(segment) for segment in segments]
        if not argvs:
            raise ValidationError("a pipeline needs at least one segment")
        child_env = self._child_env(env)
        seconds = self._seconds(timeout_seconds)
        start = time.monotonic()
        first_stdin = subprocess.PIPE if stdin is not None else None
        procs: list[subprocess.Popen[bytes]] = []
        try:
            for args in argvs:
                source = procs[-1].stdout if procs else first_stdin
                procs.append(
                    subprocess.Popen(
                        args,
                        stdin=source,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=cwd,
                        env=child_env,
                    )
                )
                if len(procs) > 1 and procs[-2].stdout:
                    procs[-2].stdout.close()  # the upstream segment sees SIGPIPE when we stop
            single = len(procs) == 1
            if stdin is not None and not single and procs[0].stdin:
                procs[0].stdin.write(stdin)
                procs[0].stdin.close()
            out, err = procs[-1].communicate(stdin if single else None, timeout=seconds)
            for p in procs[:-1]:
                p.wait(timeout=_UPSTREAM_WAIT_SECONDS)
        except subprocess.TimeoutExpired as e:
            for p in procs:
                p.kill()
            raise ProcessTimeout(argvs[-1], e) from e
        except OSError as e:
            for p in procs:
                p.kill()
            raise ServiceError(f"pipeline from {argvs[0][0]} failed to run: {e}") from e
        taken = time.monotonic() - start
        upstream = [
            ProcessResult(a, p.returncode, b"", b"", taken)
            for a, p in zip(argvs[:-1], procs[:-1], strict=True)
        ]
        return (*upstream, ProcessResult(argvs[-1], procs[-1].returncode, out, err, taken))

    def _child_env(self, env: Mapping[str, str] | None) -> dict[str, str]:
        child_env = {k: os.environ[k] for k in self._keep_env if k in os.environ}
        child_env.update(env or {})
        return child_env

    def _seconds(self, timeout_seconds: float | None) -> float:
        return min(timeout_seconds or self._timeout, self._timeout)
