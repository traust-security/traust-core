from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.base import Readiness, on_path
from traust_core.v1.providers.correlation import REQUEST_ID_ENV, current_correlation

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "env"})
_DEFAULT_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
_UPSTREAM_WAIT_SECONDS = 5
_OUTPUT_POLL_SECONDS = 0.01
log = logging.getLogger(__name__)


def _log_process(
    operation: str, outcome: str, duration_ms: float, returncode: int | None = None
) -> None:
    message = "process %s outcome=%s returncode=%s duration_ms=%.1f"
    args = (operation, outcome, returncode, duration_ms)
    extra = {
        "operation": operation,
        "outcome": outcome,
        "returncode": returncode,
        "duration_ms": duration_ms,
    }
    (log.info if outcome == "completed" else log.warning)(message, *args, extra=extra)


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
        super().__init__(
            f"{result.argv[0]} exited {result.returncode}: {tail}", operation="process.run"
        )
        self.result = result


class ProcessOutputLimit(ServiceError):
    """A run exceeding its combined stdout and stderr capture budget."""

    def __init__(self, result: ProcessResult, max_output_bytes: int) -> None:
        super().__init__("process output exceeded its capture limit", operation="process.run")
        self.result = result
        self.max_output_bytes = max_output_bytes


class ProcessTimeout(ServiceError):
    """A run killed at its timeout, with what it had written by then."""

    def __init__(
        self,
        argv: tuple[str, ...],
        e: subprocess.TimeoutExpired,
        *,
        operation: str = "process.run",
    ) -> None:
        super().__init__(f"{argv[0]} failed to run: {e}", operation=operation)
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

    def readiness(self, binary: str) -> Readiness:
        """Ready when the allowlist grants `binary` and it is on PATH."""
        if not self.allows(binary):
            return Readiness(ready=False, detail=f"{binary} is not in process.allowed_binaries")
        return on_path(binary, missing=" not on PATH")

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
        max_output_bytes: int | None = None,
    ) -> ProcessResult:
        """Run a command, optionally limiting combined captured stdout and stderr bytes."""
        args = self._validate(argv)
        if max_output_bytes is not None and (
            not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes <= 0
        ):
            raise ValidationError("max_output_bytes must be a positive integer")
        start = time.monotonic()
        try:
            if max_output_bytes is None:
                done = subprocess.run(
                    args,
                    cwd=cwd,
                    env=self._child_env(env),
                    input=stdin,
                    capture_output=True,
                    timeout=self._seconds(timeout_seconds),
                    check=False,
                )
                result = ProcessResult(
                    args, done.returncode, done.stdout, done.stderr, time.monotonic() - start
                )
            else:
                result = self._run_bounded(
                    args,
                    cwd=cwd,
                    env=env,
                    stdin=stdin,
                    seconds=self._seconds(timeout_seconds),
                    max_output_bytes=max_output_bytes,
                    start=start,
                )
        except ProcessOutputLimit as e:
            _log_process(
                "process.run", "output_limit", e.result.seconds * 1000, e.result.returncode
            )
            raise
        except subprocess.TimeoutExpired as e:
            _log_process("process.run", "timeout", (time.monotonic() - start) * 1000)
            raise ProcessTimeout(args, e) from e
        except OSError as e:
            _log_process("process.run", "failed", (time.monotonic() - start) * 1000)
            raise ServiceError(f"{args[0]} failed to run: {e}", operation="process.run") from e
        _log_process("process.run", "completed", result.seconds * 1000, result.returncode)
        if check and result.returncode != 0:
            raise ProcessError(result)
        return result

    def _run_bounded(
        self,
        args: tuple[str, ...],
        *,
        cwd: Path | None,
        env: Mapping[str, str] | None,
        stdin: bytes | None,
        seconds: float,
        max_output_bytes: int,
        start: float,
    ) -> ProcessResult:
        with ExitStack() as resources:
            stdout = resources.enter_context(tempfile.TemporaryFile())
            stderr = resources.enter_context(tempfile.TemporaryFile())
            source = None
            if stdin is not None:
                source = resources.enter_context(tempfile.TemporaryFile())
                source.write(stdin)
                source.seek(0)
            with subprocess.Popen(
                args,
                cwd=cwd,
                env=self._child_env(env),
                stdin=source,
                stdout=stdout,
                stderr=stderr,
            ) as process:
                deadline = time.monotonic() + seconds
                timed_out = False
                try:
                    while process.poll() is None:
                        if (
                            os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                            > max_output_bytes
                        ):
                            break
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            break
                        with suppress(subprocess.TimeoutExpired):
                            process.wait(timeout=min(_OUTPUT_POLL_SECONDS, remaining))
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                overflow = (
                    os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                    > max_output_bytes
                )
                stdout.seek(0)
                stderr.seek(0)
                out = stdout.read(max_output_bytes)
                err = stderr.read(max_output_bytes - len(out))
                result = ProcessResult(args, process.returncode, out, err, time.monotonic() - start)
                if overflow:
                    raise ProcessOutputLimit(result, max_output_bytes)
                if timed_out:
                    raise subprocess.TimeoutExpired(args, seconds, output=out, stderr=err)
                return result

    def pipeline(
        self,
        segments: Sequence[Sequence[str]],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        segment_envs: Sequence[Mapping[str, str]] | None = None,
        stdin: bytes | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[ProcessResult, ...]:
        """Each segment's stdout piped into the next, no shell: one result per segment, the
        output and stderr on the last one. Without `stdin` the first segment inherits ours."""
        argvs = [self._validate(segment) for segment in segments]
        if not argvs:
            raise ValidationError("a pipeline needs at least one segment")
        if segment_envs is not None and len(segment_envs) != len(argvs):
            raise ValidationError("pipeline environments must match its segments")
        child_envs = [
            self._child_env({**(env or {}), **(segment_envs[i] if segment_envs else {})})
            for i in range(len(argvs))
        ]
        seconds = self._seconds(timeout_seconds)
        start = time.monotonic()
        first_stdin = subprocess.PIPE if stdin is not None else None
        procs: list[subprocess.Popen[bytes]] = []
        try:
            for args, child_env in zip(argvs, child_envs, strict=True):
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
            _log_process("process.pipeline", "timeout", (time.monotonic() - start) * 1000)
            raise ProcessTimeout(argvs[-1], e, operation="process.pipeline") from e
        except OSError as e:
            for p in procs:
                p.kill()
            _log_process("process.pipeline", "failed", (time.monotonic() - start) * 1000)
            raise ServiceError(
                f"pipeline from {argvs[0][0]} failed to run: {e}", operation="process.pipeline"
            ) from e
        taken = time.monotonic() - start
        upstream = [
            ProcessResult(a, p.returncode, b"", b"", taken)
            for a, p in zip(argvs[:-1], procs[:-1], strict=True)
        ]
        _log_process("process.pipeline", "completed", taken * 1000, procs[-1].returncode)
        return (*upstream, ProcessResult(argvs[-1], procs[-1].returncode, out, err, taken))

    def _child_env(self, env: Mapping[str, str] | None) -> dict[str, str]:
        child_env = {k: os.environ[k] for k in self._keep_env if k in os.environ}
        child_env.update(env or {})
        child_env.pop(REQUEST_ID_ENV, None)
        if correlation := current_correlation():
            child_env[REQUEST_ID_ENV] = correlation.request_id
        return child_env

    def _seconds(self, timeout_seconds: float | None) -> float:
        return min(timeout_seconds or self._timeout, self._timeout)
