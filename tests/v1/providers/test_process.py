import logging
from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.correlation import correlation_scope
from traust_core.v1.providers.process import ProcessError, ProcessRunner, ProcessTimeout


@pytest.mark.parametrize(
    "argv",
    [[], ["bash", "-c", "echo hi"], ["/bin/sh", "-c", "id"], ["env", "wc"], ["curl", "x"]],
)
def test_process_runner_rejects(argv: list[str]) -> None:
    with pytest.raises(ValidationError):
        ProcessRunner(["wc", "bash", "sh", "env"]).run(argv)


def test_process_runner_scrubs_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    out = ProcessRunner(["printenv"]).run(["printenv"])
    assert b"GITHUB_TOKEN" not in out.stdout


def test_process_events_omit_arguments_and_output(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-only-never-a-real-credential"
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.process"):
        result = ProcessRunner(["python3"]).run(["python3", "-c", f"print({secret!r})"])
    assert result.stdout.strip().decode() == secret
    (record,) = caplog.records
    assert (record.operation, record.outcome, record.returncode) == (
        "process.run",
        "completed",
        0,
    )
    assert record.duration_ms >= 0
    assert secret not in caplog.text
    assert "python3" not in caplog.text


def test_an_accepted_nonzero_exit_is_a_completed_info_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.process"):
        result = ProcessRunner(["python3"]).run(
            ["python3", "-c", "raise SystemExit(3)"], check=False
        )
    assert result.returncode == 3
    (record,) = caplog.records
    assert (record.levelno, record.outcome, record.returncode) == (logging.INFO, "completed", 3)


def test_a_nonzero_pipeline_is_a_completed_info_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="traust_core.v1.providers.process"):
        (result,) = ProcessRunner(["grep"]).pipeline([["grep", "missing"]], stdin=b"present\n")
    assert result.returncode == 1
    (record,) = caplog.records
    assert (record.levelno, record.outcome, record.returncode) == (logging.INFO, "completed", 1)


def test_process_runner_passes_only_its_scoped_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRAUST_REQUEST_ID", "leaked-parent")
    runner = ProcessRunner(["printenv"], keep_env=("PATH", "TRAUST_REQUEST_ID"))
    with correlation_scope("scoped-1"):
        inside = runner.run(["printenv"], env={"TRAUST_REQUEST_ID": "spoofed"})
    outside = runner.run(["printenv"], env={"TRAUST_REQUEST_ID": "spoofed"})
    assert b"TRAUST_REQUEST_ID=scoped-1" in inside.stdout
    assert b"TRAUST_REQUEST_ID=" not in outside.stdout


def test_process_runner_raises_on_nonzero_exit(tmp_path: Path) -> None:
    with pytest.raises(ProcessError):
        ProcessRunner(["wc"]).run(["wc", "-l", "--", str(tmp_path / "missing")])


@pytest.mark.parametrize("runner_seconds,call_seconds", [(0.2, None), (60, 0.2), (0.2, 60)])
def test_a_call_runs_no_longer_than_the_shorter_of_its_own_and_the_runner_timeout(
    runner_seconds: float, call_seconds: float | None
) -> None:
    runner = ProcessRunner(["sleep"], timeout_seconds=runner_seconds)
    with pytest.raises(ServiceError, match="sleep failed to run"):
        runner.run(["sleep", "5"], timeout_seconds=call_seconds)


def test_a_timeout_carries_what_the_run_wrote_before_it() -> None:
    runner = ProcessRunner(["python3"], timeout_seconds=1)
    script = "import sys, time; print('started', flush=True); time.sleep(5)"
    with pytest.raises(ProcessTimeout, match="python3 failed to run") as raised:
        runner.run(["python3", "-c", script])
    assert raised.value.stdout == b"started\n"


def test_a_pipeline_pipes_each_segment_into_the_next_and_reports_each_exit() -> None:
    runner = ProcessRunner(["printf", "grep", "wc"])
    *upstream, last = runner.pipeline(
        [["printf", "a\\nb\\nab\\n"], ["grep", "a"], ["wc", "-l"]], stdin=None
    )
    assert [r.returncode for r in upstream] == [0, 0]
    assert (last.argv, last.returncode, last.stdout.strip()) == (("wc", "-l"), 0, b"2")


def test_a_pipeline_reads_stdin_into_its_first_segment() -> None:
    [only] = ProcessRunner(["grep"]).pipeline([["grep", "-c", "x"]], stdin=b"x\ny\nx\n")
    assert only.stdout == b"2\n"


@pytest.mark.parametrize(
    "segments", [[], [["grep", "x"], ["bash", "-c", "id"]], [["grep", "x"], ["curl", "x"]]]
)
def test_a_pipeline_rejects_what_a_run_would(segments: list[list[str]]) -> None:
    with pytest.raises(ValidationError):
        ProcessRunner(["grep", "bash"]).pipeline(segments)


def test_a_pipeline_that_times_out_or_cannot_start_is_a_service_error(tmp_path: Path) -> None:
    with pytest.raises(ProcessTimeout):
        ProcessRunner(["sleep", "cat"], timeout_seconds=0.2).pipeline([["sleep", "5"], ["cat"]])
    with pytest.raises(ServiceError, match="failed to run"):
        ProcessRunner(["cat", "missing"]).pipeline([["cat"], [str(tmp_path / "missing")]])
