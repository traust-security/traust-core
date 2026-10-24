from pathlib import Path

import pytest

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.providers.process import ProcessError, ProcessRunner


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
