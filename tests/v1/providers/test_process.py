from pathlib import Path

import pytest

from traust_core.v1.errors import ValidationError
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
