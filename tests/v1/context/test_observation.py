import pytest

from tests.v1.observation_support import NOW
from traust_core.v1.context.observation import command_source
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.providers.process import ProcessResult, ProcessRunner


def test_batch_source_respects_the_supplied_host_allowlist_and_clock(monkeypatch):
    calls = []

    def run(self, argv, **kwargs):
        calls.append(tuple(argv))
        return ProcessResult(tuple(argv), 0, b"{}", b"", 0)

    monkeypatch.setattr(ProcessRunner, "run", run)
    source = command_source({"github.com": "github"}, clock=FixedClock(NOW))
    with pytest.raises(ValidationError):
        source.info(HttpsRepoUrl("example.com", "o/r"))
    assert calls == []
    assert source.info(HttpsRepoUrl("github.com", "o/r")).provenance.acquired_at == NOW
    assert len(calls) == 1
